import os
import requests
import json
import time
import subprocess
import tempfile
import shutil
from urllib.parse import urlparse, quote
from pathlib import Path

def parse_github_url(url):
    """Parse GitHub URL to extract owner, repo, and PR info"""
    import re
    
    patterns = {
        'pull': r'https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/pull/(?P<pr>\d+)',
        'commit': r'https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/commit/(?P<commit>[a-fA-F0-9]+)',
        'compare': r'https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/compare/(?P<base>[^#]+)\.\.\.(?P<head>[^#]+)',
        'tree': r'https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/tree/(?P<ref>.+)'
    }
    
    for url_type, pattern in patterns.items():
        match = re.match(pattern, url)
        if match:
            return url_type, match.groupdict()
    
    return None, None

def calculate_relevance_score(filename, patch_content, search_terms):
    """Calculate relevance score based on filename and patch content"""
    score = 0
    filename_lower = filename.lower()
    patch_lower = patch_content.lower()
    
    for term in search_terms:
        term_lower = term.lower()
        
        if term_lower == os.path.splitext(os.path.basename(filename_lower))[0]:
            score += 100
        elif term_lower in filename_lower:
            score += 50
            
        if term_lower in patch_lower:
            score += 20
    
    return score

class GitCloneHandler:
    def __init__(self):
        self.temp_dir = None
        self.repo_path = None
    
    def clone_repo_for_pr(self, github_url, pr_number):
        """Clone GitHub repository specifically for PR analysis with proper depth"""
        try:
            url_type, url_parts = parse_github_url(github_url)
            if not url_parts:
                print(f"Could not parse GitHub URL: {github_url}")
                return False
            
            owner = url_parts['owner']
            repo = url_parts['repo']
            clone_url = f"https://github.com/{owner}/{repo}.git"
            
            self.temp_dir = tempfile.mkdtemp(prefix="github_analysis_")
            self.repo_path = os.path.join(self.temp_dir, repo)
            
            print(f"Cloning repository {owner}/{repo} for PR analysis...")
            
            cmd = ['git', 'clone', '--depth', '1', clone_url, self.repo_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode != 0:
                print(f"Git clone failed: {result.stderr}")
                self.cleanup()
                return False
            
            os.chdir(self.repo_path)
            
            print(f"Fetching PR #{pr_number} with extended history...")
            
            pr_fetch_commands = [
                ['git', 'fetch', 'origin', f'+refs/pull/{pr_number}/head:refs/remotes/origin/pr-{pr_number}'],
                ['git', 'fetch', 'origin', f'+refs/pull/{pr_number}/merge:refs/remotes/origin/pr-{pr_number}-merge'],
                ['git', 'fetch', '--depth=20', 'origin'],
            ]
            
            pr_ref = None
            for cmd in pr_fetch_commands:
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    if 'pr-' in cmd[-1]:
                        pr_ref = cmd[-1].split(':')[-1]
                    print(f"Successfully executed: {' '.join(cmd)}")
                else:
                    print(f"Command failed: {' '.join(cmd)} - {result.stderr}")
            
            if not pr_ref:
                pr_ref = f'origin/pr-{pr_number}'
            
            verify_cmd = ['git', 'rev-parse', pr_ref]
            verify_result = subprocess.run(verify_cmd, capture_output=True, text=True)
            
            if verify_result.returncode == 0:
                print(f"PR ref {pr_ref} is accessible")
                return True
            else:
                alt_pr_ref = f'remotes/origin/pr-{pr_number}'
                alt_verify_cmd = ['git', 'rev-parse', alt_pr_ref]
                alt_verify_result = subprocess.run(alt_verify_cmd, capture_output=True, text=True)
                
                if alt_verify_result.returncode == 0:
                    print(f"Using alternative PR ref: {alt_pr_ref}")
                    return True
                else:
                    print("Could not access PR with any ref format")
                    self.cleanup()
                    return False
                    
        except Exception as e:
            print(f"Git clone error: {e}")
            self.cleanup()
            return False

    def clone_repo(self, github_url, depth=20):
        """Legacy clone method - now redirects to the improved version"""
        url_type, url_parts = parse_github_url(github_url)
        if url_type == 'pull':
            pr_number = url_parts['pr']
            return self.clone_repo_for_pr(github_url, pr_number)
        
        try:
            if not url_parts:
                print(f"Could not parse GitHub URL: {github_url}")
                return False
            
            owner = url_parts['owner']
            repo = url_parts['repo']
            clone_url = f"https://github.com/{owner}/{repo}.git"
            
            self.temp_dir = tempfile.mkdtemp(prefix="github_analysis_")
            self.repo_path = os.path.join(self.temp_dir, repo)
            
            print(f"Cloning repository {owner}/{repo} (depth={depth})...")
            
            cmd = ['git', 'clone', '--depth', str(depth), '--single-branch', clone_url, self.repo_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                print(f"Repository cloned successfully to {self.repo_path}")
                return True
            else:
                print(f"Git clone failed: {result.stderr}")
                self.cleanup()
                return False
                
        except subprocess.TimeoutExpired:
            print("Git clone timed out after 2 minutes")
            self.cleanup()
            return False
        except Exception as e:
            print(f"Git clone error: {e}")
            self.cleanup()
            return False

    def find_earliest_commit_for_files_git(self, changed_files, base_sha):
        """Find the earliest commit that contains any of the changed files using git"""
        earliest_commit_sha = None
        earliest_date = None
        
        for file_info in changed_files:
            if file_info['status'] == 'added':
                continue
                
            file_path = file_info['previous_file_path']
            
            history_cmd = ['git', 'log', '--follow', '--format=%H|%cd', '--date=iso', base_sha, '--', file_path]
            history_result = subprocess.run(history_cmd, capture_output=True, text=True)
            
            if history_result.returncode == 0 and history_result.stdout.strip():
                commits = history_result.stdout.strip().split('\n')
                if commits:
                    last_commit = commits[-1]
                    if '|' in last_commit:
                        commit_sha, commit_date = last_commit.split('|', 1)
                        
                        if earliest_date is None or commit_date < earliest_date:
                            earliest_date = commit_date
                            earliest_commit_sha = commit_sha
        
        return earliest_commit_sha if earliest_commit_sha else base_sha

    def get_pr_files_via_git(self, github_url, search_terms=None):
        """Get PR files using git commands on cloned repository"""
        url_type, url_parts = parse_github_url(github_url)
        if url_type != 'pull':
            print(f"This function handles pull request URLs. Got: {url_type}")
            return None
        
        if not self.repo_path or not os.path.exists(self.repo_path):
            print("Repository not cloned or path doesn't exist")
            return None
        
        try:
            owner = url_parts['owner']
            repo = url_parts['repo']
            pr_number = url_parts['pr']
            os.chdir(self.repo_path)
            
            pr_refs = [
                f'remotes/origin/pr-{pr_number}',
                f'origin/pr-{pr_number}',
                f'pr-{pr_number}'
            ]
            
            pr_ref = None
            pr_head_sha = None
            
            for ref in pr_refs:
                cmd = ['git', 'rev-parse', ref]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    pr_ref = ref
                    pr_head_sha = result.stdout.strip()
                    print(f"Found PR at {pr_ref}: {pr_head_sha[:8]}")
                    break
            
            if not pr_ref:
                print("PR reference not found, attempting to fetch...")
                fetch_cmd = ['git', 'fetch', 'origin', f'pull/{pr_number}/head:pr-{pr_number}']
                fetch_result = subprocess.run(fetch_cmd, capture_output=True, text=True)
                
                if fetch_result.returncode == 0:
                    pr_ref = f'pr-{pr_number}'
                    cmd = ['git', 'rev-parse', pr_ref]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode == 0:
                        pr_head_sha = result.stdout.strip()
                        print(f"Successfully fetched and found PR: {pr_head_sha[:8]}")
                
            if not pr_ref:
                print("Could not find PR reference")
                return None
            
            base_sha = None
            target_branch = None
            base_branches = ['origin/main', 'origin/master', 'main', 'master']
            
            for base_branch in base_branches:
                cmd = ['git', 'merge-base', pr_ref, base_branch]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    base_sha = result.stdout.strip()
                    target_branch = base_branch
                    print(f"Found base commit using {base_branch}: {base_sha[:8]}")
                    break
            
            if not base_sha:
                print("Merge-base failed, trying alternative methods...")
                cmd = ['git', 'rev-parse', f'{pr_ref}^']
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    base_sha = result.stdout.strip()
                    target_branch = 'main'
                    print(f"Using first parent as base: {base_sha[:8]}")
            
            if not base_sha:
                cmd = ['git', 'rev-parse', 'HEAD']
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    base_sha = result.stdout.strip()
                    target_branch = 'main'
                    print(f"Using HEAD as base (fallback): {base_sha[:8]}")
            
            if not base_sha:
                print("Could not determine base commit")
                return None
            
            print(f"Comparing {base_sha[:8]} -> {pr_head_sha[:8]}")
            diff_cmd = ['git', 'diff', '--name-status', base_sha, pr_head_sha]
            diff_result = subprocess.run(diff_cmd, capture_output=True, text=True)
            
            if diff_result.returncode != 0:
                print(f"Diff command failed: {diff_result.stderr}")
                alt_diff_cmd = ['git', 'show', '--name-status', '--format=', pr_head_sha]
                alt_diff_result = subprocess.run(alt_diff_cmd, capture_output=True, text=True)
                if alt_diff_result.returncode == 0:
                    print("Using alternative diff method (git show)")
                    diff_output = alt_diff_result.stdout
                else:
                    print(f"Alternative diff also failed: {alt_diff_result.stderr}")
                    return None
            else:
                diff_output = diff_result.stdout
            
            print(f"Diff output:\n{diff_output}")
            
            if not diff_output.strip():
                print("No changes found in diff")
                return None
            
            changed_files = []
            smart_contract_extensions = ('.sol', '.tsol', '.vy', '.rs', '.move', '.cairo', '.fc', '.func')
            
            for line in diff_output.strip().split('\n'):
                if not line:
                    continue
                    
                parts = line.split('\t')
                if len(parts) < 2:
                    continue
                
                status_char = parts[0][0]
                filename = parts[1]
                previous_filename = parts[2] if len(parts) > 2 else filename
                
                status_map = {
                    'A': 'added',
                    'D': 'removed', 
                    'M': 'modified',
                    'R': 'renamed',
                    'C': 'copied'
                }
                status = status_map.get(status_char, 'modified')
                
                print(f"Processing file: {filename} (status: {status})")
                
                if filename.endswith(smart_contract_extensions):
                    old_blob = None
                    old_blob_sha = ""
                    
                    if status != 'added':
                        old_content_cmd = ['git', 'show', f'{base_sha}:{previous_filename}']
                        old_content_result = subprocess.run(old_content_cmd, capture_output=True, text=True)
                        
                        if old_content_result.returncode == 0:
                            old_blob = old_content_result.stdout
                            print(f"Retrieved old blob for {previous_filename}: {len(old_blob)} chars")
                            
                            old_blob_cmd = ['git', 'rev-parse', f'{base_sha}:{previous_filename}']
                            old_blob_result = subprocess.run(old_blob_cmd, capture_output=True, text=True)
                            if old_blob_result.returncode == 0:
                                old_blob_sha = old_blob_result.stdout.strip()
                        else:
                            print(f"Could not get old blob: {old_content_result.stderr}")
                    
                    new_blob = None
                    new_blob_sha = ""
                    
                    if status != 'removed':
                        new_content_cmd = ['git', 'show', f'{pr_head_sha}:{filename}']
                        new_content_result = subprocess.run(new_content_cmd, capture_output=True, text=True)
                        
                        if new_content_result.returncode == 0:
                            new_blob = new_content_result.stdout
                            print(f"Retrieved new blob for {filename}: {len(new_blob)} chars")
                            
                            new_blob_cmd = ['git', 'rev-parse', f'{pr_head_sha}:{filename}']
                            new_blob_result = subprocess.run(new_blob_cmd, capture_output=True, text=True)
                            if new_blob_result.returncode == 0:
                                new_blob_sha = new_blob_result.stdout.strip()
                        else:
                            print(f"Could not get new blob: {new_content_result.stderr}")
                    
                    file_info = {
                        'file_path': filename,
                        'previous_file_path': previous_filename,
                        'status': status,
                        'old_blob': old_blob,
                        'new_blob': new_blob,
                        'old_blob_sha': old_blob_sha,
                        'new_blob_sha': new_blob_sha,
                        'old_blob_url': f"https://github.com/{owner}/{repo}/blob/{base_sha}/{quote(previous_filename)}" if status != 'added' else '',
                        'new_blob_url': f"https://github.com/{owner}/{repo}/blob/{pr_head_sha}/{quote(filename)}" if status != 'removed' else '',
                        'score': 100
                    }
                    
                    if search_terms:
                        patch_cmd = ['git', 'diff', base_sha, pr_head_sha, '--', filename]
                        patch_result = subprocess.run(patch_cmd, capture_output=True, text=True)
                        patch_content = patch_result.stdout if patch_result.returncode == 0 else ''
                        
                        score = calculate_relevance_score(filename, patch_content, search_terms)
                        file_info['score'] = score
                        
                        if score > 0:
                            changed_files.append(file_info)
                    else:
                        changed_files.append(file_info)
                    
                    print(f"Added {filename} to results")
            
            earliest_commit_sha = self.find_earliest_commit_for_files_git(changed_files, base_sha)
            
            print(f"Found {len(changed_files)} smart contract files")
            
            owner = url_parts['owner']
            repo = url_parts['repo']
            clean_target_branch = target_branch.replace('origin/', '') if target_branch else 'main'
            
            return {
                'pr_number': pr_number,
                'files': changed_files,
                'earliest_tree_url': f"https://github.com/{owner}/{repo}/tree/{earliest_commit_sha}",
                'merged_target_tree_url': f"https://github.com/{owner}/{repo}/tree/{clean_target_branch}",
                'base_commit_sha': base_sha,
                'head_commit_sha': pr_head_sha,
                'earliest_commit_sha': earliest_commit_sha,
                'target_branch': clean_target_branch
            }
            
        except Exception as e:
            print(f"Error processing PR via git: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def cleanup(self):
        """Clean up temporary directory"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
                print(f"Cleaned up temporary directory: {self.temp_dir}")
            except Exception as e:
                print(f"Warning: Could not clean up temp directory: {e}")
            self.temp_dir = None
            self.repo_path = None

class GitHubAPIHandler:
    def __init__(self):
        self.api_key = os.getenv('GITHUB_API_KEY')
        self.base_url = "https://api.github.com"
        self.session = requests.Session()
        
        if self.api_key:
            self.session.headers.update({
                'Authorization': f'token {self.api_key}',
                'Accept': 'application/vnd.github.v3+json'
            })
            print("GitHub API key found and configured")
        else:
            print("No GitHub API key found. Rate limits will be much lower")
    
    def check_rate_limit(self):
        """Check current API rate limit status"""
        try:
            response = self.session.get(f"{self.base_url}/rate_limit")
            if response.status_code == 200:
                data = response.json()
                core_limit = data['resources']['core']
                if core_limit['remaining'] < 10:
                    reset_time = core_limit['reset']
                    print(f"Low rate limit! Resets at {time.ctime(reset_time)}")
                return core_limit['remaining'] > 0
        except Exception as e:
            print(f"Could not check rate limit: {e}")
        return True
    
    def get_file_content_at_commit(self, owner, repo, commit_sha, file_path):
        """Get specific file content at a specific commit via GitHub API"""
        if not self.check_rate_limit():
            return None
            
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{file_path}"
        
        try:
            response = self.session.get(url, params={'ref': commit_sha})
            
            if response.status_code == 200:
                file_data = response.json()
                
                if file_data.get('encoding') == 'base64':
                    import base64
                    content = base64.b64decode(file_data['content']).decode('utf-8', errors='ignore')
                    return content
                else:
                    print(f"Unexpected encoding: {file_data.get('encoding')}")
                    return None
            else:
                print(f"Failed to get file content: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"Error getting file content: {e}")
            return None

    def get_file_commit_history(self, owner, repo, file_path, until_sha=None):
        """Get commit history for a specific file, optionally until a specific commit"""
        if not self.check_rate_limit():
            return None
            
        url = f"{self.base_url}/repos/{owner}/{repo}/commits"
        params = {
            'path': file_path,
            'per_page': 100
        }
        if until_sha:
            params['sha'] = until_sha
        
        try:
            response = self.session.get(url, params=params)
            
            if response.status_code == 200:
                commits = response.json()
                return commits
            else:
                print(f"Failed to get file history: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"Error getting file history: {e}")
            return None

    def find_earliest_commit_for_files(self, owner, repo, changed_files, base_sha):
        """Find the earliest commit that contains any of the changed files"""
        earliest_commit = None
        earliest_date = None
        
        for file_info in changed_files:
            if file_info['status'] == 'added':
                continue
                
            file_path = file_info.get('previous_file_path', file_info['file_path'])
            
            history = self.get_file_commit_history(owner, repo, file_path, base_sha)
            
            if history and len(history) > 0:
                file_earliest = history[-1]
                file_commit_date = file_earliest['commit']['committer']['date']
                
                if earliest_date is None or file_commit_date < earliest_date:
                    earliest_date = file_commit_date
                    earliest_commit = file_earliest
                    
        return earliest_commit['sha'] if earliest_commit else base_sha

    def get_pr_files(self, owner, repo, pr_number):
        """Get list of changed files in a pull request via GitHub API"""
        if not self.check_rate_limit():
            print("Rate limit exceeded!")
            time.sleep(300)
            return self.get_pr_files(owner, repo, pr_number)
            
        pr_url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}"
        try:
            pr_response = self.session.get(pr_url)
            
            if pr_response.status_code != 200:
                print(f"Failed to fetch PR details: {pr_response.status_code}")
                return None
                
            pr_data = pr_response.json()
            base_ref = pr_data['base']['ref']
            head_ref = pr_data['head']['ref']
            base_sha = pr_data['base']['sha']
            head_sha = pr_data['head']['sha']
            
            files_url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}/files"
            files_response = self.session.get(files_url)
            
            if files_response.status_code == 200:
                files_data = files_response.json()
                
                changed_files_info = []
                smart_contract_extensions = ('.sol', '.vy', '.rs', '.move', '.cairo', '.fc', '.func')
                
                for file_info in files_data:
                    filename = file_info['filename']
                    status = file_info['status']
                    
                    if filename.endswith(smart_contract_extensions):
                        previous_filename = file_info.get('previous_filename', filename)
                        
                        old_blob = None
                        if status != 'added':
                            old_blob = self.get_file_content_at_commit(owner, repo, base_sha, previous_filename)
                        
                        new_blob = None
                        if status != 'removed':
                            new_blob = self.get_file_content_at_commit(owner, repo, head_sha, filename)
                        
                        file_data = {
                            'file_path': filename,
                            'previous_file_path': previous_filename,
                            'status': status,
                            'old_blob': old_blob,
                            'new_blob': new_blob,
                            'old_blob_sha': '',
                            'new_blob_sha': '',
                            'old_blob_url': f"https://github.com/{owner}/{repo}/blob/{base_sha}/{quote(previous_filename)}" if status != 'added' else '',
                            'new_blob_url': f"https://github.com/{owner}/{repo}/blob/{head_sha}/{quote(filename)}" if status != 'removed' else '',
                            'score': 100
                        }
                        
                        changed_files_info.append(file_data)
                
                earliest_commit_sha = self.find_earliest_commit_for_files(owner, repo, changed_files_info, base_sha)
                
                return {
                    'pr_number': pr_number,
                    'files': changed_files_info,
                    'earliest_tree_url': f"https://github.com/{owner}/{repo}/tree/{earliest_commit_sha}",
                    'merged_target_tree_url': f"https://github.com/{owner}/{repo}/tree/{base_ref}",
                    'base_commit_sha': base_sha,
                    'head_commit_sha': head_sha,
                    'earliest_commit_sha': earliest_commit_sha,
                    'target_branch': base_ref
                }
                
            else:
                print(f"API request failed: {files_response.status_code}")
                return None
                
        except Exception as e:
            print(f"Error fetching PR files: {e}")
            return None

def handle_pr_files_via_git_clone(github_url, search_terms=None):
    """Handle pull request files using git clone approach with fallback to API"""
    print("Attempting git clone approach...")
    
    git_handler = GitCloneHandler()
    
    try:
        if git_handler.clone_repo(github_url):
            result = git_handler.get_pr_files_via_git(github_url, search_terms)
            if result:
                print("Successfully processed PR using git clone method")
                return result, git_handler
            else:
                print("Git clone succeeded but PR processing failed, falling back to API...")
        else:
            print("Git clone failed, falling back to API method...")
    except Exception as e:
        print(f"Git clone method failed with error: {e}")
        print("Falling back to API method...")
    
    print("Using GitHub API fallback method...")
    
    url_type, url_parts = parse_github_url(github_url)
    
    if not url_parts or url_type != 'pull':
        print(f"Invalid URL or not a pull request: {github_url}")
        return None, None
    
    owner = url_parts['owner']
    repo = url_parts['repo']
    pr_number = url_parts['pr']
    
    api = GitHubAPIHandler()
    result = api.get_pr_files(owner, repo, pr_number)
    
    if not result:
        print("Could not retrieve pull request information")
        return None, None
    
    if search_terms:
        filtered_files = []
        for file_info in result['files']:
            score = calculate_relevance_score(file_info['file_path'], '', search_terms)
            if score > 0:
                file_info['score'] = score
                filtered_files.append(file_info)
        result['files'] = filtered_files
    
    print("Successfully processed PR using GitHub API method")
    return result, None

def handle_pr_files_via_api(github_url, search_terms=None):
    """Handle pull request files using GitHub API with git fallback"""
    result, git_handler = handle_pr_files_via_git_clone(github_url, search_terms)
    
    if git_handler:
        git_handler.cleanup()
    
    return result

def main():
    """Quick test to see what's happening with PR #9"""
    url = "https://github.com/OlympusDAO/olympus-v3/pull/57"
    
    print("=== Testing PR #9 ===")
    result = handle_pr_files_via_api(url)
    
    if result:
        print(f"Found {len(result['files'])} files:")
        print(f"Earliest tree URL: {result['earliest_tree_url']}")
        print(f"Merged target tree URL: {result['merged_target_tree_url']}")
        print(f"Target branch: {result['target_branch']}")
        print("\nFiles:")
        
        for file in result['files']:
            print(f"{file}")
            
    else:
        print("Failed to process PR")

if __name__ == "__main__":
    main()