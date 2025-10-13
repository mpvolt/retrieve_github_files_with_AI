import os
import requests
import json
import time
import subprocess
import tempfile
import shutil
from urllib.parse import urlparse, quote
from pathlib import Path
from config import SMART_CONTRACT_EXTENSIONS

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
        self.api_handler = GitHubAPIHandler()  # Initialize API handler for fallback
    
    def clone_repo_for_pr(self, github_url, pr_number):
        """Clone GitHub repository specifically for PR analysis with fork support and head tree info."""
        result_info = {
            "success": False,
            "repo_path": None,
            "head_tree_info": None,
        }

        try:
            url_type, url_parts = parse_github_url(github_url)
            if not url_parts:
                print(f"Could not parse GitHub URL: {github_url}")
                return result_info

            owner = url_parts['owner']
            repo = url_parts['repo']
            base_clone_url = f"https://github.com/{owner}/{repo}.git"

            self.temp_dir = tempfile.mkdtemp(prefix="github_analysis_")
            self.repo_path = os.path.join(self.temp_dir, repo)
            result_info["repo_path"] = self.repo_path

            print(f"Cloning base repository {owner}/{repo}...")
            clone_proc = subprocess.run(
                ['git', 'clone', '--depth', '1', base_clone_url, self.repo_path],
                capture_output=True, text=True
            )
            if clone_proc.returncode != 0:
                print(f"Git clone failed: {clone_proc.stderr}")
                self.cleanup()
                return result_info

            os.chdir(self.repo_path)

            # --- Fetch PR details ---
            pr_api = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
            pr_info = requests.get(pr_api).json()

            if "message" in pr_info and "Not Found" in pr_info["message"]:
                print(f"Could not fetch PR info from GitHub API: {pr_info}")
                self.cleanup()
                return result_info

            head_repo_url = pr_info["head"]["repo"]["clone_url"]
            head_ref = pr_info["head"]["ref"]
            head_sha = pr_info["head"]["sha"]

            print(f"PR #{pr_number} head repo: {head_repo_url}")
            print(f"Branch: {head_ref}, Commit: {head_sha}")

            # --- Fetch PR branch from fork or same repo ---
            subprocess.run(['git', 'remote', 'add', 'prhead', head_repo_url], check=False)
            fetch_proc = subprocess.run(['git', 'fetch', '--depth=20', 'prhead', head_ref],
                                        capture_output=True, text=True)
            if fetch_proc.returncode != 0:
                print(f"PR fetch failed: {fetch_proc.stderr}")
                self.cleanup()
                return result_info

            # --- Verify branch ---
            verify_proc = subprocess.run(['git', 'rev-parse', f'prhead/{head_ref}'],
                                        capture_output=True, text=True)
            if verify_proc.returncode != 0:
                print("Could not verify PR branch")
                self.cleanup()
                return result_info

            # --- Get tree info for head commit ---
            commit_api = f"https://api.github.com/repos/{owner}/{repo}/git/commits/{head_sha}"
            head_commit_info = requests.get(commit_api).json()

            if "tree" in head_commit_info:
                result_info["head_tree_info"] = head_commit_info["tree"]["url"]
                print(f"Head tree URL: {result_info['head_tree_info']}")
            else:
                print("Could not retrieve tree info from commit API")

            result_info["success"] = True
            return result_info

        except Exception as e:
            print(f"Error cloning PR: {e}")
            self.cleanup()
            return result_info

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

    def get_blob_via_api_fallback(self, owner, repo, commit_sha, file_path, is_fork_head=False, fork_owner=None, fork_repo=None):
        """Fallback to API when git show fails to retrieve a file"""
        target_owner = fork_owner if is_fork_head and fork_owner else owner
        target_repo = fork_repo if is_fork_head and fork_repo else repo
        
        print(f"  → API fallback: fetching {file_path} from {target_owner}/{target_repo}@{commit_sha[:8]}")
        
        content = self.api_handler.get_file_content_at_commit(
            target_owner, target_repo, commit_sha, file_path
        )
        
        if content:
            print(f"  ✓ Successfully retrieved via API")
        else:
            print(f"  ✗ API fallback also failed")
        
        return content

    def get_pr_files_via_git(self, github_url, search_terms=None):
        """
        Get all PR files using git commands on a cloned repository.
        Handles PRs from forks and multiple commits with API fallback for missing files.
        """
        import subprocess
        from urllib.parse import quote
        import os

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

            # --- Step 1: Get PR metadata (to detect forks) ---
            print("Fetching PR metadata from GitHub API...")
            pr_url = f"{self.api_handler.base_url}/repos/{owner}/{repo}/pulls/{pr_number}"
            pr_response = self.api_handler.session.get(pr_url)

            if pr_response.status_code != 200:
                print(f"Failed to fetch PR metadata: {pr_response.text}")
                return None

            pr_data = pr_response.json()
            head_repo = pr_data["head"].get("repo")
            head_ref = pr_data["head"]["ref"]
            head_sha = pr_data["head"]["sha"]
            base_sha = pr_data["base"]["sha"]
            base_ref = pr_data["base"]["ref"]

            # Detect fork origin
            fork_owner = None
            fork_repo = None
            head_clone_url = None
            is_fork = False

            if head_repo:
                fork_owner = head_repo["owner"]["login"]
                fork_repo = head_repo["name"]
                head_clone_url = head_repo["clone_url"]
                is_fork = (fork_owner != owner) or (fork_repo != repo)

            if is_fork:
                print(f"Detected fork PR from {fork_owner}/{fork_repo}")
            else:
                print("PR is from same repository.")

            # --- Step 2: Fetch PR branch ---
            pr_ref = f"pr-{pr_number}"
            if is_fork:
                # Add fork as remote if missing
                subprocess.run(["git", "remote", "add", "prhead", head_clone_url], check=False)
                fetch_cmd = ["git", "fetch", "--depth=20", "prhead", head_ref]
            else:
                fetch_cmd = ["git", "fetch", "origin", f"pull/{pr_number}/head:{pr_ref}"]

            fetch_result = subprocess.run(fetch_cmd, capture_output=True, text=True)
            if fetch_result.returncode != 0:
                print(f"Fetch failed: {fetch_result.stderr}")
                return None

            # Verify PR head SHA
            verify_cmd = ["git", "rev-parse", f"FETCH_HEAD"]
            verify_result = subprocess.run(verify_cmd, capture_output=True, text=True)
            if verify_result.returncode == 0:
                pr_head_sha = verify_result.stdout.strip()
            else:
                pr_head_sha = head_sha

            print(f"PR head SHA: {pr_head_sha[:8]}")
            print(f"Base SHA: {base_sha[:8]} ({base_ref})")

            # --- Step 3: Diff to get changed files ---
            diff_cmd = ["git", "diff", "--name-status", f"{base_sha}..{pr_head_sha}"]
            diff_result = subprocess.run(diff_cmd, capture_output=True, text=True)
            if diff_result.returncode != 0:
                print(f"Diff failed: {diff_result.stderr}")
                return None
            diff_output = diff_result.stdout.strip()
            if not diff_output:
                print("No files changed in this PR.")
                return None

            changed_files = []

            for line in diff_output.splitlines():
                if not line:
                    continue

                parts = line.split('\t')
                if len(parts) < 2:
                    continue

                status_char = parts[0][0]
                filename = parts[1]
                previous_filename = parts[2] if len(parts) > 2 else filename

                status_map = {'A': 'added', 'D': 'removed', 'M': 'modified', 'R': 'renamed', 'C': 'copied'}
                status = status_map.get(status_char, 'modified')

                if not filename.endswith(SMART_CONTRACT_EXTENSIONS):
                    continue

                old_blob = None
                new_blob = None
                old_blob_sha = ""
                new_blob_sha = ""

                # --- Get old blob (base) ---
                if status != 'added':
                    old_result = subprocess.run(['git', 'show', f'{base_sha}:{previous_filename}'],
                                                capture_output=True, text=True)
                    if old_result.returncode == 0:
                        old_blob = old_result.stdout
                        old_blob_sha = subprocess.run(['git', 'rev-parse', f'{base_sha}:{previous_filename}'],
                                                    capture_output=True, text=True).stdout.strip()
                    else:
                        print(f"Fallback: fetching old blob for {previous_filename} via API...")
                        old_blob = self.get_blob_via_api_fallback(owner, repo, base_sha, previous_filename)

                # --- Get new blob (head) ---
                if status != 'removed':
                    new_result = subprocess.run(['git', 'show', f'{pr_head_sha}:{filename}'],
                                                capture_output=True, text=True)
                    if new_result.returncode == 0:
                        new_blob = new_result.stdout
                        new_blob_sha = subprocess.run(['git', 'rev-parse', f'{pr_head_sha}:{filename}'],
                                                    capture_output=True, text=True).stdout.strip()
                    else:
                        print(f"Fallback: fetching new blob for {filename} via API...")
                        new_blob = self.get_blob_via_api_fallback(
                            fork_owner if is_fork else owner,
                            fork_repo if is_fork else repo,
                            pr_head_sha,
                            filename,
                            is_fork_head=is_fork,
                            fork_owner=fork_owner,
                            fork_repo=fork_repo
                        )

                new_blob_owner = fork_owner if is_fork else owner
                new_blob_repo = fork_repo if is_fork else repo

                file_info = {
                    'file_path': filename,
                    'previous_file_path': previous_filename,
                    'status': status,
                    'old_blob': old_blob,
                    'new_blob': new_blob,
                    'old_blob_sha': old_blob_sha,
                    'new_blob_sha': new_blob_sha,
                    'old_blob_url': f"https://github.com/{owner}/{repo}/blob/{base_sha}/{quote(previous_filename)}" if old_blob else '',
                    'new_blob_url': f"https://github.com/{new_blob_owner}/{new_blob_repo}/blob/{pr_head_sha}/{quote(filename)}" if new_blob else '',
                    'retrieved_via_api': (old_blob is None and status != 'added') or (new_blob is None and status != 'removed')
                }

                changed_files.append(file_info)
                retrieval_method = "API" if file_info['retrieved_via_api'] else "git"
                print(f"Added {filename} (status: {status}, method: {retrieval_method})")

            print(f"\nTotal files collected: {len(changed_files)}")

            # --- Step 4: Optional earliest commit detection ---
            earliest_commit_sha = self.find_earliest_commit_for_files_git(changed_files, base_sha)
            clean_target_branch = base_ref or "main"

            # --- Step 5: Return full info including head tree URL ---
            commit_api = f"https://api.github.com/repos/{fork_owner if is_fork else owner}/{fork_repo if is_fork else repo}/git/commits/{pr_head_sha}"
            commit_info = self.api_handler.session.get(commit_api).json()
            head_tree_url = commit_info.get("tree", {}).get("url")

            return {
                'pr_number': pr_number,
                'files': changed_files,
                'base_commit_sha': base_sha,
                'head_commit_sha': pr_head_sha,
                'earliest_commit_sha': earliest_commit_sha,
                'target_branch': clean_target_branch,
                'head_tree_info': head_tree_url,
                'earliest_tree_url': f"https://github.com/{owner}/{repo}/tree/{earliest_commit_sha}",
                'merged_target_tree_url': f"https://github.com/{owner}/{repo}/tree/{clean_target_branch}"
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
        """Get all changed files in a pull request via GitHub API, including forked PRs and deleted branches"""
        # Check API rate limit
        if not self.check_rate_limit():
            time.sleep(5)
            return self.get_pr_files(owner, repo, pr_number)

        # Step 1: Fetch PR details
        pr_url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}"
        pr_response = self.session.get(pr_url)
        if pr_response.status_code != 200:
            print(f"Failed to fetch PR details: {pr_response.status_code}")
            return None

        pr_data = pr_response.json()
        base_sha = pr_data['base']['sha']
        head_sha = pr_data['head']['sha']
        base_ref = pr_data['base']['ref']

        # Determine head repo (fork-safe)
        head_repo = pr_data['head'].get('repo')
        head_owner = head_repo['owner']['login'] if head_repo else owner
        head_repo_name = head_repo['name'] if head_repo else repo

        # Step 2: Fetch all changed files via pagination
        files_url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}/files"
        all_files = []
        page = 1

        while True:
            files_response = self.session.get(files_url, params={'page': page, 'per_page': 100})
            if files_response.status_code != 200:
                print(f"Failed to fetch PR files: {files_response.status_code}")
                break

            files_data = files_response.json()
            if not files_data:
                break

            for file_info in files_data:
                filename = file_info['filename']
                if not filename.endswith(SMART_CONTRACT_EXTENSIONS):
                    continue

                previous_filename = file_info.get('previous_filename', filename)
                status = file_info['status']

                # Step 3: Fetch old file content (from base repo/commit)
                old_blob = None
                if status != 'added':
                    old_blob = self.get_file_content_at_commit(owner, repo, base_sha, previous_filename)

                # Step 4: Fetch new file content (from head repo/commit, fork-safe)
                new_blob = None
                if status != 'removed':
                    new_blob = self.get_file_content_at_commit(head_owner, head_repo_name, head_sha, filename)

                all_files.append({
                    'file_path': filename,
                    'previous_file_path': previous_filename,
                    'status': status,
                    'old_blob': old_blob,
                    'new_blob': new_blob,
                    'old_blob_url': f"https://github.com/{owner}/{repo}/blob/{base_sha}/{quote(previous_filename)}" if old_blob else '',
                    'new_blob_url': f"https://github.com/{head_owner}/{head_repo_name}/blob/{head_sha}/{quote(filename)}" if new_blob else '',
                    'score': 100
                })

            page += 1

        # Step 5: Determine earliest commit containing any of the files
        earliest_commit_sha = self.find_earliest_commit_for_files(owner, repo, all_files, base_sha)

        return {
            'pr_number': pr_number,
            'files': all_files,
            'earliest_tree_url': f"https://github.com/{owner}/{repo}/tree/{earliest_commit_sha}",
            'merged_target_tree_url': f"https://github.com/{owner}/{repo}/tree/{base_ref}",
            'base_commit_sha': base_sha,
            'head_commit_sha': head_sha,
            'earliest_commit_sha': earliest_commit_sha,
            'target_branch': base_ref
        }



def handle_pr_files_via_git_clone(github_url, search_terms=None):
    """Handle pull request files using git clone approach with fallback to API"""
    print("Attempting git clone approach...")
    
    git_handler = GitCloneHandler()
    
    try:
        result = git_handler.clone_repo(github_url)
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

    # --- Add head_tree_url automatically ---
    if 'head_commit_sha' in result:
        repo_url = f"https://github.com/{owner}/{repo}"
        result['head_tree_info'] = f"{repo_url}/tree/{result['head_commit_sha']}"
        print(f"Added head_tree_url: {result['head_tree_info']}")
    else:
        print("Warning: head_commit_sha missing, could not set head_tree_url")

    # --- Optional filtering by search terms ---
    if search_terms:
        filtered_files = []
        for file_info in result['files']:
            # Use empty string for patch_content since we're just filtering by filename
            score = calculate_relevance_score(file_info['file_path'], '', search_terms)
            if score > 0:
                file_info['score'] = score
                filtered_files.append(file_info)
        result['files'] = filtered_files
        print(f"Filtered to {len(filtered_files)} files based on search terms")

    print("Successfully processed PR using GitHub API method")

    return result, None


def handle_pr_files_via_api(github_url, search_terms=None):
    """Handle pull request files using GitHub API with git fallback"""
    result, git_handler = handle_pr_files_via_git_clone(github_url, search_terms)
    #print(result)
    
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