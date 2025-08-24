#!/usr/bin/env python3

import os
import requests
import json
import time
import subprocess
import tempfile
import shutil
from urllib.parse import urlparse, quote
from pathlib import Path

class GitCloneHandler:
    def __init__(self):
        self.temp_dir = None
        self.repo_path = None
    
    def clone_repo(self, github_url, depth=50):
        """
        Clone GitHub repository with limited depth for efficiency
        """
        try:
            # Parse GitHub URL to get clone URL
            url_type, url_parts = parse_github_url(github_url)
            if not url_parts:
                print(f"Could not parse GitHub URL: {github_url}")
                return False
            
            owner = url_parts['owner']
            repo = url_parts['repo']
            clone_url = f"https://github.com/{owner}/{repo}.git"
            
            # Create temporary directory
            self.temp_dir = tempfile.mkdtemp(prefix="github_analysis_")
            self.repo_path = os.path.join(self.temp_dir, repo)
            
            print(f"🔄 Cloning repository {owner}/{repo} (depth={depth})...")
            
            # Clone with limited depth for efficiency
            cmd = [
                'git', 'clone', 
                '--depth', str(depth),
                '--single-branch',
                clone_url, 
                self.repo_path
            ]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=120  # 2 minute timeout
            )
            
            if result.returncode == 0:
                print(f"✓ Repository cloned successfully to {self.repo_path}")
                return True
            else:
                print(f"✗ Git clone failed: {result.stderr}")
                self.cleanup()
                return False
                
        except subprocess.TimeoutExpired:
            print("✗ Git clone timed out after 2 minutes")
            self.cleanup()
            return False
        except Exception as e:
            print(f"✗ Git clone error: {e}")
            self.cleanup()
            return False
    
    def get_pr_files_via_git(self, github_url, search_terms=None):
        """
        Get PR files using git commands on cloned repository
        """
        url_type, url_parts = parse_github_url(github_url)
        if url_type != 'pull':
            print(f"This function handles pull request URLs. Got: {url_type}")
            return None
        
        if not self.repo_path or not os.path.exists(self.repo_path):
            print("Repository not cloned or path doesn't exist")
            return None
        
        try:
            pr_number = url_parts['pr']
            
            # Change to repo directory
            os.chdir(self.repo_path)
            
            # Fetch the PR
            print(f"🔄 Fetching pull request #{pr_number}...")
            fetch_cmd = [
                'git', 'fetch', 'origin', 
                f'pull/{pr_number}/head:pr-{pr_number}'
            ]
            
            result = subprocess.run(fetch_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"✗ Failed to fetch PR: {result.stderr}")
                return None
            
            # Get base branch info
            base_cmd = ['git', 'merge-base', f'pr-{pr_number}', 'origin/main']
            base_result = subprocess.run(base_cmd, capture_output=True, text=True)
            
            if base_result.returncode != 0:
                # Try with 'master' if 'main' fails
                base_cmd = ['git', 'merge-base', f'pr-{pr_number}', 'origin/master']
                base_result = subprocess.run(base_cmd, capture_output=True, text=True)
            
            if base_result.returncode != 0:
                print("✗ Could not find base commit")
                return None
            
            base_sha = base_result.stdout.strip()
            
            # Get PR head SHA
            pr_head_cmd = ['git', 'rev-parse', f'pr-{pr_number}']
            pr_head_result = subprocess.run(pr_head_cmd, capture_output=True, text=True)
            
            if pr_head_result.returncode != 0:
                print(f"✗ Could not get PR head SHA: {pr_head_result.stderr}")
                return None
            
            head_sha = pr_head_result.stdout.strip()
            
            # Get list of changed files
            diff_cmd = ['git', 'diff', '--name-status', base_sha, head_sha]
            diff_result = subprocess.run(diff_cmd, capture_output=True, text=True)
            
            if diff_result.returncode != 0:
                print(f"✗ Failed to get diff: {diff_result.stderr}")
                return None
            
            # Parse diff output
            changed_files = []
            smart_contract_extensions = ('.sol', '.vy', '.rs', '.move', '.cairo', '.fc', '.func')
            
            for line in diff_result.stdout.strip().split('\n'):
                if not line:
                    continue
                    
                parts = line.split('\t')
                if len(parts) < 2:
                    continue
                
                status_char = parts[0][0]  # First character indicates status
                filename = parts[1]
                previous_filename = parts[2] if len(parts) > 2 else filename
                
                # Map git status to GitHub-style status
                status_map = {
                    'A': 'added',
                    'D': 'removed', 
                    'M': 'modified',
                    'R': 'renamed',
                    'C': 'copied'
                }
                status = status_map.get(status_char, 'modified')
                
                if filename.endswith(smart_contract_extensions):
                    # Get file stats
                    stats_cmd = ['git', 'diff', '--numstat', base_sha, head_sha, '--', filename]
                    stats_result = subprocess.run(stats_cmd, capture_output=True, text=True)
                    
                    additions, deletions = 0, 0
                    if stats_result.returncode == 0 and stats_result.stdout.strip():
                        stats_parts = stats_result.stdout.strip().split('\t')
                        if len(stats_parts) >= 2:
                            try:
                                additions = int(stats_parts[0]) if stats_parts[0] != '-' else 0
                                deletions = int(stats_parts[1]) if stats_parts[1] != '-' else 0
                            except ValueError:
                                pass
                    
                    # Construct URLs
                    owner = url_parts['owner']
                    repo = url_parts['repo']
                    
                    old_blob_url = f"https://github.com/{owner}/{repo}/blob/{base_sha}/{quote(previous_filename)}" if status != 'added' else ''
                    new_blob_url = f"https://github.com/{owner}/{repo}/blob/{head_sha}/{quote(filename)}" if status != 'removed' else ''
                    
                    file_info = {
                        'file_path': filename,
                        'previous_file_path': previous_filename,
                        'status': status,
                        'old_blob_url': old_blob_url,
                        'new_blob_url': new_blob_url,
                        'old_branch': 'main',  # Simplified for git approach
                        'new_branch': f'pr-{pr_number}',
                        'base_commit_sha': base_sha,
                        'head_commit_sha': head_sha,
                        'blob_sha': '',  # Not easily available via git commands
                        'raw_url': f"https://raw.githubusercontent.com/{owner}/{repo}/{head_sha}/{quote(filename)}" if status != 'removed' else '',
                        'contents_url_old': f"https://api.github.com/repos/{owner}/{repo}/contents/{quote(previous_filename)}?ref={base_sha}" if status != 'added' else '',
                        'contents_url_new': f"https://api.github.com/repos/{owner}/{repo}/contents/{quote(filename)}?ref={head_sha}" if status != 'removed' else '',
                        'additions': additions,
                        'deletions': deletions,
                        'score': 100
                    }
                    
                    if search_terms:
                        # For git approach, we can get the actual patch
                        patch_cmd = ['git', 'diff', base_sha, head_sha, '--', filename]
                        patch_result = subprocess.run(patch_cmd, capture_output=True, text=True)
                        patch_content = patch_result.stdout if patch_result.returncode == 0 else ''
                        
                        score = calculate_relevance_score(filename, patch_content, search_terms)
                        file_info['score'] = score
                        
                        if score > 0:
                            changed_files.append(file_info)
                    else:
                        changed_files.append(file_info)
            
            print(f"✓ Found {len(changed_files)} smart contract files via git")
            
            return {
                'pr_number': pr_number,
                'base_branch': 'main',  # Simplified
                'head_branch': f'pr-{pr_number}',
                'base_commit_sha': base_sha,
                'head_commit_sha': head_sha,
                'base_tree_url': f"https://github.com/{url_parts['owner']}/{url_parts['repo']}/tree/{base_sha}",
                'head_tree_url': f"https://github.com/{url_parts['owner']}/{url_parts['repo']}/tree/{head_sha}",
                'original_tree_url': f"https://github.com/{url_parts['owner']}/{url_parts['repo']}/tree/{base_sha}",
                'files': changed_files
            }
            
        except Exception as e:
            print(f"✗ Error processing PR via git: {e}")
            return None
    
    def get_file_content_at_commit(self, commit_sha, file_path):
        """
        Get file content at specific commit using git
        """
        if not self.repo_path or not os.path.exists(self.repo_path):
            return None
        
        try:
            old_cwd = os.getcwd()
            os.chdir(self.repo_path)
            
            cmd = ['git', 'show', f'{commit_sha}:{file_path}']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            os.chdir(old_cwd)
            
            if result.returncode == 0:
                return result.stdout
            else:
                return None
                
        except Exception as e:
            print(f"Error getting file content via git: {e}")
            return None
    
    def cleanup(self):
        """
        Clean up temporary directory
        """
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
                print(f"🧹 Cleaned up temporary directory: {self.temp_dir}")
            except Exception as e:
                print(f"Warning: Could not clean up temp directory: {e}")
            self.temp_dir = None
            self.repo_path = None

class GitHubGraphQLHandler:
    def __init__(self):
        self.api_key = os.getenv('GITHUB_API_KEY')
        self.graphql_url = "https://api.github.com/graphql"
        self.session = requests.Session()
        
        if self.api_key:
            self.session.headers.update({
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            })
            print("✓ GitHub API key found and configured for GraphQL")
        else:
            print("⚠ No GitHub API key found. GraphQL API requires authentication")
    
    def check_rate_limit(self):
        """Check current GraphQL rate limit status"""
        query = """
        query {
            rateLimit {
                limit
                remaining
                resetAt
            }
        }
        """
        
        try:
            response = self.session.post(self.graphql_url, json={'query': query})
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and 'rateLimit' in data['data']:
                    rate_limit = data['data']['rateLimit']
                    print(f"GraphQL Rate limit: {rate_limit['remaining']}/{rate_limit['limit']} remaining")
                    if rate_limit['remaining'] < 10:
                        print(f"⚠ Low rate limit! Resets at {rate_limit['resetAt']}")
                    return rate_limit['remaining'] > 0
        except Exception as e:
            print(f"Could not check rate limit: {e}")
        return True
    
    def get_pr_files(self, owner, repo, pr_number):
        """
        Get list of changed files in a pull request via GitHub GraphQL API
        """
        if not self.api_key:
            print("GraphQL API requires authentication. Please set GITHUB_API_KEY environment variable.")
            return None
            
        if not self.check_rate_limit():
            print("Rate limit exceeded!")
            return None
        
        # GraphQL query to get PR details and files
        query = """
        query GetPullRequestFiles($owner: String!, $repo: String!, $number: Int!, $cursor: String) {
            repository(owner: $owner, name: $repo) {
                pullRequest(number: $number) {
                    number
                    baseRefName
                    headRefName
                    baseRefOid
                    headRefOid
                    mergeable
                    merged
                    state
                    title
                    body
                    files(first: 100, after: $cursor) {
                        pageInfo {
                            hasNextPage
                            endCursor
                        }
                        edges {
                            node {
                                path
                                additions
                                deletions
                                changeType
                                patch
                            }
                        }
                    }
                    baseRepository {
                        name
                        owner {
                            login
                        }
                    }
                    headRepository {
                        name
                        owner {
                            login
                        }
                    }
                    commits(last: 1) {
                        edges {
                            node {
                                commit {
                                    oid
                                    tree {
                                        oid
                                    }
                                }
                            }
                        }
                    }
                    baseRef {
                        target {
                            ... on Commit {
                                oid
                                tree {
                                    oid
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        
        variables = {
            "owner": owner,
            "repo": repo,
            "number": int(pr_number)
        }
        
        try:
            print(f"🔄 Fetching PR #{pr_number} files via GraphQL...")
            
            # Get all files (handle pagination)
            all_files = []
            cursor = None
            
            while True:
                if cursor:
                    variables["cursor"] = cursor
                
                response = self.session.post(
                    self.graphql_url, 
                    json={'query': query, 'variables': variables}
                )
                
                if response.status_code != 200:
                    print(f"✗ GraphQL request failed with status {response.status_code}: {response.text}")
                    return None
                
                data = response.json()
                
                if 'errors' in data:
                    print(f"✗ GraphQL errors: {data['errors']}")
                    return None
                
                if not data.get('data', {}).get('repository', {}).get('pullRequest'):
                    print(f"✗ Pull request #{pr_number} not found")
                    return None
                
                pr_data = data['data']['repository']['pullRequest']
                files_data = pr_data['files']
                
                # Add files from this page
                all_files.extend([edge['node'] for edge in files_data['edges']])
                
                # Check if there are more pages
                if files_data['pageInfo']['hasNextPage']:
                    cursor = files_data['pageInfo']['endCursor']
                else:
                    break
            
            print(f"✓ Retrieved {len(all_files)} files from PR #{pr_number}")
            
            # Extract PR information
            base_ref = pr_data['baseRefName']
            head_ref = pr_data['headRefName'] 
            base_sha = pr_data['baseRefOid']
            head_sha = pr_data['headRefOid']
            
            # Get tree SHAs
            base_tree_sha = pr_data['baseRef']['target']['tree']['oid'] if pr_data['baseRef'] else None
            head_tree_sha = pr_data['commits']['edges'][0]['node']['commit']['tree']['oid'] if pr_data['commits']['edges'] else None
            
            print(f"PR #{pr_number}: {head_ref} -> {base_ref}")
            print(f"Base: {base_ref} (SHA: {base_sha})")
            print(f"Head: {head_ref} (SHA: {head_sha})")
            
            # Find earliest commit for the changed files
            earliest_origin = self.find_earliest_commit_for_files(owner, repo, all_files, base_sha)
            
            # Construct URLs
            base_tree_url = f"https://github.com/{owner}/{repo}/tree/{base_ref}"
            head_tree_url = f"https://github.com/{owner}/{repo}/tree/{head_ref}"
            
            pr_info = {
                'pr_number': int(pr_number),
                'base_ref': base_ref,
                'head_ref': head_ref,
                'base_sha': base_sha,
                'head_sha': head_sha,
                'base_tree_sha': base_tree_sha,
                'head_tree_sha': head_tree_sha,
                'base_tree_url': base_tree_url,
                'head_tree_url': head_tree_url,
                'mergeable': pr_data.get('mergeable'),
                'merged': pr_data.get('merged'),
                'state': pr_data.get('state'),
                'title': pr_data.get('title', ''),
                'body': pr_data.get('body', ''),
                'files': []
            }
            
            # Add earliest origin information
            if earliest_origin:
                pr_info['original_tree_url'] = f"https://github.com/{owner}/{repo}/tree/{earliest_origin['sha']}"
                pr_info['earliest_commit_info'] = earliest_origin
            else:
                pr_info['original_tree_url'] = base_tree_url
                pr_info['earliest_commit_info'] = None
            
            # Process files
            for file_data in all_files:
                filename = file_data['path']
                change_type = file_data.get('changeType', 'MODIFIED').lower()
                
                # Map GraphQL change types to standard status
                change_type_map = {
                    'added': 'added',
                    'deleted': 'removed',
                    'modified': 'modified',
                    'renamed': 'renamed',
                    'copied': 'copied'
                }
                status = change_type_map.get(change_type, 'modified')
                
                # Handle renamed files (GraphQL doesn't provide previous filename in this query)
                previous_filename = filename
                if status == 'renamed':
                    # For renamed files, we might need additional logic to get the old filename
                    # This would require parsing the patch or making additional queries
                    previous_filename = self._extract_previous_filename_from_patch(file_data.get('patch', ''))
                    if not previous_filename:
                        previous_filename = filename
                
                # Construct URLs
                old_blob_url = f"https://github.com/{owner}/{repo}/blob/{base_sha}/{quote(previous_filename)}" if status != 'added' else ''
                new_blob_url = f"https://github.com/{owner}/{repo}/blob/{head_sha}/{quote(filename)}" if status != 'removed' else ''
                raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{head_sha}/{quote(filename)}" if status != 'removed' else ''
                
                file_info = {
                    'filename': filename,
                    'previous_filename': previous_filename,
                    'status': status,
                    'additions': file_data.get('additions', 0),
                    'deletions': file_data.get('deletions', 0),
                    'changes': (file_data.get('additions', 0) + file_data.get('deletions', 0)),
                    'patch': file_data.get('patch', ''),
                    
                    # URLs
                    'raw_url': raw_url,
                    'old_blob_url': old_blob_url,
                    'new_blob_url': new_blob_url,
                    
                    # Branch information
                    'old_branch': base_ref if status != 'added' else '',
                    'new_branch': head_ref if status != 'removed' else '',
                    
                    # Commit SHAs
                    'base_commit_sha': base_sha,
                    'head_commit_sha': head_sha,
                    
                    # API URLs for contents
                    'contents_url_old': f"https://api.github.com/repos/{owner}/{repo}/contents/{quote(previous_filename)}?ref={base_sha}" if status != 'added' else '',
                    'contents_url_new': f"https://api.github.com/repos/{owner}/{repo}/contents/{quote(filename)}?ref={head_sha}" if status != 'removed' else '',
                    
                    # Additional metadata
                    'blob_sha': '',  # Would need additional GraphQL query to get blob SHA
                    'score': 100
                }
                
                pr_info['files'].append(file_info)
            
            return pr_info
            
        except Exception as e:
            print(f"Error fetching PR files via GraphQL: {e}")
            return None
    
    def _extract_previous_filename_from_patch(self, patch):
        """
        Extract the previous filename from a git patch for renamed files
        """
        if not patch:
            return None
        
        import re
        
        # Look for rename information in patch header
        # Pattern: "rename from old_file" or "--- a/old_file"
        rename_from_match = re.search(r'^rename from (.+)$', patch, re.MULTILINE)
        if rename_from_match:
            return rename_from_match.group(1)
        
        # Alternative pattern in diff header
        old_file_match = re.search(r'^--- a/(.+)$', patch, re.MULTILINE)
        if old_file_match:
            return old_file_match.group(1)
        
        return None
    
    def get_file_content_with_graphql(self, owner, repo, file_path, ref):
        """
        Get file content using GraphQL
        """
        if not self.check_rate_limit():
            return None
        
        query = """
        query GetFileContent($owner: String!, $repo: String!, $expression: String!) {
            repository(owner: $owner, name: $repo) {
                object(expression: $expression) {
                    ... on Blob {
                        text
                        isBinary
                        byteSize
                    }
                }
            }
        }
        """
        
        variables = {
            "owner": owner,
            "repo": repo,
            "expression": f"{ref}:{file_path}"
        }
        
        try:
            response = self.session.post(
                self.graphql_url,
                json={'query': query, 'variables': variables}
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if 'errors' in data:
                    print(f"GraphQL errors: {data['errors']}")
                    return None
                
                repo_data = data.get('data', {}).get('repository')
                if not repo_data:
                    return None
                
                file_object = repo_data.get('object')
                if not file_object:
                    return None
                
                if file_object.get('isBinary'):
                    print(f"File {file_path} is binary, cannot retrieve text content")
                    return None
                
                return file_object.get('text')
            
            return None
            
        except Exception as e:
            print(f"Error getting file content via GraphQL: {e}")
            return None
    
    def find_earliest_commit_for_files(self, owner, repo, changed_files, base_sha):
        """
        Find the earliest commit that contains any of the changed files using GraphQL
        """
        if not changed_files:
            return None
        
        # For GraphQL, we'll use a simpler approach and query the commit history
        query = """
        query GetCommitHistory($owner: String!, $repo: String!, $ref: String!, $path: String!, $first: Int!) {
            repository(owner: $owner, name: $repo) {
                object(expression: $ref) {
                    ... on Commit {
                        history(first: $first, path: $path) {
                            edges {
                                node {
                                    oid
                                    committedDate
                                    message
                                    author {
                                        name
                                        email
                                        date
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        
        earliest_commit = None
        earliest_date = None
        
        print("🔍 Tracing file origins via GraphQL...")
        
        for file_info in changed_files:
            if isinstance(file_info, dict) and file_info.get('changeType') == 'ADDED':
                continue  # Skip newly added files
            
            file_path = file_info.get('path') if isinstance(file_info, dict) else file_info.get('filename', file_info.get('previous_filename'))
            if not file_path:
                continue
            
            variables = {
                "owner": owner,
                "repo": repo,
                "ref": base_sha,
                "path": file_path,
                "first": 100
            }
            
            try:
                response = self.session.post(
                    self.graphql_url,
                    json={'query': query, 'variables': variables}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if 'errors' not in data and data.get('data', {}).get('repository', {}).get('object'):
                        history = data['data']['repository']['object']['history']['edges']
                        
                        if history:
                            # Get the earliest (last) commit in the history
                            earliest_in_history = history[-1]['node']
                            commit_date = earliest_in_history['committedDate']
                            
                            if earliest_date is None or commit_date < earliest_date:
                                earliest_date = commit_date
                                earliest_commit = earliest_in_history
                                
            except Exception as e:
                print(f"Error getting history for {file_path}: {e}")
                continue
        
        if earliest_commit:
            print(f"📅 Earliest origin commit: {earliest_commit['oid'][:8]} ({earliest_date})")
            return {
                'commit': earliest_commit,
                'date': earliest_date,
                'sha': earliest_commit['oid']
            }
        
        return None
    
    def get_file_content(self, raw_url):
        """
        Get file content from GitHub's raw URL (fallback method)
        """
        try:
            response = self.session.get(raw_url)
            if response.status_code == 200:
                return response.text
            else:
                print(f"Failed to fetch file content: {response.status_code}")
                return None
        except Exception as e:
            print(f"Error fetching file content: {e}")
            return None

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

def handle_pr_files_via_git_clone(github_url, search_terms=None):
    """
    Handle pull request files using git clone approach with fallback to GraphQL API
    """
    print("🚀 Attempting git clone approach...")
    
    # Try git clone approach first
    git_handler = GitCloneHandler()
    
    try:
        if git_handler.clone_repo(github_url):
            result = git_handler.get_pr_files_via_git(github_url, search_terms)
            if result:
                print("✅ Successfully processed PR using git clone method")
                return result, git_handler
            else:
                print("⚠️  Git clone succeeded but PR processing failed, falling back to GraphQL API...")
        else:
            print("⚠️  Git clone failed, falling back to GraphQL API method...")
    except Exception as e:
        print(f"⚠️  Git clone method failed with error: {e}")
        print("Falling back to GraphQL API method...")
    
    # Fallback to GraphQL API method
    print("🔄 Using GitHub GraphQL API fallback method...")
    
    url_type, url_parts = parse_github_url(github_url)
    
    if not url_parts:
        print(f"Could not parse GitHub URL: {github_url}")
        return None, None
    
    if url_type != 'pull':
        print(f"This function handles pull request URLs. Got: {url_type}")
        return None, None
    
    owner = url_parts['owner']
    repo = url_parts['repo']
    pr_number = url_parts['pr']
    
    api = GitHubGraphQLHandler()
    pr_info = api.get_pr_files(owner, repo, pr_number)
    
    if not pr_info:
        print("Could not retrieve pull request information")
        return None, None
    
    smart_contract_extensions = ('.sol', '.vy', '.rs', '.move', '.cairo', '.fc', '.func')
    matching_files = []
    
    for file_info in pr_info['files']:
        filename = file_info['filename']
        status = file_info['status']
        
        if filename.endswith(smart_contract_extensions):
            file_match = {
                'file_path': filename,
                'previous_file_path': file_info['previous_filename'],
                'status': status,
                'old_blob_url': file_info['old_blob_url'],
                'new_blob_url': file_info['new_blob_url'], 
                'old_branch': file_info['old_branch'],
                'new_branch': file_info['new_branch'],
                'base_commit_sha': file_info['base_commit_sha'],
                'head_commit_sha': file_info['head_commit_sha'],
                'blob_sha': file_info.get('blob_sha', ''),
                'raw_url': file_info['raw_url'],
                'contents_url_old': file_info['contents_url_old'],
                'contents_url_new': file_info['contents_url_new'],
                'additions': file_info['additions'],
                'deletions': file_info['deletions'],
                'score': 100
            }
            
            if search_terms:
                score = calculate_relevance_score(filename, file_info.get('patch', ''), search_terms)
                file_match['score'] = score
                
                if score > 0:
                    matching_files.append(file_match)
            else:
                matching_files.append(file_match)
    
    result = {
        'pr_number': pr_info['pr_number'],
        'base_branch': pr_info['base_ref'],
        'head_branch': pr_info['head_ref'],
        'base_commit_sha': pr_info['base_sha'],
        'head_commit_sha': pr_info['head_sha'],
        'base_tree_url': pr_info['base_tree_url'],
        'head_tree_url': pr_info['head_tree_url'],
        'original_tree_url': pr_info.get('original_tree_url'),
        'base_tree_sha': pr_info.get('base_tree_sha'),
        'head_tree_sha': pr_info.get('head_tree_sha'),
        'earliest_commit_info': pr_info.get('earliest_commit_info'),
        'mergeable': pr_info.get('mergeable'),
        'merged': pr_info.get('merged'),
        'state': pr_info.get('state'),
        'title': pr_info.get('title', ''),
        'body': pr_info.get('body', ''),
        'files': matching_files
    }
    
    print("✅ Successfully processed PR using GitHub GraphQL API method")
    return result, None

def handle_pr_files_via_api(github_url, search_terms=None):
    """
    Handle pull request files using GitHub API, returning accurate blob URLs and commit information
    (Legacy function - now just calls the git clone handler with API fallback)
    """
    result, git_handler = handle_pr_files_via_git_clone(github_url, search_terms)
    
    # Clean up git handler if it was used
    if git_handler:
        git_handler.cleanup()
    
    return result

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

def main():
    """Test the enhanced GitHub approach with git clone and API fallback"""
    test_url = "https://github.com/Brahma-fi/protected_moonshots/pull/37"
    
    print("Testing enhanced GitHub approach (git clone + API fallback)...")
    print("=" * 70)
    
    result, git_handler = handle_pr_files_via_git_clone(test_url)
    
    try:
        if result:
            print(f"\nPull Request #{result['pr_number']}")
            print(f"Base branch: {result['base_branch']} (SHA: {result['base_commit_sha']})")
            print(f"Head branch: {result['head_branch']} (SHA: {result['head_commit_sha']})")
            
            if result.get('original_tree_url'):
                print(f"Original tree URL: {result['original_tree_url']}")
            
            # Display tree information if available
            if result.get('head_tree_info'):
                head_tree = result['head_tree_info']
                print(f"New tree GitHub URL: {head_tree['tree_github_url']}")
            
            print(f"\n✓ Found {len(result['files'])} smart contract files:")
            for file_info in result['files']:
                print(f"\n--- File: {file_info['file_path']} ---")
                if file_info['previous_file_path'] != file_info['file_path']:
                    print(f"Previous name: {file_info['previous_file_path']}")
                
                if file_info['old_blob_url']:
                    print(f"Old version: {file_info['old_blob_url']}")
                else:
                    print("Old version: N/A (file was added)")
                    
                if file_info['new_blob_url']:
                    print(f"New version: {file_info['new_blob_url']}")
                else:
                    print("New version: N/A (file was removed)")
                    
            # Test file content retrieval if git handler is available
            if git_handler and result['files']:
                print(f"\n--- Testing file content retrieval ---")
                sample_file = result['files'][0]
                
                if sample_file['status'] != 'added':
                    old_content = git_handler.get_file_content_at_commit(
                        sample_file['base_commit_sha'], 
                        sample_file['previous_file_path']
                    )
                    if old_content:
                        print(f"✓ Successfully retrieved old content for {sample_file['file_path']} ({len(old_content)} chars)")
                    else:
                        print(f"✗ Could not retrieve old content for {sample_file['file_path']}")
                
                if sample_file['status'] != 'removed':
                    new_content = git_handler.get_file_content_at_commit(
                        sample_file['head_commit_sha'], 
                        sample_file['file_path']
                    )
                    if new_content:
                        print(f"✓ Successfully retrieved new content for {sample_file['file_path']} ({len(new_content)} chars)")
                    else:
                        print(f"✗ Could not retrieve new content for {sample_file['file_path']}")
        else:
            print("No matching files found")
    
    finally:
        # Always clean up
        if git_handler:
            git_handler.cleanup()

if __name__ == "__main__":
    main()