#!/usr/bin/env python3

import os
import requests
import json
import time
from urllib.parse import urlparse, quote

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
            print("✓ GitHub API key found and configured")
        else:
            print("⚠ No GitHub API key found. Rate limits will be much lower (60 req/hour vs 5000 req/hour)")
    
    def check_rate_limit(self):
        """Check current API rate limit status"""
        try:
            response = self.session.get(f"{self.base_url}/rate_limit")
            if response.status_code == 200:
                data = response.json()
                core_limit = data['resources']['core']
                print(f"Rate limit: {core_limit['remaining']}/{core_limit['limit']} remaining")
                if core_limit['remaining'] < 10:
                    reset_time = core_limit['reset']
                    print(f"⚠ Low rate limit! Resets at {time.ctime(reset_time)}")
                return core_limit['remaining'] > 0
        except Exception as e:
            print(f"Could not check rate limit: {e}")
        return True
    
    def get_pr_files(self, owner, repo, pr_number):
        """
        Get list of changed files in a pull request via GitHub API, including proper blob SHAs
        """
        if not self.check_rate_limit():
            print("Rate limit exceeded!")
            return None
            
        # First, get PR details to extract base and head refs and SHAs
        pr_url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}"
        try:
            #print(f"Fetching PR details: {pr_url}")
            pr_response = self.session.get(pr_url)
            
            if pr_response.status_code != 200:
                print(f"✗ Failed to fetch PR details with status {pr_response.status_code}: {pr_response.text}")
                return None
                
            pr_data = pr_response.json()
            base_ref = pr_data['base']['ref']
            head_ref = pr_data['head']['ref']
            base_sha = pr_data['base']['sha']
            head_sha = pr_data['head']['sha']
            
            # print(f"PR #{pr_number}: {head_ref} -> {base_ref}")
            # print(f"Base branch: {base_ref} (SHA: {base_sha})")
            # print(f"Head branch: {head_ref} (SHA: {head_sha})")
            
            # Construct tree URLs
            base_tree_url = f"https://github.com/{owner}/{repo}/tree/{base_ref}"
            head_tree_url = f"https://github.com/{owner}/{repo}/tree/{head_ref}"
            
            # Now get the changed files - this is where we get the actual blob SHAs
            files_url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}/files"
            # print(f"Fetching PR files: {files_url}")
            files_response = self.session.get(files_url)
            
            if files_response.status_code == 200:
                files_data = files_response.json()
                # print(f"✓ Successfully retrieved {len(files_data)} changed files for PR #{pr_number}")
                
                # Get tree information for both base and head commits
                base_tree_info = self.get_commit_tree(owner, repo, base_sha)
                head_tree_info = self.get_commit_tree(owner, repo, head_sha)
                
                pr_info = {
                    'pr_number': pr_number,
                    'base_ref': base_ref,
                    'head_ref': head_ref,
                    'base_sha': base_sha,
                    'head_sha': head_sha,
                    'base_tree_url': base_tree_url,
                    'head_tree_url': head_tree_url,
                    'base_tree_info': base_tree_info,
                    'head_tree_info': head_tree_info,
                    'files': []
                }
                
                # Process changed files first to collect them
                changed_files_info = []
                
                # Process changed files first to collect them
                changed_files_info = []
                
                # Process changed files
                for file_info in files_data:
                    filename = file_info['filename']
                    status = file_info['status']
                    
                    # Extract blob URLs and SHAs from the API response
                    # The API returns different information based on file status
                    
                    # For new files (head/current version)
                    new_blob_url = file_info.get('blob_url', '')  # Points to new version
                    new_raw_url = file_info.get('raw_url', '')    # Raw content URL
                    
                    # For old files, we need to construct the URL using the base commit
                    # The 'blob_url' in the response points to the NEW version
                    # We need to construct the old version URL ourselves
                    if status == 'added':
                        old_blob_url = ''
                        old_blob_sha = ''
                        old_branch = ''
                    else:
                        old_blob_url = f"https://github.com/{owner}/{repo}/blob/{base_sha}/{quote(filename)}"
                        old_blob_sha = base_sha  # We'll get the specific blob SHA later if needed
                        old_branch = base_ref
                    
                    if status == 'removed':
                        new_blob_url = ''
                        new_blob_sha = ''
                        new_branch = ''
                    else:
                        new_blob_sha = head_sha  # We'll get the specific blob SHA later if needed
                        new_branch = head_ref
                    
                    # Try to extract actual blob SHA from the blob_url if available
                    # GitHub blob URLs sometimes contain the actual blob SHA
                    actual_blob_sha = None
                    if 'sha' in file_info:
                        actual_blob_sha = file_info['sha']
                    elif new_blob_url:
                        # Try to extract from the blob URL structure
                        # GitHub blob URLs can be: /blob/{ref}/{path} or sometimes include blob SHA
                        pass
                    
                    # Check if there's a previous_filename for renamed files
                    previous_filename = file_info.get('previous_filename', filename)
                    if previous_filename != filename:
                        # For renamed files, the old blob URL should use the old filename
                        old_blob_url = f"https://github.com/{owner}/{repo}/blob/{base_sha}/{quote(previous_filename)}"

                    file_data = {
                        'filename': filename,
                        'previous_filename': previous_filename,
                        'status': status,
                        'additions': file_info.get('additions', 0),
                        'deletions': file_info.get('deletions', 0),
                        'changes': file_info.get('changes', 0),
                        'patch': file_info.get('patch', ''),
                        
                        # Raw content URLs
                        'raw_url': new_raw_url,
                        
                        # API provided blob URL (points to new version)
                        'api_blob_url': new_blob_url,
                        
                        # Constructed blob URLs for both versions
                        'old_blob_url': old_blob_url,
                        'new_blob_url': new_blob_url,
                        
                        # Branch information
                        'old_branch': old_branch,
                        'new_branch': new_branch,
                        
                        # Commit SHAs
                        'base_commit_sha': base_sha,
                        'head_commit_sha': head_sha,
                        
                        # Blob SHA if available
                        'blob_sha': actual_blob_sha,
                        
                        # Contents URL for API access
                        'contents_url_old': f"{self.base_url}/repos/{owner}/{repo}/contents/{quote(previous_filename)}?ref={base_sha}" if old_branch else '',
                        'contents_url_new': f"{self.base_url}/repos/{owner}/{repo}/contents/{quote(filename)}?ref={head_sha}" if new_branch else ''
                    }
                    
                    changed_files_info.append(file_data)
                    pr_info['files'].append(file_data)
                
                # Now find the earliest commit that contains any of the changed files
                earliest_origin = self.find_earliest_commit_for_files(owner, repo, changed_files_info, base_sha)
                
                if earliest_origin:
                    # Get tree info for the earliest commit
                    earliest_tree_info = self.get_commit_tree(owner, repo, earliest_origin['sha'])
                    pr_info['earliest_tree_info'] = earliest_tree_info
                    pr_info['earliest_commit_info'] = earliest_origin
                    
                    # Update the old tree URL to point to the earliest origin
                    pr_info['original_tree_url'] = f"https://github.com/{owner}/{repo}/tree/{earliest_origin['sha']}"
                else:
                    # Fallback to base commit
                    pr_info['earliest_tree_info'] = base_tree_info
                    pr_info['earliest_commit_info'] = None
                    pr_info['original_tree_url'] = base_tree_url
                
                return pr_info
                
            elif files_response.status_code == 404:
                print(f"✗ Pull request #{pr_number} not found (404)")
                return None
            elif files_response.status_code == 403:
                print(f"✗ API access forbidden (403). Check your API key or rate limits")
                return None
            else:
                print(f"✗ API request failed with status {files_response.status_code}: {files_response.text}")
                return None
                
        except Exception as e:
            print(f"Error fetching PR files: {e}")
            return None
    
    def get_file_content(self, raw_url):
        """
        Get file content from GitHub's raw URL
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
    
    def get_file_content_at_commit(self, owner, repo, commit_sha, file_path):
        """
        Get specific file content at a specific commit via GitHub API
        """
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

    def get_commit_tree(self, owner, repo, commit_sha):
        """
        Get the Git tree for a specific commit
        """
        if not self.check_rate_limit():
            return None
            
        # First get the commit to get the tree SHA
        commit_url = f"{self.base_url}/repos/{owner}/{repo}/git/commits/{commit_sha}"
        
        try:
            response = self.session.get(commit_url)
            
            if response.status_code == 200:
                commit_data = response.json()
                tree_sha = commit_data['tree']['sha']
                tree_url = commit_data['tree']['url']
                
                return {
                    'tree_sha': tree_sha,
                    'tree_api_url': tree_url,
                    'tree_github_url': f"https://github.com/{owner}/{repo}/tree/{commit_sha}",
                    'tree_git_url': f"{self.base_url}/repos/{owner}/{repo}/git/trees/{tree_sha}",
                    'commit_sha': commit_sha
                }
            else:
                print(f"Failed to get commit tree: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"Error getting commit tree: {e}")
            return None

    def get_tree_contents(self, owner, repo, tree_sha, recursive=False):
        """
        Get the contents of a Git tree (optionally recursive)
        """
        if not self.check_rate_limit():
            return None
            
        url = f"{self.base_url}/repos/{owner}/{repo}/git/trees/{tree_sha}"
        params = {}
        if recursive:
            params['recursive'] = '1'
        
        try:
            response = self.session.get(url, params=params)
            
            if response.status_code == 200:
                tree_data = response.json()
                return tree_data
            else:
                print(f"Failed to get tree contents: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"Error getting tree contents: {e}")
            return None

    def get_file_commit_history(self, owner, repo, file_path, until_sha=None):
        """
        Get commit history for a specific file, optionally until a specific commit
        """
        if not self.check_rate_limit():
            return None
            
        url = f"{self.base_url}/repos/{owner}/{repo}/commits"
        params = {
            'path': file_path,
            'per_page': 100  # Get more history
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
        """
        Find the earliest commit that contains any of the changed files
        """
        earliest_commit = None
        earliest_date = None
        file_origins = {}
        
        #print("🔍 Tracing file origins...")
        
        for file_info in changed_files:
            if file_info['status'] == 'added':
                continue  # Skip newly added files
                
            file_path = file_info.get('previous_filename', file_info['filename'])
            #print(f"  Tracing {file_path}...")
            
            # Get commit history for this file up to the base commit
            history = self.get_file_commit_history(owner, repo, file_path, base_sha)
            
            if history and len(history) > 0:
                # The last commit in the history is the earliest one
                file_earliest = history[-1]
                file_commit_date = file_earliest['commit']['committer']['date']
                file_origins[file_path] = {
                    'commit': file_earliest,
                    'date': file_commit_date,
                    'sha': file_earliest['sha']
                }
                
                #print(f"    Earliest commit: {file_earliest['sha'][:8]} ({file_commit_date})")
                
                # Track the globally earliest commit
                if earliest_date is None or file_commit_date < earliest_date:
                    earliest_date = file_commit_date
                    earliest_commit = file_earliest
                    
        if earliest_commit:
            #print(f"📅 Earliest origin commit: {earliest_commit['sha'][:8]} ({earliest_date})")
            return {
                'commit': earliest_commit,
                'date': earliest_date,
                'sha': earliest_commit['sha'],
                'file_origins': file_origins
            }
        else:
            print("⚠️  Could not determine earliest commit, falling back to base commit")
            return None

    def get_blob_details(self, owner, repo, blob_sha):
        """
        Get blob details using the Git blobs API
        """
        if not self.check_rate_limit():
            return None
            
        url = f"{self.base_url}/repos/{owner}/{repo}/git/blobs/{blob_sha}"
        
        try:
            response = self.session.get(url)
            
            if response.status_code == 200:
                blob_data = response.json()
                return blob_data
            else:
                print(f"Failed to get blob details: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"Error getting blob details: {e}")
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

def handle_pr_files_via_api(github_url, search_terms=None):
    """
    Handle pull request files using GitHub API, returning accurate blob URLs and commit information
    """
    url_type, url_parts = parse_github_url(github_url)
    
    if not url_parts:
        print(f"Could not parse GitHub URL: {github_url}")
        return None
    
    if url_type != 'pull':
        print(f"This function handles pull request URLs. Got: {url_type}")
        return None
    
    owner = url_parts['owner']
    repo = url_parts['repo']
    pr_number = url_parts['pr']
    
    #print(f"Processing pull request #{pr_number} from {owner}/{repo}")
    
    api = GitHubAPIHandler()
    
    pr_info = api.get_pr_files(owner, repo, pr_number)
    
    if not pr_info:
        print("Could not retrieve pull request information")
        return None
    
    smart_contract_extensions = ('.sol', '.vy', '.rs', '.move', '.cairo', '.fc', '.func')
    matching_files = []
    
    for file_info in pr_info['files']:
        filename = file_info['filename']
        status = file_info['status']
        #print(f"  - {filename} ({status}, +{file_info['additions']}/-{file_info['deletions']})")
        
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
    
    return {
        'pr_number': pr_info['pr_number'],
        'base_branch': pr_info['base_ref'],
        'head_branch': pr_info['head_ref'],
        'base_commit_sha': pr_info['base_sha'],
        'head_commit_sha': pr_info['head_sha'],
        'base_tree_url': pr_info['base_tree_url'],
        'head_tree_url': pr_info['head_tree_url'],
        'original_tree_url': pr_info.get('original_tree_url'),  # Earliest origin tree
        'base_tree_info': pr_info.get('base_tree_info'),
        'head_tree_info': pr_info.get('head_tree_info'),
        'earliest_tree_info': pr_info.get('earliest_tree_info'),  # Tree info for earliest origin
        'earliest_commit_info': pr_info.get('earliest_commit_info'),  # Full earliest commit details
        'files': matching_files
    }

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
    """Test the GitHub API approach with a pull request"""
    test_url = "https://github.com/Brahma-fi/protected_moonshots/pull/37"
    
    #print("Testing GitHub API approach for pull request...")
    #print("=" * 60)
    
    result = handle_pr_files_via_api(test_url)
    
    if result:
        #print(f"\nPull Request #{result['pr_number']}")
        #print(f"Base branch (original files): {result['base_branch']} (SHA: {result['base_commit_sha']})")
        #print(f"Head branch (changed files): {result['head_branch']} (SHA: {result['head_commit_sha']})")
        # print(f"Base tree URL: {result['base_tree_url']}")
        #print(f"Head tree URL: {result['head_tree_url']}")
        if result.get('original_tree_url'):
            print(f"Original tree URL (earliest files origin): {result['original_tree_url']}")
        
        # Display tree information
        if result.get('base_tree_info'):
            base_tree = result['base_tree_info']
            #print(f"Base tree SHA: {base_tree['tree_sha']}")
            #print(f"Base tree API URL: {base_tree['tree_api_url']}")
        
        if result.get('earliest_tree_info') and result.get('earliest_commit_info'):
            earliest_tree = result['earliest_tree_info']
            earliest_commit = result['earliest_commit_info']
            #print(f"Earliest origin tree SHA: {earliest_tree['tree_sha']}")
            #print(f"Earliest origin commit: {earliest_commit['sha']} ({earliest_commit['date']})")
            #print(f"Earliest origin tree API URL: {earliest_tree['tree_api_url']}")
            
        if result.get('head_tree_info'):
            head_tree = result['head_tree_info']
            #print(f"Head tree SHA: {head_tree['tree_sha']}")
            #print(f"Head tree API URL: {head_tree['tree_api_url']}")
            print(f"New tree GitHub URL: {head_tree['tree_github_url']}")
            #print(f"New tree Git API URL: {head_tree['tree_git_url']}")
        
        print(f"\n✓ Found {len(result['files'])} smart contract files:")
        for file_info in result['files']:
            print(f"\n--- File: {file_info['file_path']} ---")
            if file_info['previous_file_path'] != file_info['file_path']:
                print(f"Previous name: {file_info['previous_file_path']}")
            #print(f"Status: {file_info['status']} (+{file_info['additions']}/-{file_info['deletions']})")
            
            if file_info['old_branch']:
                print(f"Old version:")
                #print(f"  Branch: {file_info['old_branch']}")
                #print(f"  Commit: {file_info['base_commit_sha']}")
                print(f"  Blob URL: {file_info['old_blob_url']}")
                #print(f"  Contents API: {file_info['contents_url_old']}")
            else:
                print("Old version: N/A (file was added)")
                
            if file_info['new_branch']:
                print(f"New version:")
                #print(f"  Branch: {file_info['new_branch']}")
                #print(f"  Commit: {file_info['head_commit_sha']}")
                print(f"  Blob URL: {file_info['new_blob_url']}")
                #print(f"  Contents API: {file_info['contents_url_new']}")
                # if file_info['blob_sha']:
                #     print(f"  Blob SHA: {file_info['blob_sha']}")
            else:
                print("New version: N/A (file was removed)")
                
        # Demonstrate getting file content from specific commits
        if result['files']:
            api = GitHubAPIHandler()
            sample_file = result['files'][0]
            
            # Show file origins if available
            # if result.get('earliest_commit_info') and result['earliest_commit_info'].get('file_origins'):
            #     print(f"\n--- File Origins ---")
            #     for file_path, origin_info in result['earliest_commit_info']['file_origins'].items():
            #         print(f"{file_path}: {origin_info['sha'][:8]} ({origin_info['date']})")
            
            # Show tree structure example
            # if result.get('head_tree_info'):
            #     print(f"\n--- Tree Structure Example ---")
            #     owner, repo = test_url.split('/')[3:5]
            #     tree_contents = api.get_tree_contents(owner, repo, result['head_tree_info']['tree_sha'])
            #     if tree_contents:
            #         print(f"Tree contains {len(tree_contents.get('tree', []))} items")
            #         # Show first few files as example
            #         for item in tree_contents.get('tree', [])[:5]:
            #             print(f"  {item['type']}: {item['path']} (SHA: {item['sha']})")
            #         if len(tree_contents.get('tree', [])) > 5:
            #             print(f"  ... and {len(tree_contents.get('tree', [])) - 5} more items")
            
            # if sample_file['contents_url_old']:
            #     print(f"\n--- Sample: Getting old content for {sample_file['file_path']} ---")
            #     owner, repo = test_url.split('/')[3:5]
            #     old_content = api.get_file_content_at_commit(
            #         owner, repo, 
            #         sample_file['base_commit_sha'], 
            #         sample_file['previous_file_path']
            #     )
            #     if old_content:
            #         print(f"Old content preview (first 200 chars):")
            #         print(old_content[:200] + "..." if len(old_content) > 200 else old_content)
    else:
        print("No matching files found")

if __name__ == "__main__":
    main()