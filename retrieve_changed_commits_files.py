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
            # print("✓ GitHub API key found and configured")
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
    
    def get_commit_info(self, owner, repo, commit_hash):
        """
        Get detailed commit information including changed files via GitHub API.
        - commit_hash: The newer version (current commit)
        - parent_sha: The older version (parent commit)
        """
        if not self.check_rate_limit():
            print("Rate limit exceeded!")
            return None
            
        url = f"{self.base_url}/repos/{owner}/{repo}/commits/{commit_hash}"
        
        try:
            # print(f"Fetching commit info: {url}")
            response = self.session.get(url)
            
            if response.status_code == 200:
                commit_data = response.json()
                # print(f"✓ Successfully retrieved commit {commit_hash}")
                
                # Get parent commit SHA (older version)
                parent_sha = commit_data['parents'][0]['sha'] if commit_data.get('parents') else None
                if not parent_sha:
                    print("⚠ No parent commit found (this might be the initial commit)")
                    parent_sha = commit_hash  # Fallback to current commit if no parent
                
                # Construct tree URLs
                newer_tree_url = f"https://github.com/{owner}/{repo}/tree/{commit_hash}"  # Current commit (newer)
                older_tree_url = f"https://github.com/{owner}/{repo}/tree/{parent_sha}"  # Parent commit (older)
                
                # Extract relevant information
                commit_info = {
                    'sha': commit_data['sha'],
                    'parent_sha': parent_sha,
                    'message': commit_data['commit']['message'],
                    'author': commit_data['commit']['author']['name'],
                    'date': commit_data['commit']['author']['date'],
                    'url': commit_data['html_url'],
                    'newer_tree_url': newer_tree_url,  # Current commit tree
                    'older_tree_url': older_tree_url,  # Parent commit tree
                    'files': []
                }
                
                # Process changed files
                for file_info in commit_data.get('files', []):
                    # Determine the correct filename for the older version
                    older_filename = file_info['filename']  # Default to current filename
                    
                    # Handle renamed files - use previous_filename for older blob URL
                    if file_info['status'] == 'renamed' and 'previous_filename' in file_info:
                        older_filename = file_info['previous_filename']
                    
                    # Construct older blob URL using the correct older filename
                    older_blob_url = ''
                    if file_info['status'] != 'added':  # Don't create older URL for newly added files
                        older_blob_url = f"https://github.com/{owner}/{repo}/blob/{parent_sha}/{quote(older_filename)}"
                    
                    file_data = {
                        'filename': file_info['filename'],
                        'older_filename': older_filename,  # Track the older filename separately
                        'status': file_info['status'],  # added, modified, removed, renamed
                        'additions': file_info.get('additions', 0),
                        'deletions': file_info.get('deletions', 0),
                        'changes': file_info.get('changes', 0),
                        'patch': file_info.get('patch', ''),
                        'raw_url': file_info.get('raw_url', ''),
                        'blob_url': file_info.get('blob_url', ''),  # Blob URL for the file in the current commit
                        'older_blob_url': older_blob_url,
                        'previous_filename': file_info.get('previous_filename', '')  # Include previous filename info
                    }
                    commit_info['files'].append(file_data)
                
                # print(f"Found {len(commit_info['files'])} changed files")
                return commit_info
                
            elif response.status_code == 404:
                print(f"✗ Commit {commit_hash} not found (404)")
                return None
            elif response.status_code == 403:
                print(f"✗ API access forbidden (403). Check your API key or rate limits")
                return None
            else:
                print(f"✗ API request failed with status {response.status_code}: {response.text}")
                return None
                
        except Exception as e:
            print(f"Error fetching commit info: {e}")
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
    
    def get_file_content_at_commit(self, owner, repo, commit_hash, file_path):
        """
        Get specific file content at a specific commit via GitHub API
        """
        if not self.check_rate_limit():
            return None
            
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{file_path}"
        
        try:
            response = self.session.get(url, params={'ref': commit_hash})
            
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

def parse_github_url(url):
    """Parse GitHub URL to extract owner, repo, and commit info"""
    import re
    
    patterns = {
        'commit': r'https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/commit/(?P<commit>[a-fA-F0-9]+)',
        'pull': r'https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/pull/(?P<pr>\d+)',
        'compare': r'https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/compare/(?P<base>[^#]+)\.\.\.(?P<head>[^#]+)',
        'tree': r'https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/tree/(?P<ref>.+)'
    }
    
    for url_type, pattern in patterns.items():
        match = re.match(pattern, url)
        if match:
            return url_type, match.groupdict()
    
    return None, None

def handle_commit_files_via_api(github_url, search_terms=None):
    """
    Handle commit files using GitHub API, returning older and newer tree URLs and blob links
    """
    url_type, url_parts = parse_github_url(github_url)
    
    if not url_parts:
        print(f"Could not parse GitHub URL: {github_url}")
        return None
    
    if url_type != 'commit':
        print(f"This function handles commit URLs. Got: {url_type}")
        return None
    
    owner = url_parts['owner']
    repo = url_parts['repo']
    commit_hash = url_parts['commit']
    
    # print(f"Processing commit {commit_hash} from {owner}/{repo}")
    
    api = GitHubAPIHandler()
    
    commit_info = api.get_commit_info(owner, repo, commit_hash)
    
    if not commit_info:
        print("Could not retrieve commit information")
        return None
    
    # print(f"Commit: {commit_info['message'][:100]}...")
    # print(f"Author: {commit_info['author']} ({commit_info['date']})")
    # print(f"Newer tree URL (commit, {commit_info['sha']}): {commit_info['newer_tree_url']}")
    # print(f"Older tree URL (parent, {commit_info['parent_sha']}): {commit_info['older_tree_url']}")
    # print(f"Changed files:")
    
    smart_contract_extensions = ('.sol', '.vy', '.rs', '.move', '.cairo', '.fc', '.func')
    matching_files = []
    
    for file_info in commit_info['files']:
        filename = file_info['filename']
        older_filename = file_info['older_filename']
        status_info = f" ({file_info['status']}, +{file_info['additions']}/-{file_info['deletions']})"
        
        # Show rename information if applicable
        if file_info['status'] == 'renamed' and file_info['previous_filename']:
            print(f"  - {older_filename} → {filename}{status_info}")
        else:
            print(f"  - {filename}{status_info}")
        
        # Check if either the current or older filename matches smart contract extensions
        current_is_contract = filename.endswith(smart_contract_extensions)
        older_is_contract = older_filename.endswith(smart_contract_extensions)
        
        if current_is_contract or older_is_contract:
            file_match = {
                'file_path': filename,
                'older_file_path': older_filename,  # Include older file path
                'file_url': file_info['blob_url'],  # Blob URL for the file in the current commit
                'older_file_url': file_info['older_blob_url'],
                'raw_url': file_info['raw_url'],
                'status': file_info['status'],
                'additions': file_info['additions'],
                'deletions': file_info['deletions'],
                'score': 100,
                'previous_filename': file_info['previous_filename']  # Include rename info
            }
            
            if search_terms:
                # Calculate score based on both current and older filenames
                score = max(
                    calculate_relevance_score(filename, file_info.get('patch', ''), search_terms),
                    calculate_relevance_score(older_filename, file_info.get('patch', ''), search_terms)
                )
                file_match['score'] = score
                
                if score > 0:
                    matching_files.append(file_match)
            else:
                matching_files.append(file_match)
    
    return {
        'newer_tree_url': commit_info['newer_tree_url'],  # Current commit (newer)
        'older_tree_url': commit_info['older_tree_url'],  # Parent commit (older)
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
    """Test the GitHub API approach with a commit"""
    test_url = "https://github.com/get-smooth/crypto-lib/commit/0af3c3cae84b29a14fa374a29824dc3abbb3d586"
    
    # print("Testing GitHub API approach for commit...")
    # print("=" * 60)
    
    result = handle_commit_files_via_api(test_url)
    
    if result:
        print(f"\nNewer tree URL: {result['newer_tree_url']}")
        print(f"Older tree URL: {result['older_tree_url']}")
        # print(f"\n✓ Found {len(result['files'])} smart contract files:")
        for file_info in result['files']:
            print(f"\nFile: {file_info['file_path']}")
            if file_info['older_file_path'] != file_info['file_path']:
                print(f"Previous name: {file_info['older_file_path']}")
            print(f"New Blob URL: {file_info['file_url']}")
            print(f"Older Blob URL: {file_info['older_file_url']}")

            #print(f"Status: {file_info['status']} (+{file_info['additions']}/-{file_info['deletions']})")
            
            api = GitHubAPIHandler()
            if file_info['raw_url']:
                # print("Getting file content...")
                content = api.get_file_content(file_info['raw_url'])
                # if content:
                #     print(f"Content preview (first 200 chars):")
                #     print(content[:200] + "..." if len(content) > 200 else content)
        
    else:
        print("No matching files found")

if __name__ == "__main__":
    main()