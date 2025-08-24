#!/usr/bin/env python3

import os
import requests
import json
import time
from urllib.parse import urlparse, quote

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
    
    def safe_url_encode(self, path):
        """Safely encode a file path for GitHub URLs"""
        from urllib.parse import quote
        # Split path by / and encode each part separately to handle special characters
        parts = path.split('/')
        encoded_parts = [quote(part, safe='') for part in parts]
        return '/'.join(encoded_parts)
    
    def get_compare_files(self, owner, repo, base, head):
        """
        Get list of changed files in a comparison between two refs via GitHub GraphQL API
        """
        if not self.api_key:
            print("GraphQL API requires authentication. Please set GITHUB_API_KEY environment variable.")
            return None
            
        if not self.check_rate_limit():
            print("Rate limit exceeded!")
            return None
        
        # GraphQL query to compare two refs and get file changes
        query = """
        query CompareRefs($owner: String!, $repo: String!, $base: String!, $head: String!, $cursor: String) {
            repository(owner: $owner, name: $repo) {
                object(expression: $head) {
                    ... on Commit {
                        oid
                        comparison(base: $base) {
                            status
                            aheadBy
                            behindBy
                            commits(first: 10) {
                                totalCount
                                edges {
                                    node {
                                        oid
                                        messageHeadline
                                        author {
                                            name
                                            date
                                        }
                                    }
                                }
                            }
                            files(first: 100, after: $cursor) {
                                pageInfo {
                                    hasNextPage
                                    endCursor
                                }
                                totalCount
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
                        }
                    }
                }
                baseRef: object(expression: $base) {
                    ... on Commit {
                        oid
                        tree {
                            oid
                        }
                    }
                }
                headRef: object(expression: $head) {
                    ... on Commit {
                        oid
                        tree {
                            oid
                        }
                    }
                }
            }
        }
        """
        
        variables = {
            "owner": owner,
            "repo": repo,
            "base": base,
            "head": head
        }
        
        try:
            print(f"🔄 Fetching comparison {base}...{head} via GraphQL...")
            
            # Get all files (handle pagination)
            all_files = []
            cursor = None
            comparison_info = None
            
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
                
                repo_data = data.get('data', {}).get('repository')
                if not repo_data:
                    print(f"✗ Repository or comparison not found")
                    return None
                
                head_obj = repo_data.get('object')
                if not head_obj or not head_obj.get('comparison'):
                    print(f"✗ Could not get comparison data between {base} and {head}")
                    return None
                
                comparison = head_obj['comparison']
                
                # Store comparison info on first iteration
                if comparison_info is None:
                    base_obj = repo_data.get('baseRef', {})
                    head_ref_obj = repo_data.get('headRef', {})
                    
                    comparison_info = {
                        'base': base,
                        'head': head,
                        'base_oid': base_obj.get('oid', base),
                        'head_oid': head_ref_obj.get('oid', head),
                        'base_tree_oid': base_obj.get('tree', {}).get('oid') if base_obj.get('tree') else None,
                        'head_tree_oid': head_ref_obj.get('tree', {}).get('oid') if head_ref_obj.get('tree') else None,
                        'base_tree_url': f"https://github.com/{owner}/{repo}/tree/{base}",
                        'head_tree_url': f"https://github.com/{owner}/{repo}/tree/{head}",
                        'status': comparison.get('status', 'unknown'),
                        'ahead_by': comparison.get('aheadBy', 0),
                        'behind_by': comparison.get('behindBy', 0),
                        'total_commits': comparison.get('commits', {}).get('totalCount', 0),
                        'total_files': comparison.get('files', {}).get('totalCount', 0),
                        'files': []
                    }
                    
                    # Add commit information
                    commits = comparison.get('commits', {}).get('edges', [])
                    comparison_info['commits'] = []
                    for commit_edge in commits:
                        commit = commit_edge['node']
                        comparison_info['commits'].append({
                            'oid': commit['oid'],
                            'message': commit.get('messageHeadline', ''),
                            'author': commit.get('author', {}).get('name', ''),
                            'date': commit.get('author', {}).get('date', '')
                        })
                
                # Add files from this page
                files_data = comparison.get('files', {}).get('edges', [])
                all_files.extend([edge['node'] for edge in files_data])
                
                # Check if there are more pages
                page_info = comparison.get('files', {}).get('pageInfo', {})
                if page_info.get('hasNextPage'):
                    cursor = page_info.get('endCursor')
                else:
                    break
            
            print(f"✓ Retrieved {len(all_files)} files from comparison")
            
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
                
                # Handle older filename for different file statuses
                older_filename = filename
                older_blob_url = ''
                
                if status == 'added':
                    # New file, no older version exists
                    older_filename = ''
                    older_blob_url = ''
                elif status == 'removed':
                    # File was deleted, older version exists with same name
                    older_filename = filename
                    older_blob_url = f"https://github.com/{owner}/{repo}/blob/{base}/{self.safe_url_encode(filename)}"
                elif status == 'renamed':
                    # File was renamed, extract previous filename from patch
                    previous_name = self._extract_previous_filename_from_patch(file_data.get('patch', ''))
                    if previous_name:
                        older_filename = previous_name
                        older_blob_url = f"https://github.com/{owner}/{repo}/blob/{base}/{self.safe_url_encode(older_filename)}"
                    else:
                        # Fallback to current filename
                        older_blob_url = f"https://github.com/{owner}/{repo}/blob/{base}/{self.safe_url_encode(filename)}"
                else:
                    # Modified file, same filename
                    older_blob_url = f"https://github.com/{owner}/{repo}/blob/{base}/{self.safe_url_encode(filename)}"
                
                # Construct current file URLs
                current_blob_url = ''
                raw_url = ''
                if status != 'removed':
                    current_blob_url = f"https://github.com/{owner}/{repo}/blob/{head}/{self.safe_url_encode(filename)}"
                    raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{head}/{self.safe_url_encode(filename)}"
                
                # Construct older raw URL
                older_raw_url = ''
                if status != 'added' and older_filename:
                    older_raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{base}/{self.safe_url_encode(older_filename)}"
                
                file_info = {
                    'filename': filename,
                    'older_filename': older_filename,
                    'status': status,
                    'additions': file_data.get('additions', 0),
                    'deletions': file_data.get('deletions', 0),
                    'changes': (file_data.get('additions', 0) + file_data.get('deletions', 0)),
                    'patch': file_data.get('patch', ''),
                    'raw_url': raw_url,
                    'older_raw_url': older_raw_url,
                    'blob_url': current_blob_url,
                    'older_blob_url': older_blob_url,
                    'previous_filename': older_filename if status == 'renamed' else '',
                    'contents_url': f"https://api.github.com/repos/{owner}/{repo}/contents/{self.safe_url_encode(filename)}?ref={head}" if status != 'removed' else ''
                }
                
                comparison_info['files'].append(file_info)
            
            print(f"Found {len(comparison_info['files'])} changed files")
            return comparison_info
            
        except Exception as e:
            print(f"Error fetching comparison files via GraphQL: {e}")
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
            old_name = old_file_match.group(1)
            # Make sure it's different from the new name
            new_file_match = re.search(r'^\+\+\+ b/(.+)$', patch, re.MULTILINE)
            if new_file_match and new_file_match.group(1) != old_name:
                return old_name
        
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
    
    def get_file_content_at_commit(self, owner, repo, commit_hash, file_path):
        """
        Get specific file content at a specific commit via GraphQL
        """
        return self.get_file_content_with_graphql(owner, repo, file_path, commit_hash)
    
    def get_older_file_raw_url(self, owner, repo, base_commit, file_path):
        """
        Get the raw URL for a file at a specific commit
        """
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{base_commit}/{self.safe_url_encode(file_path)}"

def parse_github_url(url):
    """Parse GitHub URL to extract owner, repo, and compare info"""
    import re
    
    patterns = {
        'compare': r'https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/compare/(?P<base>[^#]+)\.\.\.(?P<head>[^#]+)',
        'commit': r'https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/commit/(?P<commit>[a-fA-F0-9]+)',
        'pull': r'https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/pull/(?P<pr>\d+)',
        'tree': r'https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/tree/(?P<ref>.+)'
    }
    
    for url_type, pattern in patterns.items():
        match = re.match(pattern, url)
        if match:
            return url_type, match.groupdict()
    
    return None, None

def handle_compare_files_via_api(github_url, search_terms=None):
    """
    Handle comparison files using GitHub GraphQL API, returning tree URLs and blob links
    """
    url_type, url_parts = parse_github_url(github_url)
    
    if not url_parts:
        # print(f"Could not parse GitHub URL: {github_url}")
        return None
    
    if url_type != 'compare':
        # print(f"This function handles compare URLs. Got: {url_type}")
        return None
    
    owner = url_parts['owner']
    repo = url_parts['repo']
    base = url_parts['base']
    head = url_parts['head']
    
    # print(f"Processing comparison between {base} and {head} from {owner}/{repo}")
    
    api = GitHubGraphQLHandler()
    
    compare_info = api.get_compare_files(owner, repo, base, head)
    
    if not compare_info:
        print("Could not retrieve comparison information")
        return None
    
    # Print comparison summary
    print(f"Comparison: {base}...{head}")
    print(f"Status: {compare_info['status']}")
    print(f"Ahead by: {compare_info['ahead_by']} commits")
    print(f"Behind by: {compare_info['behind_by']} commits")
    print(f"Total commits: {compare_info['total_commits']}")
    print(f"Total files changed: {compare_info['total_files']}")
    print(f"Base tree URL: {compare_info['base_tree_url']}")
    print(f"Head tree URL: {compare_info['head_tree_url']}")
    
    # Show recent commits in the comparison
    if compare_info.get('commits'):
        print("Recent commits in comparison:")
        for commit in compare_info['commits'][:3]:  # Show first 3 commits
            print(f"  - {commit['oid'][:8]}: {commit['message'][:60]}{'...' if len(commit['message']) > 60 else ''}")
            print(f"    by {commit['author']} on {commit['date']}")
    
    print("Changed files:")
    
    smart_contract_extensions = ('.sol', '.vy', '.rs', '.move', '.cairo', '.fc', '.func')
    matching_files = []
    
    for file_info in compare_info['files']:
        filename = file_info['filename']
        older_filename = file_info['older_filename']
        status_info = f" ({file_info['status']}, +{file_info['additions']}/-{file_info['deletions']})"
        
        # Show rename information if applicable
        if file_info['status'] == 'renamed' and file_info['previous_filename']:
            print(f"  - {older_filename} → {filename}{status_info}")
        else:
            print(f"  - {filename}{status_info}")
        
        # Check if either current or older filename matches smart contract extensions
        is_smart_contract = (filename.endswith(smart_contract_extensions) or 
                           (older_filename and older_filename.endswith(smart_contract_extensions)))
        
        if is_smart_contract:
            file_match = {
                'file_path': filename,
                'older_file_path': older_filename,
                'file_url': file_info['blob_url'],
                'older_file_url': file_info['older_blob_url'],
                'raw_url': file_info['raw_url'],
                'older_raw_url': file_info['older_raw_url'],
                'status': file_info['status'],
                'additions': file_info['additions'],
                'deletions': file_info['deletions'],
                'changes': file_info['changes'],
                'previous_filename': file_info.get('previous_filename', ''),
                'score': 100
            }
            
            if search_terms:
                # Calculate score based on both current and older filenames
                score = calculate_relevance_score(filename, file_info.get('patch', ''), search_terms)
                if older_filename and older_filename != filename:
                    older_score = calculate_relevance_score(older_filename, file_info.get('patch', ''), search_terms)
                    score = max(score, older_score)
                
                file_match['score'] = score
                
                if score > 0:
                    matching_files.append(file_match)
            else:
                matching_files.append(file_match)
    
    result = {
        'base_tree_url': compare_info['base_tree_url'],
        'head_tree_url': compare_info['head_tree_url'],
        'comparison_info': compare_info,  # Full comparison data
        'files': matching_files
    }
    
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
    """Test the GitHub API approach with a compare URL"""
    test_url = "https://github.com/wavey0x/yearn-boosted-staker/compare/f0d1833de0530c124dacd1572b3cf401a71702d9...0d42a0ff1868efcab35494b814cea4de4c183e12"

    
    # print("Testing GitHub API approach for comparison...")
    # print("=" * 60)
    
    result = handle_compare_files_via_api(test_url)
    
    if result:
        print(f"Old tree version: {result['base_tree_url']}")
        print(f"New tree version: {result['head_tree_url']}")
        for file_info in result['files']:
            print(f"Current file: {file_info['file_path']}")
            if file_info['older_file_path'] and file_info['older_file_path'] != file_info['file_path']:
                print(f"Previous file: {file_info['older_file_path']}")
            print(f"New Blob URL:  {file_info['file_url']}")
            print(f"Older Blob URL:  {file_info['older_file_url']}")
            print(f"New Raw URL:  {file_info['raw_url']}")
            if file_info['older_raw_url']:
                print(f"Older Raw URL:  {file_info['older_raw_url']}")
            print(f"Status: {file_info['status']} (+{file_info['additions']}/-{file_info['deletions']})")
            print("-" * 40)
            
    else:
        print("No matching files found")

if __name__ == "__main__":
    main()