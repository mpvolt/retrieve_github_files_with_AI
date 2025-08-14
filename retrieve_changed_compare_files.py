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
    
    def get_compare_files(self, owner, repo, base, head):
        """
        Get list of changed files in a comparison between two refs via GitHub API
        """
        if not self.check_rate_limit():
            print("Rate limit exceeded!")
            return None
            
        url = f"{self.base_url}/repos/{owner}/{repo}/compare/{base}...{head}"
        
        try:
            #print(f"Fetching comparison files: {url}")
            response = self.session.get(url)
            
            if response.status_code == 200:
                compare_data = response.json()
                #print(f"✓ Successfully retrieved comparison between {base} and {head}")
                
                compare_info = {
                    'base': base,
                    'head': head,
                    'base_tree_url': f"https://github.com/{owner}/{repo}/tree/{base}",
                    'head_tree_url': f"https://github.com/{owner}/{repo}/tree/{head}",
                    'files': []
                }
                
                # Process changed files
                for file_info in compare_data.get('files', []):
                    older_blob_url = f"https://github.com/{owner}/{repo}/blob/{base}/{quote(file_info['filename'])}" if file_info['status'] != 'added' else ''

                    file_data = {
                        'filename': file_info['filename'],
                        'status': file_info['status'],  # added, modified, removed, renamed
                        'additions': file_info.get('additions', 0),
                        'deletions': file_info.get('deletions', 0),
                        'changes': file_info.get('changes', 0),
                        'patch': file_info.get('patch', ''),
                        'raw_url': file_info.get('raw_url', ''),
                        'blob_url': file_info.get('blob_url', ''),
                        'older_blob_url': older_blob_url
                    }
                    compare_info['files'].append(file_data)
                
                print(f"Found {len(compare_info['files'])} changed files")
                return compare_info
                
            elif response.status_code == 404:
                print(f"✗ Comparison not found (404)")
                return None
            elif response.status_code == 403:
                print(f"✗ API access forbidden (403). Check your API key or rate limits")
                return None
            else:
                print(f"✗ API request failed with status {response.status_code}: {response.text}")
                return None
                
        except Exception as e:
            print(f"Error fetching comparison files: {e}")
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
    Handle comparison files using GitHub API, returning tree URLs and blob links
    """
    url_type, url_parts = parse_github_url(github_url)
    
    if not url_parts:
        #print(f"Could not parse GitHub URL: {github_url}")
        return None
    
    if url_type != 'compare':
        #print(f"This function handles compare URLs. Got: {url_type}")
        return None
    
    owner = url_parts['owner']
    repo = url_parts['repo']
    base = url_parts['base']
    head = url_parts['head']
    
    # print(f"Processing comparison between {base} and {head} from {owner}/{repo}")
    
    api = GitHubAPIHandler()
    
    compare_info = api.get_compare_files(owner, repo, base, head)
    
    if not compare_info:
        print("Could not retrieve comparison information")
        return None
    
    # print(f"Comparison: {base}...{head}")
    # print(f"Base tree URL: {compare_info['base_tree_url']}")
    # print(f"Head tree URL: {compare_info['head_tree_url']}")
    # print(f"Changed files:")
    
    smart_contract_extensions = ('.sol', '.vy', '.rs', '.move', '.cairo', '.fc', '.func')
    matching_files = []
    
    for file_info in compare_info['files']:
        filename = file_info['filename']
        #print(f"  - {filename} ({file_info['status']}, +{file_info['additions']}/-{file_info['deletions']})")
        
        if filename.endswith(smart_contract_extensions):
            file_match = {
                'file_path': filename,
                'file_url': file_info['blob_url'],
                'older_file_url': file_info['older_blob_url'],
                'raw_url': file_info['raw_url'],
                'status': file_info['status'],
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
        'base_tree_url': compare_info['base_tree_url'],
        'head_tree_url': compare_info['head_tree_url'],
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
    """Test the GitHub API approach with a compare URL"""
    test_url = "https://github.com/wavey0x/yearn-boosted-staker/compare/f0d1833de0530c124dacd1572b3cf401a71702d9...0d42a0ff1868efcab35494b814cea4de4c183e12"

    
    # print("Testing GitHub API approach for comparison...")
    # print("=" * 60)
    
    result = handle_compare_files_via_api(test_url)
    
    if result:
        print(f"Old tree version: {result['base_tree_url']}")
        print(f"New tree version: {result['head_tree_url']}")
        for file_info in result['files']:
            print(f"New Blob URL:  {file_info['file_url']}")
            print(f"Older Blob URL:  {file_info['older_file_url']}")
            print(f"Status: {file_info['status']} (+{file_info['additions']}/-{file_info['deletions']})")
            
    else:
        print("No matching files found")

if __name__ == "__main__":
    main()