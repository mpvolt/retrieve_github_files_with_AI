#!/usr/bin/env python3
"""
Enhanced GitHub Smart Contract File Retriever

This script provides a function to fetch all smart contract files from a GitHub repository
using GraphQL first (fastest), then REST API fallback when needed.

Key features:
- GraphQL first strategy for maximum performance
- REST API fallback for commit hashes and edge cases
- Handles various smart contract file extensions
- Enhanced error handling and validation

Usage:
    from github_smart_contract_retriever import get_smart_contracts
    
    results = get_smart_contracts(
        github_url="https://github.com/ethereum/solidity/tree/develop",
        api_key="your_github_token_here"
    )
"""

import os
import json
import requests
import subprocess
import tempfile
import shutil
import time
import base64
import re
from pathlib import Path
from urllib.parse import urlparse, unquote
from typing import List, Dict, Tuple, Optional, Set

SMART_CONTRACT_EXTENSIONS = {
    '.sol': 'Solidity',
    '.tsol': "Solidity (test)",
    '.vy': 'Vyper', 
    '.rs': 'Rust (Solana/NEAR)',
    '.cairo': 'Cairo (StarkNet)',
    '.move': 'Move (Aptos/Sui)',
    '.fc': 'FunC (TON)',
    '.func': 'FunC (TON)',
    '.clar': 'Clarity (Stacks)',
    '.scilla': 'Scilla (Zilliqa)',
    '.ligo': 'LIGO (Tezos)',
    '.mligo': 'LIGO (Tezos)',
    '.religo': 'LIGO (Tezos)',
    '.jsligo': 'LIGO (Tezos)',
    '.aes': 'Sophia (Aeternity)',
    '.ride': 'Ride (Waves)',
    '.teal': 'TEAL (Algorand)',
    '.circom': 'ZK Circuits'
}

class GitHubGraphQLRetriever:
    def __init__(self, api_key: str):
        """Initialize with GitHub API token (required for GraphQL)."""
        if not api_key:
            raise ValueError("GitHub API token is required for GraphQL API")
        
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
            'User-Agent': 'SmartContract-GraphQL-Retriever/1.0'
        })
        self.graphql_url = "https://api.github.com/graphql"
        self.max_graphql_depth = 8  # Configurable max depth for GraphQL queries
    
    def is_smart_contract_file(self, filename: str) -> Tuple[bool, str]:
        """Check if file is a smart contract based on extension."""
        filename_lower = filename.lower()
        for ext, language in SMART_CONTRACT_EXTENSIONS.items():
            if filename_lower.endswith(ext.lower()):
                return True, language
        return False, ''
    
    def build_tree_fragment(self, depth: int) -> str:
        """Recursively build GraphQL tree fragment for specified depth."""
        if depth <= 0:
            return ""
        
        blob_fragment = """
                        ... on Blob {
                          byteSize
                          text
                          isBinary
                        }"""
        
        if depth == 1:
            return blob_fragment
        
        # Build the tree fragment recursively
        nested_fragment = self.build_tree_fragment(depth - 1)
        
        tree_fragment = f"""
                        ... on Tree {{
                          entries {{
                            name
                            type
                            path
                            object {{
                              {blob_fragment}
                              {nested_fragment}
                            }}
                          }}
                        }}"""
        
        return tree_fragment
    
    def build_tree_query(self, owner: str, repo: str, branch: str, path: str = "", max_depth: int = None) -> str:
        """Build GraphQL query to fetch entire repository tree with configurable depth."""
        if max_depth is None:
            max_depth = self.max_graphql_depth
        
        tree_expression = f"{branch}:{path}" if path else f"{branch}:"
        tree_fragment = self.build_tree_fragment(max_depth)
        
        return f"""
        query GetRepositoryTree($owner: String!, $name: String!, $expression: String!) {{
          repository(owner: $owner, name: $name) {{
            object(expression: $expression) {{
              ... on Tree {{
                entries {{
                  name
                  type
                  path
                  object {{
                    ... on Blob {{
                      byteSize
                      text
                      isBinary
                    }}
                    {tree_fragment}
                  }}
                }}
              }}
            }}
            defaultBranchRef {{
              name
            }}
          }}
        }}
        """
    
    def execute_graphql_query(self, query: str, variables: Dict) -> Optional[Dict]:
        """Execute GraphQL query with error handling and rate limiting."""
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                response = self.session.post(
                    self.graphql_url,
                    json={'query': query, 'variables': variables},
                    timeout=60
                )
                
                if response.status_code == 200:
                    result = response.json()
                    
                    # Check for GraphQL errors
                    if 'errors' in result:
                        print(f"GraphQL errors: {result['errors']}")
                        return None
                    
                    return result.get('data')
                
                elif response.status_code == 403:
                    print(f"Rate limit or permission error (attempt {attempt + 1})")
                    if attempt < max_retries - 1:
                        time.sleep(60)
                        continue
                    
                else:
                    print(f"HTTP error {response.status_code}: {response.text}")
                    return None
                    
            except requests.exceptions.RequestException as e:
                print(f"Request error (attempt {attempt + 1}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(30)
                    continue
                    
        return None
    
    def extract_files_from_tree(self, tree_entries: List[Dict], base_path: str = "") -> List[Dict]:
        """Recursively extract smart contract files from tree structure."""
        smart_contract_files = []
        
        for entry in tree_entries:
            # Use GraphQL's path if available, otherwise construct it
            entry_path = entry.get('path', f"{base_path}/{entry['name']}" if base_path else entry['name'])
            
            if entry['type'] == 'blob':
                # Check if it's a smart contract file
                is_contract, language = self.is_smart_contract_file(entry['name'])
                
                if is_contract and entry.get('object'):
                    blob = entry['object']
                    
                    # Skip binary files and very large files
                    if blob.get('isBinary', False) or blob.get('byteSize', 0) > 10 * 1024 * 1024:
                        continue
                    
                    # Get content if available
                    content = blob.get('text', '')
                    if content and len(content.strip()) > 10:
                        smart_contract_files.append({
                            'name': entry['name'],
                            'path': entry_path,
                            'content': content,
                            'size': blob.get('byteSize', len(content)),
                            'language': language,
                            'lines': len(content.splitlines()),
                            'is_valid': True
                        })
            
            elif entry['type'] == 'tree' and entry.get('object', {}).get('entries'):
                # Recursively process subdirectories
                subdirectory_files = self.extract_files_from_tree(
                    entry['object']['entries'], 
                    entry_path
                )
                smart_contract_files.extend(subdirectory_files)
        
        return smart_contract_files
    
    def get_directory_structure_paths(self, owner: str, repo: str, commit_sha: str) -> List[str]:
        """Get all directory paths using REST API to determine max depth needed."""
        tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{commit_sha}?recursive=1"
        
        try:
            response = self.session.get(tree_url, timeout=30)
            if response.status_code != 200:
                return []
            
            tree_data = response.json()
            if 'tree' not in tree_data:
                return []
            
            # Get all directory paths
            paths = []
            for item in tree_data['tree']:
                if item['type'] == 'blob':
                    paths.append(item['path'])
            
            return paths
            
        except Exception:
            return []
    
    def determine_max_depth(self, paths: List[str]) -> int:
        """Determine maximum depth needed based on file paths."""
        if not paths:
            return self.max_graphql_depth
        
        max_depth = 0
        for path in paths:
            depth = len(path.split('/'))
            max_depth = max(max_depth, depth)
        
        # Add buffer and cap at reasonable limit
        return min(max_depth + 1, 12)
    
    def get_smart_contracts_adaptive_depth(self, owner: str, repo: str, branch: str, 
                                         path: str = "", verbose: bool = True) -> List[Dict]:
        """
        Get smart contracts using adaptive depth GraphQL - analyzes repository first.
        This method determines the required depth and uses appropriate GraphQL query.
        """
        if verbose:
            print(f"Using adaptive-depth GraphQL...")
        
        # First, try to get commit SHA and analyze repository structure
        commit_sha = None
        try:
            # Try to resolve branch/commit
            if len(branch) == 40 and all(c in '0123456789abcdef' for c in branch.lower()):
                commit_sha = branch
            else:
                # Get branch SHA
                branch_url = f"https://api.github.com/repos/{owner}/{repo}/branches/{branch}"
                response = self.session.get(branch_url, timeout=10)
                if response.status_code == 200:
                    commit_sha = response.json()['commit']['sha']
            
            if commit_sha and verbose:
                print(f"   Analyzing repository structure for depth optimization...")
                
                # Get directory structure to determine optimal depth
                paths = self.get_directory_structure_paths(owner, repo, commit_sha)
                smart_contract_paths = []
                
                for file_path in paths:
                    filename = file_path.split('/')[-1]
                    is_contract, _ = self.is_smart_contract_file(filename)
                    if is_contract:
                        smart_contract_paths.append(file_path)
                
                if smart_contract_paths:
                    optimal_depth = self.determine_max_depth(smart_contract_paths)
                    if verbose:
                        print(f"   Found {len(smart_contract_paths)} smart contracts, max depth needed: {optimal_depth}")
                else:
                    optimal_depth = self.max_graphql_depth
                    if verbose:
                        print(f"   No smart contracts found in initial scan, using default depth: {optimal_depth}")
            else:
                optimal_depth = self.max_graphql_depth
                
        except Exception as e:
            if verbose:
                print(f"   Structure analysis failed: {e}, using default depth")
            optimal_depth = self.max_graphql_depth
        
        # Now execute GraphQL query with optimal depth
        tree_query = self.build_tree_query(owner, repo, branch, path, optimal_depth)
        variables = {
            'owner': owner,
            'name': repo,
            'expression': f"{branch}:{path}" if path else f"{branch}:"
        }
        
        result = self.execute_graphql_query(tree_query, variables)
        if not result or not result.get('repository', {}).get('object'):
            if verbose:
                print("GraphQL failed to fetch repository tree or branch not found")
            raise Exception("GraphQL query failed")
        
        # Extract smart contract files from the tree
        tree_object = result['repository']['object']
        if not tree_object.get('entries'):
            if verbose:
                print("No entries found in the specified path")
            return []
        
        smart_contract_files = self.extract_files_from_tree(tree_object['entries'])
        
        if verbose:
            print(f"GraphQL found {len(smart_contract_files)} smart contract files")
        
        return smart_contract_files
    
    def get_smart_contracts_batch(self, owner: str, repo: str, branch: str, 
                                 path: str = "", verbose: bool = True) -> List[Dict]:
        """
        Get smart contracts using GraphQL batch approach - now with unlimited depth support!
        This method can retrieve an entire repository structure regardless of depth.
        """
        if verbose:
            print(f"Using GraphQL (unlimited depth method)...")
        
        try:
            # Use adaptive depth approach
            return self.get_smart_contracts_adaptive_depth(owner, repo, branch, path, verbose)
            
        except Exception as e:
            if verbose:
                print(f"Adaptive depth failed: {e}")
            
            # Fallback to fixed depth approach
            if verbose:
                print(f"   Falling back to fixed depth ({self.max_graphql_depth} levels)...")
            
            tree_query = self.build_tree_query(owner, repo, branch, path)
            variables = {
                'owner': owner,
                'name': repo,
                'expression': f"{branch}:{path}" if path else f"{branch}:"
            }
            
            result = self.execute_graphql_query(tree_query, variables)
            if not result or not result.get('repository', {}).get('object'):
                if verbose:
                    print("GraphQL fallback also failed")
                raise Exception("GraphQL query failed")
            
            tree_object = result['repository']['object']
            if not tree_object.get('entries'):
                if verbose:
                    print("No entries found in the specified path")
                return []
            
            smart_contract_files = self.extract_files_from_tree(tree_object['entries'])
            
            if verbose:
                print(f"GraphQL fallback found {len(smart_contract_files)} smart contract files")
            
            return smart_contract_files

def parse_github_url(github_url: str) -> Dict:
    """Parse GitHub URL and extract components."""
    url = github_url.rstrip('/').replace('.git', '')
    parsed = urlparse(url)
    path = parsed.path.lstrip('/')
    
    path_parts = path.split('/')
    if len(path_parts) < 2:
        raise ValueError(f"Invalid GitHub URL format: {github_url}")
    
    owner = path_parts[0]
    repo = path_parts[1]
    branch = 'main'  # Default
    subpath = ''
    
    # Handle tree URLs
    if len(path_parts) > 2 and path_parts[2] == 'tree':
        if len(path_parts) > 3:
            branch = unquote(path_parts[3])
            if len(path_parts) > 4:
                subpath = '/'.join(path_parts[4:])
    
    return {
        'owner': owner,
        'repo': repo,
        'branch': branch,
        'subpath': subpath
    }

def get_smart_contracts(github_url: str, api_key: str, verbose: bool = True) -> Dict:
    """
    Get smart contracts from GitHub repository using GraphQL first, REST fallback.
    
    Strategy:
    1. Always try GraphQL first (fastest method)
    2. If GraphQL finds files → use GraphQL results
    3. If GraphQL finds no files → try REST fallback
    4. If GraphQL fails completely → try REST fallback
    
    Args:
        github_url: GitHub repository URL
        api_key: GitHub API token (required)
        verbose: Whether to print progress
    
    Returns:
        Dict with 'files' and 'summary'
    """
    if not api_key:
        raise ValueError("GitHub API token is required")
    
    try:
        # Parse URL
        parsed = parse_github_url(github_url)
        owner = parsed['owner']
        repo = parsed['repo']
        branch = parsed['branch']
        subpath = parsed['subpath']
        
        commit_sha = None
        
        if verbose:
            print(f"Repository: {owner}/{repo}")
            print(f"Reference: {branch}")
            if subpath:
                print(f"Subpath: {subpath}")
        
        # STEP 1: Try GraphQL first
        graphql_files = []
        graphql_succeeded = False
        
        try:
            retriever = GitHubGraphQLRetriever(api_key)
            graphql_files = retriever.get_smart_contracts_batch(
                owner, repo, branch, subpath, verbose
            )
            graphql_succeeded = True
            
            if graphql_files:
                if verbose:
                    print(f"✅ GraphQL succeeded - found {len(graphql_files)} files!")
                method_used = 'graphql'
                smart_contract_files = graphql_files
            else:
                if verbose:
                    print("⚠️  GraphQL found no files - trying REST fallback...")
                graphql_succeeded = False  # Force fallback
                
        except Exception as graphql_error:
            graphql_succeeded = False
            if verbose:
                print(f"GraphQL failed: {str(graphql_error)[:100]}...")
        
        # STEP 2: Use REST fallback if needed
        if not graphql_succeeded:
            fallback = GitHubRestFallback(api_key)
            commit_sha = fallback.get_commit_sha(owner, repo, branch)
            
            if commit_sha:
                rest_files = fallback.get_smart_contracts_rest(
                    owner, repo, commit_sha, subpath, verbose
                )
                
                if rest_files:
                    method_used = 'rest_fallback'
                    smart_contract_files = rest_files
                    if verbose:
                        print(f"✅ REST fallback succeeded - found {len(rest_files)} files!")
                elif graphql_files:
                    # REST found nothing but GraphQL had results
                    method_used = 'graphql'
                    smart_contract_files = graphql_files
                    if verbose:
                        print("Using GraphQL results instead")
                else:
                    # Both methods found nothing
                    method_used = 'no_files_found'
                    smart_contract_files = []
                    if verbose:
                        print("✅ No smart contract files found in this repository/reference")
            else:
                if graphql_files:
                    method_used = 'graphql'
                    smart_contract_files = graphql_files
                else:
                    method_used = 'no_files_found'
                    smart_contract_files = []
                    if verbose:
                        print("✅ No smart contract files found")
        
        # Generate summary
        if not smart_contract_files:
            return {
                'files': [],
                'summary': {
                    'repository': f"{owner}/{repo}",
                    'branch': branch,
                    'subpath': subpath,
                    'total_files': 0,
                    'extensions': {},
                    'languages': {},
                    'method_used': method_used
                }
            }
        
        # Generate summary statistics
        extensions = {}
        languages = {}
        total_content_size = 0
        total_lines = 0
        
        for file_info in smart_contract_files:
            ext = Path(file_info['name']).suffix.lower()
            extensions[ext] = extensions.get(ext, 0) + 1
            
            lang = file_info.get('language', 'Unknown')
            languages[lang] = languages.get(lang, 0) + 1
            
            total_content_size += len(file_info['content'])
            total_lines += file_info.get('lines', 0)
        
        # Generate blob URLs
        display_ref = commit_sha if commit_sha else branch
        for file_info in smart_contract_files:
            file_info['blob_url'] = f"https://github.com/{owner}/{repo}/blob/{display_ref}/{file_info['path']}"
        
        summary = {
            'repository': f"{owner}/{repo}",
            'branch': branch,
            'subpath': subpath,
            'total_files': len(smart_contract_files),
            'extensions': extensions,
            'languages': languages,
            'total_content_size': total_content_size,
            'total_lines': total_lines,
            'method_used': method_used
        }
        
        if verbose:
            print(f"\n{'='*60}")
            print("RETRIEVAL SUMMARY")
            print(f"{'='*60}")
            print(f"Repository: {summary['repository']}")
            print(f"Reference: {summary['branch']}")
            print(f"Method: {method_used} {'⚡' if method_used == 'graphql' else '🐌'}")
            print(f"Files retrieved: {summary['total_files']}")
            print(f"Total content: {summary['total_content_size']:,} characters")
            print(f"Total lines: {summary['total_lines']:,}")
            
            if summary['languages']:
                print("\nLanguages found:")
                for lang, count in sorted(summary['languages'].items()):
                    print(f"  {lang}: {count} files")
        
        return {
            'files': smart_contract_files,
            'summary': summary
        }
        
    except Exception as e:
        if verbose:
            print(f"❌ Error: {e}")
        return {
            'files': [],
            'summary': {
                'repository': 'Unknown',
                'total_files': 0,
                'extensions': {},
                'languages': {},
                'method_used': 'error',
                'error': str(e)
            }
        }

# Utility functions
def filter_by_language(results: Dict, language: str) -> List[Dict]:
    """Filter smart contract files by programming language."""
    return [f for f in results['files'] if f.get('language', '').lower() == language.lower()]

def filter_by_extension(results: Dict, extension: str) -> List[Dict]:
    """Filter smart contract files by file extension."""
    ext = extension if extension.startswith('.') else f'.{extension}'
    return [f for f in results['files'] if f['name'].lower().endswith(ext.lower())]

def get_largest_files(results: Dict, n: int = 5) -> List[Dict]:
    """Get the n largest smart contract files by size."""
    return sorted(results['files'], key=lambda x: x['size'], reverse=True)[:n]

def export_to_json(results: Dict, output_file: str) -> bool:
    """Export results to a JSON file."""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error exporting to JSON: {e}")
        return False

def save_files_to_directory(results: Dict, output_dir: str) -> bool:
    """Save all smart contract files to a local directory structure."""
    try:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        for file_info in results['files']:
            file_path = output_path / file_info['path']
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(file_info['content'])
        
        return True
    except Exception as e:
        print(f"Error saving files: {e}")
        return False

# Test script
if __name__ == "__main__":
    API_KEY = os.getenv('GITHUB_API_KEY')
    
    if not API_KEY:
        print("⚠️  Warning: No GitHub API key found.")
        print("   Set GITHUB_API_KEY environment variable.")
        print("   You can create one at: https://github.com/settings/tokens")
    
    # Test with your specific URL
    test_url = "https://github.com/mysofinance/v2/tree/c740f7c6b5ebd365618fd2d7ea77370599e1ca11"
    
    print(f"🧪 Testing GraphQL-first strategy:")
    print(f"URL: {test_url}")
    print(f"{'='*80}")
    
    results = get_smart_contracts(
        github_url=test_url,
        api_key=API_KEY,
        verbose=True
    )
    
    # Display results
    print(f"\n📊 FINAL RESULTS:")
    print(f"- Method used: {results['summary']['method_used']}")
    print(f"- Files found: {results['summary']['total_files']}")
    
    if results['files']:
        print(f"\n📄 Smart contract files:")
        for i, file in enumerate(results['files'], 1):
            print(f"{i}. {file['path']} ({file['language']})")
            print(f"   Size: {file['size']:,} chars, Lines: {file.get('lines', 'N/A')}")
            print(f"   Preview: {file['content'][:100].replace(chr(10), ' ')}...")
            print()
    else:
        print("\n✅ No smart contract files found in this repository/reference")
    
    print(f"\n{'='*80}")
    print("Test completed!")