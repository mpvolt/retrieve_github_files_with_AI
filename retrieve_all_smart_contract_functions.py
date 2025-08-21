#!/usr/bin/env python3
"""
Extracts function names from a smart contract file accessed via a GitHub blob URL.

This script processes files with extensions .sol, .vy, .rs, .move, .cairo, .fc, .func
using the GitHub API with an API key from the environment variable GITHUB_API_KEY.
It returns a list of function names found in the file.

Usage:
    from extract_function_names import extract_function_names
    
    function_names = extract_function_names("https://github.com/owner/repo/blob/main/contract.sol")
    print(function_names)
"""

import os
import re
import requests
from urllib.parse import urlparse, unquote
from typing import List, Optional
from pathlib import Path  # Added missing import
import time

# Supported smart contract file extensions
SMART_CONTRACT_EXTENSIONS = ('.sol', '.vy', '.rs', '.move', '.cairo', '.fc', '.func')

def parse_github_blob_url(blob_url: str) -> Optional[dict]:
    """
    Parse a GitHub blob URL to extract owner, repo, path, and commit/branch.
    
    Args:
        blob_url (str): GitHub blob URL (e.g., https://github.com/owner/repo/blob/main/contract.sol)
        
    Returns:
        Optional[dict]: Dictionary with owner, repo, path, and ref (commit/branch), or None if invalid
    """
    try:
        parsed = urlparse(blob_url)
        if 'github.com' not in parsed.netloc:
            print(f"Error: {blob_url} is not a valid GitHub URL")
            return None
        
        # Split the path: /owner/repo/blob/ref/path/to/file
        path_parts = parsed.path.lstrip('/').split('/')
        if len(path_parts) < 4 or path_parts[2] != 'blob':
            print(f"Error: Invalid GitHub blob URL format: {blob_url}")
            return None
        
        owner = path_parts[0]
        repo = path_parts[1]
        ref = path_parts[3]  # Commit hash or branch name
        file_path = '/'.join(path_parts[4:])  # Path to the file
        
        return {
            'owner': owner,
            'repo': repo,
            'path': unquote(file_path),
            'ref': ref
        }
    except Exception as e:
        print(f"Error parsing GitHub blob URL {blob_url}: {e}")
        return None

def fetch_file_content(owner: str, repo: str, path: str, ref: str, api_key: str) -> Optional[str]:
    """
    Fetch file content from GitHub API using the provided API key.
    
    Args:
        owner (str): Repository owner
        repo (str): Repository name
        path (str): Path to the file in the repository
        ref (str): Commit hash or branch name
        api_key (str): GitHub API key
        
    Returns:
        Optional[str]: File content, or None if fetch fails
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={ref}"
    headers = {
        'Authorization': f'token {api_key}',
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'FunctionName-Extractor/1.0'
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        content_data = response.json()
        if 'content' in content_data:
            # Decode base64 content
            import base64
            content = base64.b64decode(content_data['content']).decode('utf-8')
            return content
        else:
            print(f"Error: No content found for {path}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error fetching file from {url}: {e}")
        if hasattr(e.response, 'status_code'):
            if e.response.status_code == 404:
                print(f"File {path} not found in {owner}/{repo} at ref {ref}")
            elif e.response.status_code == 403 and 'rate limit' in e.response.text.lower():
                print("API rate limit exceeded")
                time.sleep(60)
                fetch_file_content(owner, repo, path, ref, api_key)
        return None

def extract_function_names(blob_url: str, api_key: Optional[str] = None) -> List[str]:
    """
    Extract function names from a smart contract file accessed via a GitHub blob URL.
    
    Args:
        blob_url (str): GitHub blob URL to the smart contract file
        api_key (Optional[str]): GitHub API key (defaults to GITHUB_API_KEY env variable)
        
    Returns:
        List[str]: List of function names found in the file
        
    Example:
        function_names = extract_function_names(
            "https://github.com/ethereum/solidity/blob/main/libsolidity/interface/Contract.sol",
            api_key="ghp_xxxxxxxxxxxx"
        )
        print(function_names)  # ['transfer', 'balanceOf', 'approve']
    """
    # Get API key from environment if not provided
    api_key = api_key or os.getenv('GITHUB_API_KEY')
    if not api_key:
        print("Error: GitHub API key not provided and GITHUB_API_KEY environment variable not set")
        print("Create one at: https://github.com/settings/tokens")
        return []
    
    # Parse the blob URL
    url_info = parse_github_blob_url(blob_url)
    if not url_info:
        return []
    
    # Check if file extension is supported
    if not url_info['path'].lower().endswith(SMART_CONTRACT_EXTENSIONS):
        print(f"Error: {url_info['path']} has unsupported extension. Supported: {SMART_CONTRACT_EXTENSIONS}")
        return []
    
    # Fetch file content
    content = fetch_file_content(
        owner=url_info['owner'],
        repo=url_info['repo'],
        path=url_info['path'],
        ref=url_info['ref'],
        api_key=api_key
    )
    if content is None:
        return []
    
    function_names = []
    extension = Path(url_info['path']).suffix.lower()
    
    if extension == '.sol':  # Solidity
        # Matches: function name(...), function name (...), or function name()
        pattern = r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*(?:public|private|internal|external)?'
        matches = re.findall(pattern, content)
        function_names.extend(matches)
    
    elif extension == '.vy':  # Vyper
        # Matches: @external def name(...): or def name(...):
        pattern = r'(?:@external\s+)?def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*:'
        matches = re.findall(pattern, content)
        function_names.extend(matches)
    
    elif extension == '.rs':  # Rust (used in Solana smart contracts)
        # Matches: fn name(...) or pub fn name(...)
        pattern = r'(?:pub\s+)?fn\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)'
        matches = re.findall(pattern, content)
        function_names.extend(matches)
    
    elif extension == '.move':  # Move (used in Aptos/Sui)
        # Matches: fun name(...) or public fun name(...)
        pattern = r'(?:public\s+)?fun\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)'
        matches = re.findall(pattern, content)
        function_names.extend(matches)
    
    elif extension == '.cairo':  # Cairo (used in StarkNet)
        # Matches: func name{...}(...): or func name(...)
        pattern = r'func\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\{[^}]*\})?\s*\([^)]*\)\s*:'
        matches = re.findall(pattern, content)
        function_names.extend(matches)
    
    elif extension in ('.fc', '.func'):  # FunC (used in TON blockchain)
        # Matches: () name(...) or name(...)
        pattern = r'(?:\([^\)]*\)\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)'
        matches = re.findall(pattern, content)
        function_names.extend(matches)
    
    # Remove duplicates while preserving order
    seen = set()
    function_names = [name for name in function_names if not (name in seen or seen.add(name))]
    
    return function_names


if __name__ == "__main__":
    blob_url = "https://github.com/PotLock/grantpicks/blob/69f785ed988d4aeefc4a041047bb5e4d200c6967/stellar/contract/lists/src/internal.rs"
    API_KEY = os.getenv('GITHUB_API_KEY')

    functions = extract_function_names(blob_url, API_KEY)
    
    if functions:
        print(f"Function names found in {blob_url}:")
        for func in functions:
            print(f"- {func}")
    else:
        print(f"No functions found in {blob_url}")