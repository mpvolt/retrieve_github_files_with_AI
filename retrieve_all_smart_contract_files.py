#!/usr/bin/env python3
"""
GitHub Smart Contract File Retriever

This script provides a function to fetch all smart contract files from a GitHub repository
using the GitHub API. It supports various smart contract file extensions
including Solidity, Vyper, Rust, Move, Cairo, and FunC.

Usage:
    from github_smart_contract_retriever import get_smart_contracts
    
    results = get_smart_contracts(
        github_url="https://github.com/ethereum/solidity",
        api_key="your_github_token_here",
        download_files=True,
        output_dir="./contracts"
    )
"""

import os
import json
import requests
from pathlib import Path
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Optional

# Smart contract file extensions
SMART_CONTRACT_EXTENSIONS = ('.sol', '.vy', '.rs', '.move', '.cairo', '.fc', '.func')

class GitHubSmartContractRetriever:
    def __init__(self, api_key: str):
        """Initialize the retriever with GitHub API key."""
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'token {api_key}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'SmartContract-Retriever/1.0'
        })
        
    def parse_github_url(self, url: str) -> Tuple[str, str]:
        """Parse GitHub URL to extract owner and repository name."""
        # Remove trailing slash and .git if present
        url = url.rstrip('/').replace('.git', '')
        
        # Handle different GitHub URL formats
        if 'github.com' in url:
            # Extract from https://github.com/owner/repo or git@github.com:owner/repo
            if url.startswith('git@'):
                # SSH format: git@github.com:owner/repo
                path = url.split(':')[1]
            else:
                # HTTPS format: https://github.com/owner/repo
                parsed = urlparse(url)
                path = parsed.path.lstrip('/')
            
            parts = path.split('/')
            if len(parts) >= 2:
                return parts[0], parts[1]
        
        raise ValueError(f"Invalid GitHub URL format: {url}")
    
    def get_repository_contents(self, owner: str, repo: str, path: str = "") -> List[Dict]:
        """Get repository contents from GitHub API."""
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching repository contents: {e}")
            if hasattr(e.response, 'status_code'):
                if e.response.status_code == 404:
                    print(f"Repository {owner}/{repo} not found or path '{path}' doesn't exist")
                elif e.response.status_code == 403:
                    print("API rate limit exceeded or insufficient permissions")
            return []
    
    def is_smart_contract_file(self, filename: str) -> bool:
        """Check if file has a smart contract extension."""
        return filename.lower().endswith(SMART_CONTRACT_EXTENSIONS)
    
    def get_file_content(self, download_url: str) -> Optional[str]:
        """Download file content from GitHub."""
        try:
            response = self.session.get(download_url)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            print(f"Error downloading file from {download_url}: {e}")
            return None
    
    def scan_repository_recursive(self, owner: str, repo: str, path: str = "", verbose: bool = True) -> List[Dict]:
        """Recursively scan repository for smart contract files, ignoring node_modules."""
        smart_contract_files = []
        contents = self.get_repository_contents(owner, repo, path)
        
        for item in contents:
            if item['type'] == 'file':
                if self.is_smart_contract_file(item['name']):
                    smart_contract_files.append({
                        'name': item['name'],
                        'path': item['path'],
                        'download_url': item['download_url'],
                        'size': item['size'],
                        'sha': item['sha']
                    })
                    if verbose:
                        print(f"Found smart contract: {item['path']}")
            elif item['type'] == 'dir':
                # Skip node_modules directory
                if item['name'] == 'node_modules':
                    if verbose:
                        print(f"Skipping node_modules directory: {item['path']}")
                    continue
                # Recursively scan other subdirectories
                if verbose:
                    print(f"Scanning directory: {item['path']}")
                subdirectory_files = self.scan_repository_recursive(owner, repo, item['path'], verbose)
                smart_contract_files.extend(subdirectory_files)
        
        return smart_contract_files
    
    def save_file(self, file_info: Dict, content: str, output_dir: Path, verbose: bool = True):
        """Save file content to local directory maintaining directory structure."""
        file_path = output_dir / file_info['path']
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            if verbose:
                print(f"Saved: {file_path}")
        except Exception as e:
            print(f"Error saving file {file_path}: {e}")


def get_smart_contracts(github_url: str, 
                       api_key: str, 
                       verbose: bool = True) -> Dict:
    """
    Retrieve all smart contract files and their content from a GitHub repository.
    
    Args:
        github_url (str): GitHub repository URL (HTTPS or SSH format)
        api_key (str): GitHub API token/personal access token
        verbose (bool): Whether to print progress messages
    
    Returns:
        Dict: Contains 'files' list with file content and 'summary' with statistics
        
    Example:
        results = get_smart_contracts(
            github_url="https://github.com/ethereum/solidity",
            api_key="ghp_xxxxxxxxxxxx"
        )
        
        print(f"Found {results['summary']['total_files']} smart contract files")
        for file_info in results['files']:
            print(f"- {file_info['path']}: {len(file_info['content'])} characters")
            print(f"  First 100 chars: {file_info['content'][:100]}...")
    """
    
    retriever = GitHubSmartContractRetriever(api_key)
    
    try:
        owner, repo = retriever.parse_github_url(github_url)
        if verbose:
            print(f"Scanning repository: {owner}/{repo}")
        
        # Find all smart contract files
        smart_contract_files = retriever.scan_repository_recursive(owner, repo, verbose=verbose)
        
        if not smart_contract_files:
            if verbose:
                print("No smart contract files found in the repository.")
            return {'files': [], 'summary': {'repository': f"{owner}/{repo}", 'total_files': 0, 'extensions': {}}}
        
        if verbose:
            print(f"\nFound {len(smart_contract_files)} smart contract files")
            print("Downloading file contents...")
        
        # Download content for each file
        files_with_content = []
        for file_info in smart_contract_files:
            if verbose:
                print(f"Downloading: {file_info['path']}")
            
            content = retriever.get_file_content(file_info['download_url'])
            if content is not None:
                files_with_content.append({
                    'name': file_info['name'],
                    'path': file_info['path'],
                    'content': content,
                    'size': file_info['size'],
                    'sha': file_info['sha']
                })
            else:
                if verbose:
                    print(f"Failed to download: {file_info['path']}")
        
        # Generate summary
        extensions = {}
        total_content_size = 0
        for file_info in files_with_content:
            ext = Path(file_info['name']).suffix.lower()
            extensions[ext] = extensions.get(ext, 0) + 1
            total_content_size += len(file_info['content'])
        
        summary = {
            'repository': f"{owner}/{repo}",
            'total_files': len(files_with_content),
            'extensions': extensions,
            'total_content_size': total_content_size,
            'failed_downloads': len(smart_contract_files) - len(files_with_content)
        }
        
        if verbose:
            print(f"\n{'='*50}")
            print("SUMMARY")
            print(f"{'='*50}")
            print(f"Repository: {summary['repository']}")
            print(f"Successfully downloaded: {summary['total_files']} smart contract files")
            print(f"Total content size: {summary['total_content_size']:,} characters")
            
            if summary['failed_downloads'] > 0:
                print(f"Failed downloads: {summary['failed_downloads']}")
            
            if summary['extensions']:
                print("\nFiles by extension:")
                for ext, count in sorted(summary['extensions'].items()):
                    print(f"  {ext}: {count} files")
        
        return {
            'files': files_with_content,
            'summary': summary
        }
        
    except Exception as e:
        if verbose:
            print(f"Error retrieving smart contracts: {e}")
        return {
            'files': [], 
            'summary': {
                'repository': 'Unknown',
                'total_files': 0, 
                'extensions': {},
                'error': str(e)
            }
        }


# Example usage and testing
if __name__ == "__main__":
    # Example usage - replace with your actual GitHub token
    API_KEY = os.getenv('GITHUB_API_KEY')
    
    if not API_KEY:
        print("Please set your GitHub API token in the API_KEY variable")
        print("Create one at: https://github.com/settings/tokens")
    else:
        # Example: Get all smart contract files with their content
        results = get_smart_contracts(
            github_url="https://github.com/get-smooth/crypto-lib/tree/f40942c2bdff620d9fb1935054c8d0b21e6f17b1",
            api_key=API_KEY
        )
        
        # Access results
        for file in results['files']:  # Show first 3 files
            print(f"\n- {file['path']} ({len(file['content'])} characters)")
            print(f"  Content preview: {file['content'][:100]}...")
        
        # You can now access the full content of each file
        # for file in results['files']:
        #     if file['name'].endswith('.sol'):
        #         print(f"\nSolidity file: {file['path']}")
        #         print(file['content'])  # Full file content