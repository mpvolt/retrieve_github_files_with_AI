#!/usr/bin/env python3
"""
Enhanced GitHub Smart Contract File Retriever

This script provides a function to fetch all smart contract files from a GitHub repository
using git clone (primary method) with GitHub API as fallback. It supports various smart 
contract file extensions and handles GitHub tree URLs correctly.

Key improvements:
- Better GitHub URL parsing for tree URLs and commits
- Enhanced file validation and path checking
- More robust smart contract file detection
- Improved error handling and validation

Usage:
    from github_smart_contract_retriever import get_smart_contracts
    
    results = get_smart_contracts(
        github_url="https://github.com/ethereum/solidity/tree/develop",
        api_key="your_github_token_here"  # Optional, only needed for API fallback
    )
"""

import os
import json
import requests
import subprocess
import tempfile
import shutil
import time
import re
from pathlib import Path
from urllib.parse import urlparse, unquote
from typing import List, Dict, Tuple, Optional, Set

# Enhanced smart contract file extensions with descriptions
SMART_CONTRACT_EXTENSIONS = {
    '.sol': 'Solidity',
    '.vy': 'Vyper', 
    '.fe': 'Fe',
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
    '.py': 'Python (Algorand PyTeal)',  # Only if contains PyTeal patterns
}

# Directories to skip during scanning
SKIP_DIRECTORIES = {
    'node_modules', '.git', '__pycache__', '.vscode', '.idea', 
    'build', 'dist', 'target', 'out', 'artifacts', 'cache',
    '.pytest_cache', '.coverage', 'coverage', 'docs', 'test_data'
}

class GitHubSmartContractRetriever:
    def __init__(self, api_key: Optional[str] = None):
        """Initialize the retriever with optional GitHub API key."""
        self.api_key = api_key
        if api_key:
            self.session = requests.Session()
            self.session.headers.update({
                'Authorization': f'token {api_key}',
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'SmartContract-Retriever/2.0'
            })
        else:
            self.session = None
        
    def parse_github_url(self, url: str) -> Tuple[str, str, str, str, Optional[str]]:
        """
        Parse GitHub URL to extract owner, repository name, branch/commit, clone URL, and subpath.
        
        Handles various URL formats:
        - https://github.com/owner/repo
        - https://github.com/owner/repo/tree/branch
        - https://github.com/owner/repo/tree/branch/subpath
        - https://github.com/owner/repo/commit/hash
        - git@github.com:owner/repo.git
        
        Returns:
            Tuple[owner, repo, branch_or_commit, clone_url, subpath]
        """
        # Clean up URL
        url = url.rstrip('/').replace('.git', '')
        
        # Default values
        branch = 'main'
        subpath = None
        
        if 'github.com' not in url:
            raise ValueError(f"Invalid GitHub URL format: {url}")
        
        if url.startswith('git@'):
            # SSH format: git@github.com:owner/repo
            path = url.split(':')[1]
            clone_url = url + '.git'
            parts = path.split('/')
            if len(parts) >= 2:
                return parts[0], parts[1], branch, clone_url, subpath
        else:
            # HTTPS format
            parsed = urlparse(url)
            path = parsed.path.lstrip('/')
            
            # Split path into components
            path_parts = path.split('/')
            if len(path_parts) < 2:
                raise ValueError(f"Invalid GitHub URL format: {url}")
            
            owner = path_parts[0]
            repo = path_parts[1]
            
            # Handle tree URLs: /tree/branch/optional/subpath
            if len(path_parts) > 2 and path_parts[2] == 'tree':
                if len(path_parts) > 3:
                    branch = unquote(path_parts[3])
                    # Check if there's a subpath after the branch
                    if len(path_parts) > 4:
                        subpath = '/'.join(path_parts[4:])
            
            # Handle commit URLs: /commit/hash
            elif len(path_parts) > 2 and path_parts[2] == 'commit':
                if len(path_parts) > 3:
                    branch = path_parts[3]  # This is actually a commit hash
            
            # Handle blob URLs: /blob/branch/filepath
            elif len(path_parts) > 2 and path_parts[2] == 'blob':
                if len(path_parts) > 3:
                    branch = unquote(path_parts[3])
                    if len(path_parts) > 4:
                        # This is pointing to a specific file, get its directory
                        file_path = '/'.join(path_parts[4:])
                        subpath = str(Path(file_path).parent) if Path(file_path).parent != Path('.') else None
            
            # Create clone URL
            clone_url = f"https://github.com/{owner}/{repo}.git"
            
            return owner, repo, branch, clone_url, subpath
        
        raise ValueError(f"Could not parse GitHub URL: {url}")
    
    def is_valid_file_path(self, file_path: Path) -> bool:
        """
        Validate that the file path is safe and readable.
        
        Args:
            file_path: Path to validate
            
        Returns:
            bool: True if path is valid and safe
        """
        try:
            # Check if file exists and is actually a file
            if not file_path.exists() or not file_path.is_file():
                return False
            
            # Check for path traversal attempts
            resolved_path = file_path.resolve()
            if '..' in str(resolved_path) or str(resolved_path).startswith('/'):
                return False
            
            # Check file size (avoid very large files that might not be source code)
            try:
                size = file_path.stat().st_size
                # Skip files larger than 10MB (likely not source code)
                if size > 10 * 1024 * 1024:
                    return False
            except OSError:
                return False
            
            # Check if file is readable
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    # Try to read first few bytes to ensure it's readable
                    f.read(100)
                return True
            except (OSError, PermissionError, UnicodeError):
                return False
                
        except Exception:
            return False
    
    def is_smart_contract_file(self, filename: str, content: str = None) -> Tuple[bool, str]:
        """
        Enhanced smart contract file detection.
        
        Args:
            filename: Name of the file
            content: Optional file content for additional validation
            
        Returns:
            Tuple[is_smart_contract, language]: Whether it's a smart contract and the language
        """
        filename_lower = filename.lower()
        
        # Check extension first
        for ext, language in SMART_CONTRACT_EXTENSIONS.items():
            if filename_lower.endswith(ext.lower()):
                # Special case for Python files - check for PyTeal patterns
                if ext == '.py' and content:
                    pyteal_patterns = [
                        'pyteal', 'Txn.', 'Global.', 'App.', 'Gtxn.',
                        'InnerTxnBuilder', 'Approve()', 'Reject()',
                        'algosdk', 'application_id'
                    ]
                    if not any(pattern in content for pattern in pyteal_patterns):
                        return False, ''
                
                # Special case for Rust files - check for blockchain patterns  
                elif ext == '.rs' and content:
                    rust_blockchain_patterns = [
                        'solana_program', 'anchor_lang', 'near_sdk',
                        '#[program]', '#[derive(Accounts)]', 'ProgramResult',
                        'AccountInfo', 'Pubkey', 'msg!', 'require!'
                    ]
                    if not any(pattern in content for pattern in rust_blockchain_patterns):
                        return False, ''
                
                return True, language
        
        # Check for common smart contract patterns in filename
        smart_contract_indicators = [
            'contract', 'token', 'erc20', 'erc721', 'erc1155',
            'nft', 'defi', 'swap', 'pool', 'vault', 'factory',
            'proxy', 'governance', 'staking', 'bridge'
        ]
        
        if any(indicator in filename_lower for indicator in smart_contract_indicators):
            # If filename suggests it's a smart contract but extension doesn't match,
            # check content for smart contract patterns
            if content:
                content_lower = content.lower()
                if any(pattern in content_lower for pattern in [
                    'pragma solidity', 'contract ', 'function ', 'modifier ',
                    '@version', 'def ', '__init__', 'storage:', 'event ',
                    'struct ', 'mapping', 'require(', 'assert(', 'revert('
                ]):
                    return True, 'Unknown'
        
        return False, ''
    
    def should_skip_directory(self, dir_name: str) -> bool:
        """Check if directory should be skipped during scanning."""
        return dir_name.lower() in {d.lower() for d in SKIP_DIRECTORIES}
    
    def check_commit_exists(self, owner: str, repo: str, commit_sha: str) -> bool:
        """Check if a commit exists in the repository using GitHub API."""
        if not self.session:
            return False
        
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_sha}"
            response = self.session.get(url, timeout=30)
            return response.status_code == 200
        except Exception:
            return False
    
    def is_orphaned_commit(self, clone_url: str, branch: str, verbose: bool = True) -> bool:
        """
        Check if a commit is orphaned (doesn't belong to any branch).
        This happens when the commit exists but isn't reachable from any branch.
        """
        if len(branch) != 40 or not all(c in '0123456789abcdef' for c in branch.lower()):
            return False  # Not a commit hash
        
        try:
            # Try a shallow clone with the specific commit
            temp_check_dir = Path(tempfile.mkdtemp(prefix="commit_check_"))
            
            try:
                # First try to clone just the commit
                cmd = ['git', 'clone', '--depth', '1', clone_url, str(temp_check_dir)]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0:
                    # Try to checkout the specific commit
                    checkout_cmd = ['git', 'checkout', branch]
                    checkout_result = subprocess.run(
                        checkout_cmd, cwd=temp_check_dir, capture_output=True, text=True, timeout=30
                    )
                    
                    if checkout_result.returncode != 0:
                        # Commit exists but can't be checked out - likely orphaned
                        if verbose:
                            print(f"Commit {branch} appears to be orphaned (not reachable from any branch)")
                        return True
                
                return False
                
            finally:
                if temp_check_dir.exists():
                    shutil.rmtree(temp_check_dir)
                    
        except Exception as e:
            if verbose:
                print(f"Error checking if commit is orphaned: {e}")
            return True  # Assume orphaned if we can't check
    
    def clone_repository(self, clone_url: str, branch: str, temp_dir: Path, verbose: bool = True) -> Tuple[bool, bool]:
        """
        Clone repository to temporary directory with enhanced error handling.
        
        Returns:
            Tuple[success, is_orphaned]: Whether clone succeeded and if commit is orphaned
        """
        try:
            if verbose:
                print(f"Cloning repository: {clone_url} (branch/ref: {branch})")
            
            # Check if this looks like a commit hash and might be orphaned
            is_commit_hash = len(branch) == 40 and all(c in '0123456789abcdef' for c in branch.lower())
            
            # First try to clone the specific branch/commit
            cmd = ['git', 'clone', '--depth', '1', '--branch', branch, clone_url, str(temp_dir)]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                if verbose:
                    print(f"Successfully cloned branch/ref '{branch}'")
                return True, False
            else:
                # If it's a commit hash, check if it might be orphaned
                if is_commit_hash:
                    if verbose:
                        print(f"Failed to clone commit '{branch}' directly - checking if orphaned...")
                    
                    # Check if commit is orphaned using a quick test
                    if self.is_orphaned_commit(clone_url, branch, verbose):
                        if verbose:
                            print("Commit appears to be orphaned - will use GitHub API instead")
                        return False, True
                
                # If specific branch fails, try default branch
                if verbose:
                    print(f"Failed to clone branch/ref '{branch}', trying default branch...")
                
                # Remove the failed clone attempt
                if temp_dir.exists():
                    shutil.rmtree(temp_dir)
                
                # Try without specifying branch
                cmd = ['git', 'clone', '--depth', '1', clone_url, str(temp_dir)]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    if verbose:
                        print("Successfully cloned default branch")
                    
                    # If original request was for a specific commit, try to checkout that commit
                    if is_commit_hash:
                        try:
                            # Try to fetch the specific commit first
                            fetch_cmd = ['git', 'fetch', 'origin', branch]
                            fetch_result = subprocess.run(
                                fetch_cmd, cwd=temp_dir, capture_output=True, text=True, timeout=60
                            )
                            
                            if fetch_result.returncode == 0:
                                checkout_cmd = ['git', 'checkout', branch]
                                checkout_result = subprocess.run(
                                    checkout_cmd, cwd=temp_dir, capture_output=True, text=True, timeout=60
                                )
                                if checkout_result.returncode == 0:
                                    if verbose:
                                        print(f"Successfully checked out commit {branch}")
                                    return True, False
                                else:
                                    if verbose:
                                        print(f"Could not checkout commit {branch} - likely orphaned")
                                    return False, True
                            else:
                                if verbose:
                                    print(f"Could not fetch commit {branch} - likely orphaned")
                                return False, True
                                
                        except Exception as e:
                            if verbose:
                                print(f"Error trying to checkout commit {branch}: {e}")
                            return False, True
                    
                    return True, False
                else:
                    if verbose:
                        print(f"Git clone failed: {result.stderr}")
                    return False, False
                    
        except subprocess.TimeoutExpired:
            if verbose:
                print("Git clone timed out (5 minutes)")
            return False, False
        except FileNotFoundError:
            if verbose:
                print("Git command not found. Please install git.")
            return False, False
        except Exception as e:
            if verbose:
                print(f"Error during git clone: {e}")
            return False, False
    
    def scan_local_repository(self, repo_path: Path, owner: str, repo: str, branch: str, 
                            subpath: Optional[str] = None, verbose: bool = True) -> List[Dict]:
        """
        Scan local repository for smart contract files with enhanced validation.
        
        Args:
            repo_path: Path to the cloned repository
            owner: Repository owner
            repo: Repository name
            branch: Branch or commit
            subpath: Optional subpath to scan within the repository
            verbose: Whether to print progress messages
            
        Returns:
            List of dictionaries containing file information
        """        
        
        smart_contract_files = []
        
        # Determine scan root
        scan_root = repo_path
        if subpath:
            potential_subpath = repo_path / subpath
            if potential_subpath.exists() and potential_subpath.is_dir():
                scan_root = potential_subpath
                if verbose:
                    print(f"Scanning subpath: {subpath}")
            else:
                if verbose:
                    print(f"Warning: Subpath '{subpath}' not found, scanning entire repository")
        
        # Walk through all files in the scan root
        for file_path in scan_root.rglob('*'):
            # Skip if it's a directory
            if not file_path.is_file():
                continue
            
            # Skip directories we don't want to scan
            if any(part in SKIP_DIRECTORIES for part in file_path.parts):
                continue
            
            # Check if file has a smart contract extension
            file_extension = file_path.suffix.lower()
            if file_extension not in SMART_CONTRACT_EXTENSIONS:
                continue
            
            # Validate file path
            if not self.is_valid_file_path(file_path):
                if verbose:
                    print(f"Skipping invalid/unreadable file: {file_path}")
                continue
            
            # Get relative path from repository root (not scan root)
            try:
                relative_path = file_path.relative_to(repo_path)
            except ValueError:
                if verbose:
                    print(f"Error: Could not determine relative path for {file_path}")
                continue
            
            # Read file content
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e:
                if verbose:
                    print(f"Error reading file {file_path}: {e}")
                continue
            
            # Get language from extension
            language = SMART_CONTRACT_EXTENSIONS[file_extension]
            
            # Special handling for Python files - check for PyTeal patterns
            if file_extension == '.py':
                # Check if it's actually a PyTeal file
                pyteal_patterns = ['pyteal', 'PyTeal', 'algosdk', 'ApplicationCallTxn', 'Txn.application_id']
                if not any(pattern in content for pattern in pyteal_patterns):
                    if verbose:
                        print(f"Skipping Python file without PyTeal patterns: {relative_path}")
                    continue
            
            # Additional validation: ensure content is not empty and seems valid
            content_stripped = content.strip()
            if len(content_stripped) < 10:  # Skip very short files
                if verbose:
                    print(f"Skipping very short file: {relative_path}")
                continue
            
            # Check for binary content (simplified check)
            if '\x00' in content[:1000]:  # Check first 1000 chars for null bytes
                if verbose:
                    print(f"Skipping binary file: {relative_path}")
                continue
            
            blob_url = self.create_blob_url(owner, repo, branch, str(relative_path))
            
            smart_contract_files.append({
                'name': file_path.name,
                'path': str(relative_path),
                'content': content,
                'blob_url': blob_url,
                'size': len(content),
                'language': language,
                'local_path': str(file_path),
                'lines': len(content.splitlines()),
                'is_valid': True
            })
            
            if verbose:
                print(f"Found {language} contract: {relative_path} ({len(content)} chars)")
        
        return smart_contract_files
    
    def create_blob_url(self, owner: str, repo: str, branch: str, file_path: str) -> str:
        """Create GitHub blob URL for a file."""
        return f"https://github.com/{owner}/{repo}/blob/{branch}/{file_path}"
    
    # API methods remain largely the same but with enhanced validation
    def get_repository_contents(self, owner: str, repo: str, path: str = "", ref: str = None) -> List[Dict]:
        """Get repository contents from GitHub API with rate limiting protection."""
        if not self.session:
            return []
        
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        params = {}
        if ref:
            params['ref'] = ref
        
        max_retries = 5
        for attempt in range(max_retries):
            try:
                response = self.session.get(url, params=params, timeout=30)
                
                # Check for rate limiting
                if response.status_code == 403 and 'rate limit' in response.text.lower():
                    rate_limit_remaining = response.headers.get('X-RateLimit-Remaining', '0')
                    if rate_limit_remaining == '0':
                        print(f"Rate limit exceeded. Waiting 60 seconds (attempt {attempt + 1}/{max_retries})...")
                        if attempt < max_retries - 1:
                            time.sleep(60)
                            continue
                        else:
                            print("Max retries reached for get_repository_contents.")
                            break
                
                response.raise_for_status()
                return response.json()
                
            except requests.exceptions.RequestException as e:
                if "rate limit" in str(e).lower():
                    print(f"Rate limit error. Waiting 60 seconds (attempt {attempt + 1}/{max_retries})...")
                    if attempt < max_retries - 1:
                        time.sleep(60)
                        continue
                    else:
                        print("Max retries reached for get_repository_contents.")
                        break
                else:
                    print(f"Error fetching repository contents: {e}")
                    if hasattr(e, 'response') and e.response:
                        if e.response.status_code == 404:
                            print(f"Repository {owner}/{repo} not found or path '{path}' doesn't exist")
                        elif e.response.status_code == 403:
                            print("API rate limit exceeded or insufficient permissions")
                    break
        
        return []
    
    def get_file_content(self, download_url: str) -> Optional[str]:
        """Download file content from GitHub with rate limiting protection and validation."""
        if not self.session:
            return None
        
        max_retries = 5
        for attempt in range(max_retries):
            try:
                response = self.session.get(download_url, timeout=30)
                
                # Check for rate limiting
                if response.status_code == 403 and 'rate limit' in response.text.lower():
                    rate_limit_remaining = response.headers.get('X-RateLimit-Remaining', '0')
                    if rate_limit_remaining == '0':
                        print(f"Rate limit exceeded downloading file. Waiting 60 seconds (attempt {attempt + 1}/{max_retries})...")
                        if attempt < max_retries - 1:
                            time.sleep(60)
                            continue
                        else:
                            print("Max retries reached for file download.")
                            return None
                
                response.raise_for_status()
                
                # Validate content
                content = response.text
                if len(content.strip()) < 10:  # Skip very short files
                    return None
                
                # Check for binary content
                if '\x00' in content[:1000]:
                    return None
                    
                return content
                
            except requests.exceptions.RequestException as e:
                if "rate limit" in str(e).lower():
                    print(f"Rate limit error downloading file. Waiting 60 seconds (attempt {attempt + 1}/{max_retries})...")
                    if attempt < max_retries - 1:
                        time.sleep(60)
                        continue
                    else:
                        print("Max retries reached for file download.")
                        return None
                else:
                    print(f"Error downloading file from {download_url}: {e}")
                    return None
        
        return None
    
    def scan_repository_recursive(self, owner: str, repo: str, branch: str, 
                                path: str = "", verbose: bool = True) -> List[Dict]:
        """Recursively scan repository using API with enhanced validation."""
        if not self.session:
            return []
        
        smart_contract_files = []
        contents = self.get_repository_contents(owner, repo, path, ref=branch)
        
        for item in contents:
            if item['type'] == 'file':
                # Enhanced smart contract detection
                is_contract, language = self.is_smart_contract_file(item['name'])
                
                if is_contract:
                    blob_url = self.create_blob_url(owner, repo, branch, item['path'])
                    
                    # Skip very large files (likely not source code)
                    if item['size'] > 10 * 1024 * 1024:  # 10MB
                        if verbose:
                            print(f"Skipping large file: {item['path']} ({item['size']} bytes)")
                        continue
                    
                    smart_contract_files.append({
                        'name': item['name'],
                        'path': item['path'],
                        'download_url': item['download_url'],
                        'blob_url': blob_url,
                        'size': item['size'],
                        'sha': item['sha'],
                        'language': language
                    })
                    
            elif item['type'] == 'dir':
                # Skip directories we don't want to scan
                if self.should_skip_directory(item['name']):
                    continue
                    
                #if verbose:
                    #print(f"Scanning directory: {item['path']}")
                
                subdirectory_files = self.scan_repository_recursive(
                    owner, repo, branch, item['path'], verbose
                )
                smart_contract_files.extend(subdirectory_files)
        
        return smart_contract_files

def get_smart_contracts(github_url: str, 
                       api_key: Optional[str] = None, 
                       verbose: bool = True) -> Dict:
    """
    Enhanced function to retrieve all smart contract files from a GitHub repository.
    
    Improvements:
    - Better URL parsing for tree URLs and commits
    - Enhanced file validation and path checking
    - More robust smart contract detection
    - Support for subpath scanning
    
    Args:
        github_url (str): GitHub repository URL (supports tree URLs, commits, etc.)
        api_key (str, optional): GitHub API token (only needed for API fallback)
        verbose (bool): Whether to print progress messages
    
    Returns:
        Dict: Contains 'files' list with file content and 'summary' with statistics
        
    Examples:
        # Basic repository
        results = get_smart_contracts("https://github.com/ethereum/solidity")
        
        # Specific branch
        results = get_smart_contracts("https://github.com/ethereum/solidity/tree/develop")
        
        # Specific commit
        results = get_smart_contracts("https://github.com/owner/repo/commit/abc123def456")
        
        # Specific subdirectory
        results = get_smart_contracts("https://github.com/owner/repo/tree/main/contracts")
    """
    
    retriever = GitHubSmartContractRetriever(api_key)
    
    try:
        owner, repo, branch, clone_url, subpath = retriever.parse_github_url(github_url)
        
        if verbose:
            print(f"Repository: {owner}/{repo}")
            print(f"Branch/Commit: {branch}")
            if subpath:
                print(f"Subpath: {subpath}")
        
        # Method 1: Try git clone first (but check for orphaned commits)
        temp_dir = None
        smart_contract_files = []
        method_used = "unknown"
        force_api = False
        
        # Pre-check: If this looks like a commit hash, verify it exists and isn't orphaned
        is_commit_hash = len(branch) == 40 and all(c in '0123456789abcdef' for c in branch.lower())
        if is_commit_hash and api_key:
            if verbose:
                print("Detected commit hash - checking if it exists and is accessible...")
            
            if not retriever.check_commit_exists(owner, repo, branch):
                if verbose:
                    print(f"Commit {branch} not found in repository - using API method")
                force_api = True
        
        if not force_api:
            try:
                temp_dir = Path(tempfile.mkdtemp(prefix=f"{repo}_"))
                
                clone_success, is_orphaned = retriever.clone_repository(clone_url, branch, temp_dir, verbose)
                
                if clone_success:
                    if verbose:
                        print("Using git clone method...")
                    smart_contract_files = retriever.scan_local_repository(
                        temp_dir, owner, repo, branch, subpath, verbose
                    )
                    method_used = "git_clone"
                elif is_orphaned:
                    if verbose:
                        print("Commit is orphaned - switching to GitHub API method")
                    force_api = True
                    # Clean up failed clone
                    if temp_dir and temp_dir.exists():
                        shutil.rmtree(temp_dir)
                        temp_dir = None
                else:
                    raise Exception("Git clone failed")
                    
            except Exception as e:
                if verbose:
                    print(f"Git clone method failed: {e}")
                    print("Falling back to GitHub API...")
                force_api = True
        
        # Method 2: Use GitHub API (either as fallback or forced due to orphaned commit)
        if force_api or not smart_contract_files:
            if api_key:
                if verbose:
                    if force_api:
                        print("Using GitHub API method (forced due to orphaned commit)...")
                    else:
                        print("Using GitHub API method (fallback)...")
                
                api_path = subpath if subpath else ""
                smart_contract_files = retriever.scan_repository_recursive(
                    owner, repo, branch, path=api_path, verbose=verbose
                )
                method_used = "github_api" + ("_forced" if force_api else "_fallback")
                
                # Download content for each file using API
                if smart_contract_files:
                    if verbose:
                        print(f"Found {len(smart_contract_files)} smart contract files. Downloading content...")
                    
                    files_with_content = []
                    for i, file_info in enumerate(smart_contract_files):
                        #if verbose:
                        #    print(f"Downloading ({i+1}/{len(smart_contract_files)}): {file_info['path']}")
                        
                        content = retriever.get_file_content(file_info['download_url'])
                        if content is not None:
                            # Re-validate with content
                            is_contract, language = retriever.is_smart_contract_file(
                                file_info['name'], content
                            )
                            
                            if is_contract:
                                file_info['content'] = content
                                file_info['language'] = language
                                file_info['lines'] = len(content.splitlines())
                                file_info['is_valid'] = True
                                files_with_content.append(file_info)
                            #elif verbose:
                                #print(f"File validation failed for: {file_info['path']}")
                        else:
                            if verbose:
                                print(f"Failed to download: {file_info['path']}")
                    
                    smart_contract_files = files_with_content
            else:
                if verbose:
                    if force_api:
                        print("Orphaned commit detected but no GitHub API key provided")
                        print("Cannot access orphaned commits without API key")
                    else:
                        print("No GitHub API key provided for fallback method")
                
                error_msg = ("Orphaned commit detected but no API key provided" if force_api 
                           else "Git clone failed and no API key provided for fallback")
                
                # Clean up temp directory before returning error
                if temp_dir and temp_dir.exists():
                    try:
                        shutil.rmtree(temp_dir)
                    except Exception as e:
                        if verbose:
                            print(f"Warning: Could not clean up temp directory {temp_dir}: {e}")
                
                return {
                    'files': [], 
                    'summary': {
                        'repository': f"{owner}/{repo}",
                        'branch': branch,
                        'subpath': subpath,
                        'total_files': 0, 
                        'extensions': {},
                        'languages': {},
                        'method_used': 'none',
                        'is_orphaned_commit': force_api,
                        'error': error_msg
                    }
                }
        
        # Clean up temporary directory (moved outside the conditional blocks)
        if temp_dir and temp_dir.exists():
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                if verbose:
                    print(f"Warning: Could not clean up temp directory {temp_dir}: {e}")
        
        if not smart_contract_files:
            if verbose:
                print("No smart contract files found in the repository.")
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
        
        # Generate enhanced summary
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
        
        summary = {
            'repository': f"{owner}/{repo}",
            'branch': branch,
            'subpath': subpath,
            'total_files': len(smart_contract_files),
            'extensions': extensions,
            'languages': languages,
            'total_content_size': total_content_size,
            'total_lines': total_lines,
            'method_used': method_used,
            'is_orphaned_commit': force_api if 'force_api' in locals() else False
        }
        
        if verbose:
            print(f"\n{'='*60}")
            print("ENHANCED SUMMARY")
            print(f"{'='*60}")
            print(f"Repository: {summary['repository']}")
            print(f"Branch/Commit: {summary['branch']}")
            if summary['subpath']:
                print(f"Subpath: {summary['subpath']}")
            print(f"Method used: {summary['method_used']}")
            if summary.get('is_orphaned_commit'):
                print("Note: Orphaned commit detected - used GitHub API")
            print(f"Successfully retrieved: {summary['total_files']} smart contract files")
            print(f"Total content size: {summary['total_content_size']:,} characters")
            print(f"Total lines of code: {summary['total_lines']:,}")
            
            if summary['languages']:
                print("\nFiles by language:")
                for lang, count in sorted(summary['languages'].items()):
                    print(f"  {lang}: {count} files")
            
            if summary['extensions']:
                print("\nFiles by extension:")
                for ext, count in sorted(summary['extensions'].items()):
                    print(f"  {ext}: {count} files")
        
        return {
            'files': smart_contract_files,
            'summary': summary
        }
        
    except Exception as e:
        if verbose:
            print(f"Error retrieving smart contracts: {e}")
        return {
            'files': [], 
            'summary': {
                'repository': 'Unknown',
                'branch': 'Unknown',
                'subpath': None,
                'total_files': 0, 
                'extensions': {},
                'languages': {},
                'method_used': 'none',
                'error': str(e)
            }
        }


# Example usage and testing
if __name__ == "__main__":
    # Example usage with enhanced features
    API_KEY = os.getenv('GITHUB_API_KEY')
    
    # Test cases demonstrating enhanced functionality
    test_cases = [
        # Basic repository
        "https://github.com/ethereum/solidity",
        
        # Specific branch
        "https://github.com/ethereum/solidity/tree/develop",
        
        # Specific commit
        "https://github.com/hyperlane-xyz/hyperlane-monorepo/commit/def40316e9e0fee6857ece40d60a6ddcf2247e90",
        
        # Repository with subdirectory
        "https://github.com/OpenZeppelin/openzeppelin-contracts/tree/master/contracts",
        
        # Different blockchain projects
        "https://github.com/solana-labs/solana-program-library/tree/master/token/program",
    ]
    
    # Test the specific orphaned commit case
    orphaned_commit_url = "https://github.com/hyperlane-xyz/hyperlane-monorepo/tree/def40316e9e0fee6857ece40d60a6ddcf2247e90"
    
    print(f"\n{'='*80}")
    print(f"TESTING ORPHANED COMMIT: {orphaned_commit_url}")
    print(f"{'='*80}")
    
    results = get_smart_contracts(
        github_url=orphaned_commit_url,
        api_key=API_KEY,  # API key required for orphaned commits
        verbose=True
    )
    
    # Display results
    print(f"\nResults Summary:")
    print(f"- Method used: {results['summary']['method_used']}")
    print(f"- Is orphaned commit: {results['summary'].get('is_orphaned_commit', False)}")
    print(f"- Files found: {results['summary']['total_files']}")
    
    if results['files']:
        print(f"\nFirst few files from orphaned commit:")
        for j, file in enumerate(results['files'][:3]):
            print(f"{j+1}. {file['path']} ({file['language']})")
            print(f"   Size: {file['size']:,} chars, Lines: {file.get('lines', 'N/A')}")
            print(f"   URL: {file['blob_url']}")
            print(f"   Preview: {file['content'][:100].replace(chr(10), ' ')}...")
            print()
    
    # Additional test cases
    test_cases = [
        # Basic repository
        "https://github.com/ethereum/solidity",
        
        # Specific branch
        "https://github.com/ethereum/solidity/tree/develop",
        
        # Repository with subdirectory  
        "https://github.com/OpenZeppelin/openzeppelin-contracts/tree/master/contracts",
    ]
    
    for i, url in enumerate(test_cases[:1]):  # Test first case only
        print(f"\n{'='*80}")
        print(f"TEST CASE {i+1}: {url}")
        print(f"{'='*80}")
        
        results = get_smart_contracts(
            github_url=url,
            api_key=API_KEY,
            verbose=True
        )
        
        # Display results
        print(f"\nResults Summary:")
        print(f"- Method used: {results['summary']['method_used']}")
        print(f"- Files found: {results['summary']['total_files']}")
        
        if results['files']:
            print(f"\nFirst few files:")
            for j, file in enumerate(results['files'][:3]):
                print(f"{j+1}. {file['path']} ({file['language']})")
                print(f"   Size: {file['size']:,} chars, Lines: {file.get('lines', 'N/A')}")
                print(f"   URL: {file['blob_url']}")
                print(f"   Preview: {file['content'][:100].replace(chr(10), ' ')}...")
                print()
        
        # Validation check
        invalid_files = [f for f in results['files'] if not f.get('is_valid', True)]
        if invalid_files:
            print(f"Warning: {len(invalid_files)} files failed validation")
        
        print(f"Test case {i+1} completed successfully!")
    
    print(f"\n{'='*80}")
    print("ALL TESTS COMPLETED")
    print(f"{'='*80}")


# Additional utility functions for working with results

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

def get_file_statistics(results: Dict) -> Dict:
    """Get detailed statistics about the retrieved files."""
    files = results['files']
    if not files:
        return {}
    
    sizes = [f['size'] for f in files]
    lines = [f.get('lines', 0) for f in files if f.get('lines')]
    
    stats = {
        'total_files': len(files),
        'size_stats': {
            'min': min(sizes),
            'max': max(sizes),
            'avg': sum(sizes) // len(sizes),
            'total': sum(sizes)
        }
    }
    
    if lines:
        stats['line_stats'] = {
            'min': min(lines),
            'max': max(lines),
            'avg': sum(lines) // len(lines),
            'total': sum(lines)
        }
    
    return stats

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