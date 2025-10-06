#!/usr/bin/env python3

import json
import os
import requests
from github_file_retrieval_scripts.retrieve_all_smart_contract_files import get_smart_contracts
from github_file_retrieval_scripts.retrieve_changed_commits_files import handle_commit_files_via_api
from github_file_retrieval_scripts.retrieve_changed_pull_request_files import handle_pr_files_via_api
from github_file_retrieval_scripts.retrieve_changed_compare_files import handle_compare_files_via_api
from urllib.parse import urlparse
from config import SMART_CONTRACT_EXTENSIONS
from collections import Counter
import re
API_KEY = os.getenv('GITHUB_API_KEY')

# Create a session for file validation
file_validation_session = requests.Session()
file_validation_session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
})

if API_KEY:
    file_validation_session.headers.update({
        'Authorization': f'token {API_KEY}'
    })

def extract_string_values(obj):
    """Recursively extracts all string values from a JSON object (dict or list)."""
    strings = []
    if isinstance(obj, dict):
        for _, value in obj.items():
            if isinstance(value, str):
                strings.append(value)
            elif isinstance(value, (dict, list)):
                strings.extend(extract_string_values(value))
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, str):
                strings.append(item)
            elif isinstance(item, (dict, list)):
                strings.extend(extract_string_values(item))
    return strings

def extract_words(text, min_length=3):
    """
    Extract meaningful words from text.
    Splits on underscores, hyphens, and other non-alphanumeric characters,
    then filters out short/numeric strings.
    
    Args:
        text: String to extract words from
        min_length: Minimum word length to consider (default: 3)
    
    Returns:
        Set of lowercase words
    """
    # Split on underscores, hyphens, and other non-alphanumeric characters
    # This regex splits on any character that's not a letter or digit
    words = re.split(r'[^a-zA-Z0-9]+', text.lower())
    
    # Filter out empty strings, short words, and numbers-only strings
    words = [w for w in words if w and len(w) >= min_length and not w.isdigit()]
    
    return set(words)

def has_matching_words(filename, url, min_word_length=3):
    """
    Determine if a filename and URL share any matching words.
    
    This function extracts words from both the filename (excluding extension)
    and the URL (including domain and path), then checks for common words.
    Uses a minimum word length of 3 to avoid false positives from common
    short words like "v2", "src", "sol", etc.
    
    Args:
        filename: The filename to check (e.g., "my-document.pdf")
        url: The website URL to check (e.g., "https://example.com/my-page")
        min_word_length: Minimum length for words to be considered (default: 3)
    
    Returns:
        tuple: (bool, set) - True/False if matches exist, and the set of matching words
    
    Examples:
        >>> has_matching_words("filtered_Harvest-Flow-V2-Security-Review.json",
        ...                    "https://github.com/tokyoweb3/HARVESTFLOW_Ver.2/blob/main/contracts/src/LendingNFT.sol")
        (True, {'harvest', 'flow'})
        
        >>> has_matching_words("filtered_Harvest-Flow-V2-Security-Review.json",
        ...                    "https://github.com/chiru-labs/ERC721A-Upgradeable/blob/main/contracts/ERC721AUpgradeable.sol")
        (False, set())
        
        >>> has_matching_words("user-guide.pdf", "https://example.com/user/guide")
        (True, {'user', 'guide'})
    """
    # Remove file extension from filename
    filename_without_ext = filename.rsplit('.', 1)[0] if '.' in filename else filename
    
    # Extract words from filename
    filename_words = extract_words(filename_without_ext, min_word_length)
    
    # Parse URL and extract meaningful parts
    parsed_url = urlparse(url)
    
    # Combine domain and path for word extraction
    url_text = parsed_url.netloc + parsed_url.path
    
    # Extract words from URL
    url_words = extract_words(url_text, min_word_length)
    
    # Find matching words
    matching_words = filename_words.intersection(url_words)
    
    return len(matching_words) > 0, matching_words
    
def validate_file_exists(url):
    """
    Validate that a GitHub file URL exists and is accessible.
    Works with both blob URLs and raw URLs.
    """
    try:
        # For blob URLs, convert to raw URL for validation
        if '/blob/' in url:
            # Convert blob URL to raw URL for checking
            # https://github.com/owner/repo/blob/commit/path -> https://raw.githubusercontent.com/owner/repo/commit/path
            raw_url = url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
            response = file_validation_session.get(raw_url, timeout=10)
        else:
            # For other URLs, check directly
            response = file_validation_session.get(url, timeout=10)
        
        if response.status_code == 200:
            return True
        elif response.status_code == 404:
            print(f"  ⚠ File not found (404): {url}")
            return False
        else:
            print(f"  ⚠ Unexpected status {response.status_code} for: {url}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"  ⚠ Error validating {url}: {e}")
        return False

import json
from typing import Dict, List, Tuple, Set, Union, Any


def load_reports_from_json(json_file: str) -> List[Dict[str, Any]]:
    """
    Load and parse JSON file containing report data.
    
    Args:
        json_file: Path to the JSON file
        
    Returns:
        List of report dictionaries
        
    Raises:
        Returns empty list if file cannot be loaded
    """
    try:
        with open(json_file, "r", encoding="utf-8") as f:
            reports = json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error reading JSON file: {e}")
        return []

    # Ensure we always work with a list
    if isinstance(reports, dict):
        reports = [reports]
    
    return reports


def validate_report_urls(report: Dict[str, Any], json_file: str) -> Tuple[List[str], List[str]]:
    """
    Extract and validate source and fix URLs from a report.
    Returns URLs that have matching words with the json_file name.
    If no URLs match, returns all URLs.
    
    Args:
        report: Report dictionary containing URL fields
        json_file: Name of the JSON file to match against
        
    Returns:
        Tuple of (source_urls, fix_urls) as lists
    """
    source_url = report.get("source_code_url")
    fix_url = report.get("fix_commit_url")
    
    # Convert to lists for uniform processing
    all_source_urls = source_url if isinstance(source_url, list) else [source_url] if source_url else []
    all_fix_urls = fix_url if isinstance(fix_url, list) else [fix_url] if fix_url else []
    
    # Filter source URLs by matching words
    matching_source_urls = [url for url in all_source_urls if has_matching_words(json_file, url)]
    
    # Filter fix URLs by matching words
    matching_fix_urls = [url for url in all_fix_urls if has_matching_words(json_file, url)]
    
    # If no matches found in either list, return all URLs
    if not matching_source_urls and not matching_fix_urls:
        return all_source_urls, all_fix_urls
    
    # Otherwise, return only the matching ones
    return matching_source_urls, matching_fix_urls


def extract_search_data(report: Dict[str, Any]) -> str:
    """
    Extract relevant fields from report for semantic search.
    
    Args:
        report: Report dictionary
        
    Returns:
        JSON string of search-relevant data
    """
    search_fields = ['title', 'description', 'recommendation', 'files', 'broken_code_snippets']
    search_data = {field: report[field] for field in search_fields if field in report}
    return json.dumps(search_data)


def process_source_url(source_url: str) -> Set[str]:
    """
    Process source code URLs to extract relevant file URLs.
    
    Args:
        source_url: Source code URL to process
        
    Returns:
        All smart contract files in the source repo
    """
    relevant_files_set = set()
    
    print(f"\nSearching source code at: {source_url}")
    new_tree = None
    
    if 'commit' in source_url:
        print("Processing commit url, retrieving new tree and relevant smart contract files")
        result = handle_commit_files_via_api(source_url)
        new_tree = result['newer_tree_url']

    elif 'pull' in source_url:
        print("Processing pull url, retrieving new tree and relevant smart contract files")
        result = handle_pr_files_via_api(source_url)
        new_tree = result['head_tree_info']

    elif 'compare' in source_url:
        print("Processing compare url, retrieving new tree and relevant smart contract files")
        result = handle_compare_files_via_api(source_url)
        new_tree = result['head_tree_url']

    elif 'tree' in source_url:
        print("Already a tree, retrieving smart contract files")
        new_tree = source_url

    elif 'blob' in source_url:
        print("Blob detected, doing nothing")
        relevant_files_set.add(source_url)

    if new_tree:
        # Get all smart contract files and check semantics
        results = get_smart_contracts(github_url=new_tree, api_key=API_KEY)
        for file in results['files']:
            relevant_files_set.add(file['blob_url'])
    
    return relevant_files_set


def process_fix_url(fix_url: str, changed_files_only: bool) -> Set[str]:
    """
    Process fix commit URL to extract changed file URLs.
    
    Args:
        fix_url: Fix commit URL to process 
        changed_files_only: True if we want only the changed files in this pull/commit, 
                            False if we want to get all Smart Contract files in the source repo
        
    Returns:
        Set of files that changed in this commit/pull (process first)
        All smart contract files (second pass if first returns nothing)
    """
    relevant_files_set = set()
    github_tree_url = ""
    
    
    print(f"\nSearching fix commit at: {fix_url}")
    
    if 'commit' in fix_url:
        print("Processing commit url, retrieving changed files")
        result = handle_commit_files_via_api(fix_url)
        for file_info in result['files']:
            relevant_files_set.add(file_info['older_file_url'])
        github_tree_url = result['older_tree_url']

    elif 'pull' in fix_url:
        print("Processing pull url, retrieving changed files")
        result = handle_pr_files_via_api(fix_url)
        for file_info in result['files']:
            relevant_files_set.add(file_info['old_blob_url'])
        github_tree_url = result['earliest_tree_url']

    elif 'compare' in fix_url:
        print("Processing compare url, retrieving changed files")
        result = handle_compare_files_via_api(fix_url)
        for file_info in result['files']:
            relevant_files_set.add(file_info['older_file_url'])
        github_tree_url = result['base_tree_url']
        
    elif 'tree' in fix_url:
        print("Processing tree url, relevant smart contract files")
        fix_url = fix_url.replace("/tree/", "/commit/")
        result = handle_commit_files_via_api(fix_url)
        for file_info in result['files']:
            relevant_files_set.add(file_info['older_file_url'])
        github_tree_url = result['older_tree_url']
    
    elif 'blob' in fix_url:
        fix_url = fix_url.replace("/blob/", "/commit/")
        result = handle_commit_files_via_api(fix_url)
        for file_info in result['files']:
            relevant_files_set.add(file_info['older_file_url'])
        github_tree_url = result['older_tree_url']

    all_files = set()

    if github_tree_url and not changed_files_only:
        # Get all smart contract files and check semantics
        results = get_smart_contracts(github_url=github_tree_url, api_key=API_KEY)
        for file in results['files']:
            all_files.add(file['blob_url'])
        return all_files

    else:
        return relevant_files_set        

GITHUB_API = "https://api.github.com"

def normalize_to_commit(owner: str, repo: str, url: str, headers: dict) -> str:
    """
    Convert any GitHub tree/commit/pull/compare URL to a commit SHA.
    """
    parts = urlparse(url).path.strip("/").split("/")

    if "commit" in parts:
        # https://github.com/org/repo/commit/<sha>
        return parts[parts.index("commit") + 1]

    if "tree" in parts:
        # https://github.com/org/repo/tree/<sha>
        return parts[parts.index("tree") + 1]

    if "pull" in parts:
        # https://github.com/org/repo/pull/<number>
        pr_number = parts[parts.index("pull") + 1]
        pr_api = f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr_number}"
        r = requests.get(pr_api, headers=headers)
        r.raise_for_status()
        return r.json()["head"]["sha"]

    if "compare" in parts:
        # https://github.com/org/repo/compare/base...head
        compare_range = parts[parts.index("compare") + 1]
        head = compare_range.split("...")[-1]
        # Need to fetch compare API to resolve to a commit SHA
        compare_api = f"{GITHUB_API}/repos/{owner}/{repo}/compare/{compare_range}"
        r = requests.get(compare_api, headers=headers)
        r.raise_for_status()
        return r.json()["commits"][-1]["sha"]  # last commit in compare

    raise ValueError("Unsupported GitHub URL type")


def find_file_before_change(commit_url: str, blob_url: str, max_commits: int = 30, debug: bool = False) -> str:
    """
    Given a GitHub commit/tree/compare URL and a blob URL, finds where in the commit history
    that file was changed and returns a blob link to the original version before the change.
    
    Starting from the given commit, walks backwards through history until it finds the commit
    where the target file was actually modified, then returns the blob URL from the parent
    commit (the version before the change).
    
    Args:
        commit_url: GitHub commit/tree/compare URL to start searching from
        blob_url: GitHub blob URL of the file to track
        max_commits: Maximum number of commits to walk back through
        debug: If True, print debug information during execution
    
    Returns:
        Blob URL to the version of the file before it was changed, or None if not found
        Returns "NEW FILE" if the file was added in the first commit found
    """
    token = os.getenv("GITHUB_API_KEY")
    headers = {"Authorization": f"token {token}"} if token else {}

    # Parse repo info from blob URL
    blob_parts = urlparse(blob_url).path.strip("/").split("/")
    owner, repo = blob_parts[0], blob_parts[1]
    
    # Extract filename from blob URL
    # Format: /owner/repo/blob/sha/path/to/file
    if len(blob_parts) < 5 or blob_parts[2] != "blob":
        raise ValueError("Invalid blob URL format")
    
    file_path = "/".join(blob_parts[4:])  # everything after /blob/<sha>/
    
    if debug:
        print(f"🔍 DEBUG: Looking for file: '{file_path}'")
        print(f"🔍 DEBUG: Repo: {owner}/{repo}")
        print(f"🔍 DEBUG: Blob URL parts: {blob_parts}")

    # Normalize commit URL to a commit SHA
    start_commit_sha = normalize_to_commit(owner, repo, commit_url, headers)
    
    if debug:
        print(f"🔍 DEBUG: Starting from commit: {start_commit_sha}")

    # Walk back through commit history starting from the given commit
    current_sha = start_commit_sha
    
    for i in range(max_commits):
        if debug:
            print(f"\n🔍 DEBUG: Checking commit {i+1}/{max_commits}: {current_sha}")
        
        commit_api = f"{GITHUB_API}/repos/{owner}/{repo}/commits/{current_sha}"
        r = requests.get(commit_api, headers=headers)
        r.raise_for_status()
        commit_data = r.json()
        
        commit_message = commit_data.get("commit", {}).get("message", "").split('\n')[0][:60]
        if debug:
            print(f"🔍 DEBUG: Commit message: {commit_message}")

        # Check if this commit modified our target file
        files = commit_data.get("files", [])
        if debug:
            print(f"🔍 DEBUG: This commit changed {len(files)} files:")
            for f in files:
                print(f"    - {f['filename']} (status: {f.get('status', 'unknown')})")
                if f.get('previous_filename'):
                    print(f"      (previously: {f['previous_filename']})")
        
        file_was_changed_in_this_commit = False
        
        for f in files:
            # Check if this file matches our target (current name or previous name if renamed)
            if f["filename"] == file_path or f.get("previous_filename") == file_path:
                file_was_changed_in_this_commit = True
                
                if debug:
                    print(f"🎯 DEBUG: FOUND! File '{file_path}' was changed in this commit!")
                    print(f"    File status: {f.get('status', 'unknown')}")
                    print(f"    Changes: +{f.get('additions', 0)} -{f.get('deletions', 0)}")
                
                # Found the commit that changed this file
                if not commit_data["parents"]:
                    # This is a root commit, file was added here
                    if debug:
                        print(f"🔍 DEBUG: This is a root commit - file was added here")
                    return "NEW FILE"

                # Get the parent commit to find the "before" version
                parent_sha = commit_data["parents"][0]["sha"]
                
                # Use the previous filename if the file was renamed, otherwise use current name
                before_path = f.get("previous_filename", f["filename"])
                before_blob_url = f"https://github.com/{owner}/{repo}/blob/{parent_sha}/{before_path}"
                
                if debug:
                    print(f"🎯 DEBUG: Returning blob URL from parent commit {parent_sha}")
                    print(f"🎯 DEBUG: Before path: {before_path}")
                    print(f"🎯 DEBUG: Final URL: {before_blob_url}")
                
                return before_blob_url

        # If file wasn't changed in this commit, continue to parent
        if not file_was_changed_in_this_commit:
            if debug:
                print(f"🔍 DEBUG: File not changed in this commit, moving to parent...")
            
            parents = commit_data.get("parents", [])
            if not parents:
                # Reached root commit without finding the file change
                if debug:
                    print(f"🔍 DEBUG: Reached root commit without finding file change")
                break
            current_sha = parents[0]["sha"]

    # File change not found within the commit limit
    if debug:
        print(f"🔍 DEBUG: File change not found within {max_commits} commits")
    return None

def filter_test_files(file_urls: Set[str]) -> List[str]:
    """
    Filter out test files from the set of file URLs.
    
    Args:
        file_urls: Set of file URLs
        
    Returns:
        List of filtered file URLs (excluding test files)
    """
    return [f for f in file_urls if ".t." not in f]


def get_repo_key(url: str) -> str:
    """Extract owner/repo from a GitHub URL."""
    try:
        parts = urlparse(url).path.strip("/").split("/")
        return f"{parts[0]}/{parts[1]}" if len(parts) >= 2 else None
    except Exception:
        return None


def get_newest_github_url(urls: list) -> list:
    """
    Given a list of GitHub URLs, return the newest one(s).
    - Groups by repo, processes only the most common repo.
    - Supports commit, pull, compare, tree, and blob URLs.
    - If an error occurs, falls back to returning all URLs.
    Returns a list of URLs (could be more than one if repos tie).
    """
    if not urls:
        return []

    if len(urls) == 1:
        return urls

    try:
        # Find most common repo
        repo_keys = [get_repo_key(u) for u in urls if get_repo_key(u)]
        if not repo_keys:
            return urls  # fallback: no valid repos
        most_common_repo, freq = Counter(repo_keys).most_common(1)[0]

        # Filter URLs to only that repo
        urls = [u for u in urls if get_repo_key(u) == most_common_repo]

        session = requests.Session()
        session.headers.update({'Authorization': f'token {API_KEY}'})

        commits = []
        for url in urls:
            parsed = urlparse(url)
            parts = parsed.path.strip("/").split("/")
            owner, repo = parts[0], parts[1]
            kind = parts[2] if len(parts) > 2 else None

            sha = None
            if kind == "commit":
                sha = parts[3]
            elif kind == "tree":
                branch_or_tag = parts[3]
                api_url = f"https://api.github.com/repos/{owner}/{repo}/branches/{branch_or_tag}"
                resp = session.get(api_url)
                resp.raise_for_status()
                sha = resp.json()["commit"]["sha"]
            elif kind == "compare":
                base, head = parts[3].split("...")
                sha = head
            elif kind == "pull":
                pr_number = parts[3]
                api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
                resp = session.get(api_url)
                resp.raise_for_status()
                sha = resp.json()["head"]["sha"]
            elif kind == "blob":
                # Blob URLs don’t have commits; keep them directly
                commits.append(("9999-12-31T23:59:59Z", url))
                continue
            else:
                continue  # skip unsupported URLs

            # Lookup commit timestamp
            api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
            resp = session.get(api_url)
            resp.raise_for_status()
            commit_data = resp.json()
            commit_date = commit_data["commit"]["committer"]["date"]
            commits.append((commit_date, url))

        if not commits:
            return urls  # fallback: nothing parsed correctly

        # Sort by date descending
        commits.sort(reverse=True, key=lambda x: x[0])
        return [commits[0][1]]

    except Exception as e:
        print(f"⚠️ Error in get_newest_github_url: {e}, falling back to all URLs")
        return urls


def determine_relevant_files(report: Dict[str, Any], report_index: int, processed_urls: Dict[str, List[str]], json_file: str) -> Tuple[str, List[str]]:
    """
    Process a single report to extract relevant files.
    """
    # Validate URLs
    source_urls, fix_urls = validate_report_urls(report, json_file)
    print(f"Source Urls: {source_urls}")
    print(f"Fix Urls: {fix_urls}")

    if not source_urls and not fix_urls:
        print("Error: JSON must contain either 'source_code_url' or 'fix_commit_url'.")
        return []

    relevant_files_set = set()

    # --- Process source URLs ---
    if source_urls:
        newest_sources = get_newest_github_url(source_urls)
        for src in newest_sources:
            if src in processed_urls:
                print(f"Using cached results for source URL: {src}")
                relevant_files_set.update(processed_urls[src])
            elif 'github.com' in src and '/blob/' in src:
                print(f"Using GitHub blob as relevant file: {src}")
                processed_urls[src] = [src]
                relevant_files_set.add(src)
            else:
                print(f"Processing source URL: {src}")
                new_files = process_source_url(src)
                processed_urls[src] = list(new_files)
                relevant_files_set.update(new_files)

    # --- Process fix URLs ---
    if fix_urls:
        newest_fixes = get_newest_github_url(fix_urls)
        for fix in newest_fixes:
            if fix in processed_urls:
                print(f"Using cached results for fix URL: {fix}")
                relevant_files_set.update(processed_urls[fix])
            else:
                print(f"Processing fix URL: {fix}")
                changed_files = process_fix_url(fix, True)
                processed_urls[fix] = list(changed_files)
                relevant_files_set.update(changed_files)

    # Filter out test (.t.) files
    relevant_files = filter_test_files(relevant_files_set)

    # Print results
    for file_url in relevant_files:
        print(f"  - {file_url}")

    return relevant_files



def get_relevant_files(json_file: str) -> Tuple[Dict[str, List[str]], List[Dict[str, Any]]]:
    """
    Main function to process reports and extract relevant files.
    
    Args:
        json_file: Path to JSON file containing reports
        
    Returns:
        Tuple of (results_dict, reports_list) where:
        - results_dict: Dictionary mapping report titles to lists of relevant file URLs
        - reports_list: List of original report dictionaries
    """
    # Load reports from JSON file
    reports = load_reports_from_json(json_file)
    if not reports:
        return {}, []
    
    results_dict = {}
    processed_urls = {}  # Cache for already processed URLs
    
    # Process each report
    for i, report in enumerate(reports):
        relevant_files = determine_relevant_files(report, i, processed_urls, json_file)
        title = report.get("title", "Unknown title")
        results_dict[title] = relevant_files
    
    print(f"\n{'='*50}")
    print(f"Processing complete. Processed {len(processed_urls)} unique URLs.")
    print("Semantic analysis can be performed next.")
    print(f"{'='*50}")
    
    return results_dict, reports


    

def main():
    json_file = "/Users/matt/vulnaut/retrieve_github_files_with_AI/test_dataset/0xGuard/filtered_Anyrand.json"
    get_relevant_files(json_file)


if __name__ == "__main__":
    main()