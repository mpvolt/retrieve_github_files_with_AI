#!/usr/bin/env python3

import json
import os
import requests
from github_file_retrieval_scripts.retrieve_all_smart_contract_files import get_smart_contracts
from github_file_retrieval_scripts.retrieve_changed_commits_files import handle_commit_files_via_api
from github_file_retrieval_scripts.retrieve_changed_pull_request_files import handle_pr_files_via_api
from github_file_retrieval_scripts.retrieve_changed_compare_files import handle_compare_files_via_api
from urllib.parse import urlparse


SMART_CONTRACT_EXTENSIONS = (
        '.sol', '.tsol', '.vy', '.rs', '.move', '.cairo', '.fc', '.func', '.circom'
    )
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


def validate_report_urls(report: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """
    Extract and validate source and fix URLs from a report.
    
    Args:
        report: Report dictionary containing URL fields
        
    Returns:
        Tuple of (source_urls, fix_urls) as lists
    """
    source_url = report.get("source_code_url")
    fix_url = report.get("fix_commit_url")
    
    # Convert to lists for uniform processing
    source_urls = source_url if isinstance(source_url, list) else [source_url] if source_url else []
    fix_urls = fix_url if isinstance(fix_url, list) else [fix_url] if fix_url else []
    
    return source_urls, fix_urls


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


def find_file_before_change(commit_url: str, blob_url: str, max_commits: int = 30, debug: bool = False) -> str | None:
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

def process_single_report(report: Dict[str, Any], report_index: int, processed_urls: Dict[str, List[str]]) -> Tuple[str, List[str]]:
    """
    Process a single report to extract relevant files.
    
    Args:
        report: Report dictionary
        report_index: Index of the report for naming purposes
        processed_urls: Dictionary mapping URLs to their cached results
        
    Returns:
        Tuple of (report_title, relevant_files_list)
    """
    report_title = report.get('title', f'Untitled_Report_{report_index+1}')
    print(f"\n{'='*50}")
    print(f"Processing report {report_index+1}: {report_title}")
    print(f"{'='*50}")
    
    # Validate URLs
    source_urls, fix_urls = validate_report_urls(report)
    print(f"Source Urls: {source_urls}")
    print(f"Fix Urls: {fix_urls}")
    
    if not source_urls and not fix_urls:
        print("Error: JSON must contain either 'source_code_url' or 'fix_commit_url'.")
        return report_title, []
    
    # Extract search data (for future semantic analysis)    
    relevant_files_set = set()

    # If the source url exists and is already a blob, no processing needed
    if source_urls:
        for source_url in source_urls:
            if 'github.com' in source_url and '/blob/' in source_url:
                print(f"Using GitHub blob as relevant file: {source_url}")
                relevant_files_set.update([source_url])
    
    #Otherwise process fix URLs and see which files changed + other smart contract files
    if not relevant_files_set and fix_urls:
        for fix_url in fix_urls:
            if fix_url in processed_urls:
                print(f"Using cached results for fix URL: {fix_url}")
                relevant_files_set.update(processed_urls[fix_url])
            else:
                print(f"Processing fix URL: {fix_url}")
                changed_files = process_fix_url(fix_url, True)
                processed_urls[fix_url] = list(changed_files)
                relevant_files_set.update(changed_files)

    #If no fix url, use source url if it exists
    if not relevant_files_set and source_urls:
        # Process source URLs if no fix URLs
        for source_url in source_urls:
            if source_url in processed_urls:
                print(f"Using cached results for source URL: {source_url}")
                relevant_files_set.update(processed_urls[source_url])
            else:
                print(f"Processing source URL: {source_url}")
                new_files = process_source_url(source_url)
                processed_urls[source_url] = list(new_files)
                relevant_files_set.update(new_files)
    
    # Filter out test (.t.) files and convert to list
    relevant_files = filter_test_files(relevant_files_set)
    
    # Print results
    for file_url in relevant_files:
        print(f"  - {file_url}")
    
    return report_title, relevant_files


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
        report_title, relevant_files = process_single_report(report, i, processed_urls)
        results_dict[report_title] = relevant_files
    
    print(f"\n{'='*50}")
    print(f"Processing complete. Processed {len(processed_urls)} unique URLs.")
    print("Semantic analysis can be performed next.")
    print(f"{'='*50}")
    
    return results_dict, reports


    

def main():
    json_file = "/mnt/d/golden_dataset/bailsec/filtered_Bailsec - Defi Money Fee Module - Final Report.json"

    # Load JSON file
    #results = get_relevant_files(json_file)
    #print(results)
    find_file_before_change(
    "https://github.com/defidotmoney/dfm-contracts/commit/9757a634244ab35b1a97797040e699e038158e92",
    "https://github.com/defidotmoney/dfm-contracts/blob/9757a634244ab35b1a97797040e699e038158e92/contracts/fees/dependencies/FeeConverterBase.sol",
    debug=True
)


if __name__ == "__main__":
    main()