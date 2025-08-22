#!/usr/bin/env python3

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import requests
from urllib.parse import urlparse
from retrieve_all_smart_contract_files import get_smart_contracts
from retrieve_changed_commits_files import handle_commit_files_via_api
from retrieve_changed_pull_request_files import handle_pr_files_via_api
from retrieve_changed_compare_files import handle_compare_files_via_api
from retrieve_all_smart_contract_functions import extract_function_names


SMART_CONTRACT_EXTENSIONS = (
        '.sol', '.vy', '.rs', '.move', '.cairo', '.fc', '.func'
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


def process_source_urls(source_urls: List[str]) -> Set[str]:
    """
    Process source code URLs to extract relevant file URLs.
    
    Args:
        source_urls: List of source code URLs to process
        
    Returns:
        Set of relevant file URLs
    """
    relevant_files_set = set()
    
    for url in source_urls:
        print(f"\nSearching source code at: {url}")
        new_tree = None
        
        if 'commit' in url:
            print("Processing commit url, retrieving new tree and relevant smart contract files")
            result = handle_commit_files_via_api(url)
            new_tree = result['newer_tree_url']
        elif 'pull' in url:
            print("Processing pull url, retrieving new tree and relevant smart contract files")
            result = handle_pr_files_via_api(url)
            new_tree = result['head_tree_info']
        elif 'compare' in url:
            print("Processing compare url, retrieving new tree and relevant smart contract files")
            result = handle_compare_files_via_api(url)
            new_tree = result['head_tree_url']
        elif 'tree' in url:
            print("Already a tree, retrieving smart contract files")
            new_tree = url
        elif 'blob' in url:
            print("Blob detected, doing nothing")
            relevant_files_set.add(url)

        if new_tree:
            # Get all smart contract files and check semantics
            results = get_smart_contracts(github_url=new_tree, api_key=API_KEY)
            for file in results['files']:
                relevant_files_set.add(file['blob_url'])
    
    return relevant_files_set


def process_fix_urls(fix_urls: List[str]) -> Set[str]:
    """
    Process fix commit URLs to extract changed file URLs.
    
    Args:
        fix_urls: List of fix commit URLs to process
        
    Returns:
        Set of relevant file URLs
    """
    relevant_files_set = set()
    
    for url in fix_urls:
        print(f"\nSearching fix commit at: {url}")
        
        if 'commit' in url:
            print("Processing commit url, retrieving changed files")
            result = handle_commit_files_via_api(url)
            for file_info in result['files']:
                relevant_files_set.add(file_info['older_file_url'])
        elif 'pull' in url:
            print("Processing pull url, retrieving changed files")
            result = handle_pr_files_via_api(url)
            for file_info in result['files']:
                relevant_files_set.add(file_info['old_blob_url'])
        elif 'compare' in url:
            print("Processing compare url, retrieving changed files")
            result = handle_compare_files_via_api(url)
            for file_info in result['files']:
                relevant_files_set.add(file_info['older_file_url'])
        elif 'tree' in url:
            print("Processing tree url, relevant smart contract files")
            result = retrieve_all_smart_contract_files(url)
            if hasattr(result, 'files') or isinstance(result, dict) and 'files' in result:
                files = result['files'] if isinstance(result, dict) else result.files
                for file in files:
                    if 'blob_url' in file:
                        relevant_files_set.add(file['blob_url'])
        elif 'blob' in url:
            print("Blob detected, doing nothing")
            relevant_files_set.add(url)
    
    return relevant_files_set


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
    
    if not source_urls and not fix_urls:
        print("Error: JSON must contain either 'source_code_url' or 'fix_commit_url'.")
        return report_title, []
    
    # Extract search data (for future semantic analysis)
    search_json_str = extract_search_data(report)
    
    relevant_files_set = set()
    
    # Process fix URLs first (preferred if available)
    if fix_urls:
        for fix_url in fix_urls:
            if fix_url in processed_urls:
                print(f"Using cached results for fix URL: {fix_url}")
                relevant_files_set.update(processed_urls[fix_url])
            else:
                print(f"Processing fix URL: {fix_url}")
                new_files = process_fix_urls([fix_url])
                processed_urls[fix_url] = list(new_files)
                relevant_files_set.update(new_files)
        
        # Fallback to source URLs if no files found from fix URLs
        if not relevant_files_set and source_urls:
            for source_url in source_urls:
                if source_url in processed_urls:
                    print(f"Using cached results for source URL: {source_url}")
                    relevant_files_set.update(processed_urls[source_url])
                else:
                    print(f"Processing source URL: {source_url}")
                    new_files = process_source_urls([source_url])
                    processed_urls[source_url] = list(new_files)
                    relevant_files_set.update(new_files)
    else:
        # Process source URLs if no fix URLs
        for source_url in source_urls:
            if source_url in processed_urls:
                print(f"Using cached results for source URL: {source_url}")
                relevant_files_set.update(processed_urls[source_url])
            else:
                print(f"Processing source URL: {source_url}")
                new_files = process_source_urls([source_url])
                processed_urls[source_url] = list(new_files)
                relevant_files_set.update(new_files)
    
    # Filter out test files and convert to list
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
    json_file = "hacken/filtered_[SCA]XPower_ERC20+ERC1155+Staking_Dec2023.json"

    # Load JSON file
    results = get_relevant_files(json_file)
    #print(results)


if __name__ == "__main__":
    main()