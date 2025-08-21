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

def get_relevant_files(json_file):
    try:
        with open(json_file, "r", encoding="utf-8") as f:
            reports = json.load(f)  # could be a list
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error reading JSON file: {e}")
        return {}, []  # Return both empty dict and empty list

    if isinstance(reports, dict):
        reports = [reports]  # wrap single object in a list

    # Dictionary to store results with title as key
    results_dict = {}

    for i, report in enumerate(reports):
        print(f"\n{'='*50}")
        report_title = report.get('title', f'Untitled_Report_{i+1}')
        print(f"Processing report {i+1}: {report_title}")
        print(f"{'='*50}")
        
        # Use a set to track unique file URLs and prevent duplicates for this report
        relevant_files_set = set()
        
        # Make a copy to avoid modifying the original
        report_copy = report.copy()
        source_url = report_copy.pop("source_code_url", None)
        fix_url = report_copy.pop("fix_commit_url", None)

        if not source_url and not fix_url:
            print("Error: JSON must contain either 'source_code_url' or 'fix_commit_url'.")
            results_dict[report_title] = []
            continue

        # Only use title, description, and files fields for search terms
        search_data = {}
        if 'title' in report:
            search_data['title'] = report['title']
        if 'description' in report:
            search_data['description'] = report['description'] 
        if 'recommendation' in report:
            search_data['recommendation'] = report['recommendation']
        if 'files' in report:
            search_data['files'] = report['files']
        if 'broken_code_snippets' in report:
            search_data['broken_code_snippets'] = report['broken_code_snippets']
            
        search_json_str = json.dumps(search_data)
        
        # Convert single URLs to lists for uniform processing
        source_urls = source_url if isinstance(source_url, list) else [source_url] if source_url else []
        fix_urls = fix_url if isinstance(fix_url, list) else [fix_url] if fix_url else []

        #If we have a fix_commit_url field, we don't check source commit
        #Otherwise, we check the source commits
        if not fix_urls:
            # Process all source URLs
            # Retrieve the most recent versions of all files, determine which are relevant semantically
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
                    #Can't determine relevant files directly from source url
                    #Need to get all smart contract files and check semantics
                    results = get_smart_contracts(github_url=new_tree, api_key=API_KEY)
                    for file in results['files']:
                        relevant_files_set.add(file['blob_url'])

        else:
        # Process all fix URLs
        # Retrieve only the files that changed (if not tree), determine which are relevant semantically

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
    
        # Convert set back to list for final use, filtering out test files
        relevant_files = [f for f in relevant_files_set if ".t." not in f]
        
        for file_url in relevant_files:
            print(f"  - {file_url}")

        # Store the results for this report in the dictionary
        results_dict[report_title] = relevant_files

        #### Do semantic analyis to determine which files are relevant
    
    return results_dict, reports  # Return both the files dict AND the reports data


    

def main():
    json_file = "hacken/filtered_[SCA]Hyperlane_InterchainMessageService_Apr2023.json"

    # Load JSON file
    results = get_relevant_files(json_file)
    #print(results)


if __name__ == "__main__":
    main()