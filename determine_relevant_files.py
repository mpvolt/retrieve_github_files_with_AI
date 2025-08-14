#!/usr/bin/env python3

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urlparse

SMART_CONTRACT_EXTENSIONS = (
        '.sol', '.vy', '.rs', '.move', '.cairo', '.fc', '.func', '.ts', '.js'
    )

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


def extract_function_names(file_content, file_extension):
    """Extract function names from different smart contract file types."""
    function_names = []
    
    if file_extension == '.sol':
        # Solidity function patterns
        patterns = [
            r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
            r'modifier\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
            r'event\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
            r'constructor\s*\(',  # constructor doesn't have a name but we'll capture it
        ]
    elif file_extension == '.vy':
        # Vyper function patterns
        patterns = [
            r'@external\s*\ndef\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
            r'@internal\s*\ndef\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
            r'def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
        ]
    elif file_extension == '.rs':
        # Rust function patterns
        patterns = [
            r'fn\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
            r'pub\s+fn\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
        ]
    elif file_extension == '.move':
        # Move function patterns
        patterns = [
            r'fun\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
            r'public\s+fun\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
            r'public\s+entry\s+fun\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
        ]
    elif file_extension in ['.ts', '.js']:
        # TypeScript/JavaScript function patterns
        patterns = [
            r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(',
            r'const\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*\(',
            r'let\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*\(',
            r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:\s*\([^)]*\)\s*=>\s*',
        ]
    elif file_extension in ['.cairo', '.fc', '.func']:
        # Cairo/FunC function patterns (basic)
        patterns = [
            r'func\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
            r'fun\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
        ]
    else:
        patterns = []
    
    for pattern in patterns:
        matches = re.finditer(pattern, file_content, re.MULTILINE | re.IGNORECASE)
        for match in matches:
            if match.groups():
                function_names.append(match.group(1))
            elif 'constructor' in pattern:
                function_names.append('constructor')
    
    return function_names



def main():
    parser = argparse.ArgumentParser(description="Find smart contract files matching filenames or function names from JSON report.")
    parser.add_argument("json_file", help="Path to the JSON vulnerability report file.")
    args = parser.parse_args()

    # Load JSON file
    try:
        with open(args.json_file, "r", encoding="utf-8") as f:
            reports = json.load(f)  # could be a list
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error reading JSON file: {e}")
        return

    if isinstance(reports, dict):
        reports = [reports]  # wrap single object in a list

    all_matches = []

    for i, report in enumerate(reports):
        print(f"\n{'='*50}")
        print(f"Processing report {i+1}: {report.get('title', 'Untitled')}")
        print(f"{'='*50}")
        
        # Make a copy to avoid modifying the original
        report_copy = report.copy()
        source_url = report_copy.pop("source_code_url", None)
        fix_url = report_copy.pop("fix_commit_url", None)

        if not source_url and not fix_url:
            print("Error: JSON must contain either 'source_code_url' or 'fix_commit_url'.")
            continue

        # Only use title, description, and files fields for search terms
        search_data = {}
        if 'title' in report:
            search_data['title'] = report['title']
        if 'description' in report:
            search_data['description'] = report['description'] 
        if 'files' in report:
            search_data['files'] = report['files']
            
        search_json_str = json.dumps(search_data)

        if source_url:
            print(f"\nSearching source code at: {source_url}")
            matches = find_matching_files(search_json_str, source_url, 'source')
            all_matches.extend(matches)
            
        if fix_url:
            print(f"\nSearching fix commit at: {fix_url}")
            matches = find_matching_files(search_json_str, fix_url, 'fix')
            all_matches.extend(matches)

    # --- Output all results ---
    print(f"\n{'='*60}")
    print("SUMMARY OF ALL MATCHING FILES")
    print(f"{'='*60}")
    
    if not all_matches:
        print("No matching files found.")
    else:
        print(f"Found {len(all_matches)} matching files:")
        print()
        
        for match in all_matches:
            print(f"File: {match['file_path']} ({match['url_type']}) [Score: {match['score']}]")
            if match.get('commit_specific'):
                print(f"      ^ File was changed in this specific commit/PR")
            print(f"URL:  {match['file_url']}")
            
            if match['filename_matches']:
                print(f"Filename matches: {', '.join(match['filename_matches'])}")
            
            if match['function_matches']:
                print(f"Function matches: {', '.join(match['function_matches'])}")
            
            print("-" * 40)


if __name__ == "__main__":
    main()