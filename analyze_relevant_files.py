import json
import re
import os
from pathlib import Path
from typing import List, Dict, Set, Tuple
from fuzzywuzzy import fuzz
from determine_relevant_files import get_relevant_files 
from retrieve_all_smart_contract_functions import extract_function_names
from match_files_to_report import match_bug_to_files
import requests



SMART_CONTRACT_EXTENSIONS = (
        '.sol', '.vy', '.rs', '.move', '.cairo', '.fc', '.func'
    )

def find_files_up_commit_history(report, source_url, api_key, max_commits=50):
    """
    Walks up the commit history starting from the given source_url,
    checking each commit for relevant file changes until a match is found.
    """
    try:
        owner, repo, branch, path = parse_github_url(source_url)
    except Exception as e:
        print(f"Error parsing GitHub URL: {e}")
        return [], None
        
    headers = {"Authorization": f"token {api_key}"}
    
    # Get commits for the entire repo, not just a specific path
    commits_url = f"https://api.github.com/repos/{owner}/{repo}/commits"
    params = {"sha": branch, "per_page": 10}  # Get more commits per request
    
    current_sha = branch
    
    for i in range(max_commits):
        params["sha"] = current_sha
        resp = requests.get(commits_url, headers=headers, params=params)
        
        if resp.status_code == 403:  # Rate limit
            print("Rate limit exceeded, waiting...")
            time.sleep(60)
            continue
        elif resp.status_code != 200:
            print(f"GitHub API error: {resp.status_code}")
            break

        commits = resp.json()
        if not commits:
            break

        for commit in commits:
            commit_sha = commit["sha"]
            commit_url = commit["html_url"]

            # Get changed files for this commit
            commit_detail_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_sha}"
            detail_resp = requests.get(commit_detail_url, headers=headers)
            
            if detail_resp.status_code != 200:
                continue

            commit_data = detail_resp.json()
            changed_files = [f["filename"] for f in commit_data.get("files", [])]

            # Match against report
            matched_files = match_bug_to_files(report, set(changed_files), api_key)
            if matched_files:
                return matched_files, commit_url

        # Move to next batch of commits
        if len(commits) < 10:  # No more commits
            break
        current_sha = commits[-1]["sha"]

    return [], None
    
def main():
    """Main function to process bug reports from JSON file and match them to files."""
    import json
    import os
    
    json_file = "hacken/filtered_[SCA]LitLabGames_GameFI_Mar2023.json"
    
    # Get GitHub API key
    api_key = os.getenv('GITHUB_API_KEY')
    if not api_key:
        print("Error: GITHUB_API_KEY environment variable is not set")
        print("Please set your GitHub API token: export GITHUB_API_KEY=your_token_here")
        return None
    
    # Get all relevant files from the GitHub URLs in the JSON (now returns a dict)
    relevant_files_dict = get_relevant_files(json_file)
    
    # If we only have one or zero relevant files, no work needs to be done
    if len(relevant_files_dict) <= 1:
        return relevant_files_dict
    
    print("Relevant files by report:")
    for report_title, files in relevant_files_dict.items():
        print(f"  {report_title}: {len(files)} files")
    
    # Load the JSON to process each report
    with open(json_file, 'r') as f:
        reports = json.load(f)
    
    if not isinstance(reports, list):
        reports = [reports]  # Handle single report case
    
    all_matches = {}
    summary_results = []  # Store top results for final summary
    
    # Process each report
    for i, report in enumerate(reports):
        report_title = report.get('title', f'Report_{i+1}')
        report_id = report.get('id', f'ID_{i+1}')
        
        # Get the relevant files for this specific report
        report_relevant_files = relevant_files_dict.get(report_title, [])
            
        print(f"\nProcessing {len(report_relevant_files)} files for: {report_title}")
        
        # Convert list to set for the matching function
        report_relevant_files_set = set(report_relevant_files)
        
        # Find files that match this specific report
        matched_files = match_bug_to_files(report, report_relevant_files_set, api_key)

        if not matched_files and report.get("source", ""):
            print(f"\n⚠️ No relevant files found for {report_title}, walking commit history...")
            source_url = report.get("source", "")
            matched_files, fix_commit = find_files_up_commit_history(report, source_url, api_key)
            if matched_files:
                report["fix_commit_url"] = fix_commit
            all_matches[report_title] = matched_files or []
            
            # Add to summary (even if no matches)
            top_match = matched_files[0] if matched_files else None
            summary_results.append({
                'id': report_id,
                'title': report_title,
                'severity': report.get('severity', 'Unknown'),
                'top_match': top_match,
                'from_commit_history': True
            })
            continue
        
        # Store results
        all_matches[report_title] = matched_files
        
        # Add top result to summary
        top_match = matched_files[0] if matched_files else None
        summary_results.append({
            'id': report_id,
            'title': report_title,
            'severity': report.get('severity', 'Unknown'),
            'top_match': top_match,
            'from_commit_history': False
        })
        
        # Print top matches for this report
        print(f"\nTop matches for: {report_title}")
        print("-" * 50)
        
        top_matches = matched_files[:5]  # Show top 5
        if not top_matches:
            print("No matching files found.")
        else:
            for j, match in enumerate(top_matches):
                print(f"{j+1}. {match['file_path']} (Score: {match['total_score']:.1f})")
                print(f"   Reasons: {', '.join(match['match_reasons'])}")
                
                # Extract and display function names for top match
                if j == 0:  # Only for the top match to avoid too many API calls
                    try:
                        functions = extract_function_names(match['file_path'])
                        if functions:
                            print(f"   Functions: {', '.join(functions[:5])}")  # Show first 5
                    except Exception as e:
                        print(f"   Could not extract functions: {e}")
                
                print(f"   URL: {match['blob_url']}")
                print()
    
    # Enhanced Summary Section
    print(f"\n{'='*80}")
    print("FINAL SUMMARY - TOP MATCHES FOR EACH BUG REPORT")
    print(f"{'='*80}")
    
    # Header
    print(f"{'ID':<8} {'Severity':<12} {'Title':<35} {'File Match':<30} {'Score':<8}")
    print("-" * 80)
    
    # Results
    total_reports = len(summary_results)
    successful_matches = 0
    
    for result in summary_results:
        report_id = str(result['id'])[:7]  # Truncate long IDs
        severity = result['severity'][:11]  # Truncate long severities
        title = result['title'][:34] + '...' if len(result['title']) > 34 else result['title']
        
        if result['top_match']:
            successful_matches += 1
            file_path = result['top_match']['file_path']
            file_name = file_path.split('/')[-1][:29]  # Get filename, truncate if needed
            score = f"{result['top_match']['total_score']:.1f}"
            
            # Add indicator for commit history matches
            if result['from_commit_history']:
                file_name += " *"
            
            print(f"{report_id:<8} {severity:<12} {title:<35} {file_name:<30} {score:<8}")
        else:
            print(f"{report_id:<8} {severity:<12} {title:<35} {'NO MATCH FOUND':<30} {'N/A':<8}")
    
    # Statistics
    print(f"\n{'='*80}")
    print(f"STATISTICS:")
    print(f"  Total Reports Processed: {total_reports}")
    print(f"  Successful Matches: {successful_matches}")
    print(f"  Match Rate: {(successful_matches/total_reports)*100:.1f}%")
    
    if any(result['from_commit_history'] for result in summary_results):
        commit_matches = sum(1 for result in summary_results if result['from_commit_history'] and result['top_match'])
        print(f"  Matches from Commit History: {commit_matches} (marked with *)")
    
    print(f"{'='*80}")
    
    # Detailed breakdown by severity (if available)
    severity_stats = {}
    for result in summary_results:
        severity = result['severity']
        if severity not in severity_stats:
            severity_stats[severity] = {'total': 0, 'matched': 0}
        severity_stats[severity]['total'] += 1
        if result['top_match']:
            severity_stats[severity]['matched'] += 1
    
    if len(severity_stats) > 1:
        print("\nBreakdown by Severity:")
        for severity, stats in severity_stats.items():
            rate = (stats['matched'] / stats['total']) * 100 if stats['total'] > 0 else 0
            print(f"  {severity}: {stats['matched']}/{stats['total']} ({rate:.1f}%)")
    
    return all_matches


if __name__ == "__main__":
    # Note: You may need to install required packages if not already installed
    # pip install fuzzywuzzy python-levenshtein requests
    # Also set your GitHub API key: export GITHUB_API_KEY=your_token_here
    
    matches = main()
    print(matches)