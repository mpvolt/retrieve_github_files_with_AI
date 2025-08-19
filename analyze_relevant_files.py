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

def find_files_up_commit_history(report, source_url, api_key, max_commits=5):
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
    
def analyze_relevant_files(json_file):
    """Main function to process bug reports from JSON file and match them to files."""
    import json
    import os
    

    # Get GitHub API key
    api_key = os.getenv('GITHUB_API_KEY')
    if not api_key:
        print("Error: GITHUB_API_KEY environment variable is not set")
        print("Please set your GitHub API token: export GITHUB_API_KEY=your_token_here")
        return None
    
    # Get all relevant files from the GitHub URLs in the JSON (now returns a dict)
    relevant_files_dict = get_relevant_files(json_file)
    
    # Check if we have minimal files to process
    total_files = sum(len(files) for files in relevant_files_dict.values())
    if total_files <= 1:
        print(f"Only {total_files} total files found across all reports. No matching needed.")
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
            
        print(f"\nProcessing report: {report_title}")
        print(f"Found {len(report_relevant_files)} relevant files")
        
        # Initialize the afflicted_github_code_blob field
        report['afflicted_github_code_blob'] = None
        
        # If only 1 file, skip matching and use it directly
        if len(report_relevant_files) == 1:
            single_file_url = report_relevant_files[0]
            file_path = single_file_url
            file_name = Path(file_path).name
            
            print(f"  → Only 1 file found, using directly: {file_path}")
            
            # Create a simplified match result
            matched_files = [{
                'file_path': file_path,
                'file_name': file_name,
                'blob_url': single_file_url,
                'total_score': 100.0,  # Perfect score since it's the only option
                'match_reasons': ['Only relevant file found'],
                'score_breakdown': {'single_file': 100.0},
                'bug_id': report_id
            }]
            
            # Set the afflicted_github_code_blob field for this report
            report['afflicted_github_code_blob'] = single_file_url
            
            all_matches[report_title] = matched_files
            
            # Add to summary
            summary_results.append({
                'id': report_id,
                'title': report_title,
                'severity': report.get('severity', 'Unknown'),
                'top_match': matched_files[0],
                'from_commit_history': False,
                'single_file_match': True
            })
            continue
        
        # If no files found, check commit history
        if not report_relevant_files and report.get("source", ""):
            print(f"  ⚠️ No relevant files found, walking commit history...")
            source_url = report.get("source", "")
            matched_files, fix_commit = find_files_up_commit_history(report, source_url, api_key)
            if matched_files:
                report["fix_commit_url"] = fix_commit
                # Set the afflicted_github_code_blob field for commit history matches
                if matched_files[0]['total_score'] >= 150.0:
                    report['afflicted_github_code_blob'] = matched_files[0]['blob_url']
            
            # Filter to only high-confidence matches for storage
            high_confidence_matches = [match for match in (matched_files or []) if match['total_score'] >= 150.0]
            all_matches[report_title] = high_confidence_matches
            
            # Add to summary (even if no matches)
            top_match = high_confidence_matches[0] if high_confidence_matches else None
            summary_results.append({
                'id': report_id,
                'title': report_title,
                'severity': report.get('severity', 'Unknown'),
                'top_match': top_match,
                'from_commit_history': True,
                'single_file_match': False
            })
            continue
        
        # Multiple files - do full matching process
        print(f"  → Running full matching process for {len(report_relevant_files)} files")
        
        # Convert list to set for the matching function
        report_relevant_files_set = set(report_relevant_files)
        
        # Find files that match this specific report
        matched_files = match_bug_to_files(report, report_relevant_files_set, api_key)
        
        # Filter to only high-confidence matches (150+ score)
        high_confidence_matches = [match for match in matched_files if match['total_score'] >= 150.0]
        
        if matched_files and not high_confidence_matches:
            print(f"  ⚠️ Found {len(matched_files)} matches but none scored 150+. Highest score: {matched_files[0]['total_score']:.1f}")
        
        # Set the afflicted_github_code_blob field if we have a high-confidence match
        if high_confidence_matches:
            report['afflicted_github_code_blob'] = high_confidence_matches[0]['blob_url']
        
        # Store results (only high-confidence matches)
        all_matches[report_title] = high_confidence_matches
        
        # Add top result to summary
        top_match = high_confidence_matches[0] if high_confidence_matches else None
        summary_results.append({
            'id': report_id,
            'title': report_title,
            'severity': report.get('severity', 'Unknown'),
            'top_match': top_match,
            'from_commit_history': False,
            'single_file_match': False
        })
        
        # Print top matches for this report
        print(f"\nTop matches for: {report_title}")
        print("-" * 50)
        
        if not matched_files:
            print("No matching files found.")
        elif not high_confidence_matches:
            print(f"Found {len(matched_files)} matches but none met the 150+ score threshold.")
            print("Top candidates (below threshold):")
            for j, match in enumerate(matched_files[:3]):  # Show top 3 low-confidence matches
                print(f"  {j+1}. {match['file_path']} (Score: {match['total_score']:.1f}) - BELOW THRESHOLD")
        else:
            print(f"High-confidence matches (150+ score):")
            for j, match in enumerate(high_confidence_matches[:5]):  # Show top 5 high-confidence
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
    
    # Save the updated reports back to the JSON file
    output_file = json_file.replace('.json')
    with open(output_file, 'w') as f:
        json.dump(reports, f, indent=2)
    print(f"\n✓ Updated JSON with afflicted_github_code_blob fields saved to: {output_file}")
    
    # Enhanced Summary Section
    print(f"\n{'='*80}")
    print("FINAL SUMMARY - HIGH CONFIDENCE MATCHES ONLY (150+ SCORE)")
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
            
            # Add indicators for special match types
            if result['from_commit_history']:
                file_name += " *"
            elif result.get('single_file_match', False):
                file_name += " ¹"
            
            print(f"{report_id:<8} {severity:<12} {title:<35} {file_name:<30} {score:<8}")
        else:
            print(f"{report_id:<8} {severity:<12} {title:<35} {'NO HIGH CONF MATCH':<30} {'N/A':<8}")
    
    # Statistics
    print(f"\n{'='*80}")
    print(f"STATISTICS:")
    print(f"  Total Reports Processed: {total_reports}")
    print(f"  High Confidence Matches (≥150): {successful_matches}")
    print(f"  No High Confidence Matches: {total_reports - successful_matches}")
    print(f"  High Confidence Rate: {(successful_matches/total_reports)*100:.1f}%")
    
    if any(result['from_commit_history'] for result in summary_results):
        commit_matches = sum(1 for result in summary_results if result['from_commit_history'] and result['top_match'])
        print(f"  High Confidence from Commit History: {commit_matches} (marked with *)")
    
    if any(result.get('single_file_match', False) for result in summary_results):
        single_file_matches = sum(1 for result in summary_results if result.get('single_file_match', False))
        print(f"  Single File Auto-Matches: {single_file_matches} (marked with ¹)")
    
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
        print("\nBreakdown by Severity (High Confidence Only):")
        for severity, stats in severity_stats.items():
            rate = (stats['matched'] / stats['total']) * 100 if stats['total'] > 0 else 0
            print(f"  {severity}: {stats['matched']}/{stats['total']} ({rate:.1f}%)")
    
    # Print summary of afflicted_github_code_blob assignments
    blob_assignments = sum(1 for report in reports if report.get('afflicted_github_code_blob'))
    print(f"\nBLOB URL ASSIGNMENTS:")
    print(f"  Reports with afflicted_github_code_blob assigned: {blob_assignments}/{len(reports)}")
    print(f"  Assignment rate: {(blob_assignments/len(reports))*100:.1f}%")
    
    # Print final count of returned matches
    total_returned_matches = sum(len(matches) for matches in all_matches.values())
    print(f"\nTOTAL HIGH CONFIDENCE MATCHES RETURNED: {total_returned_matches}")
    
    return all_matches  # Returns ONLY high confidence matches (150+ score)

def main():
    json_file = "hacken/filtered_[SCA]LitLabGames_GameFI_Mar2023.json"

    analyze_relevant_files(json_file)
    #json_file = "veridise/filtered_VAR_SmoothCryptoLib_240718_V3-findings.json"
    #json_file = "veridise/filtered_VAR-Untangled-250508-vaults-V2-findings.json"
        

if __name__ == "__main__":
    # Note: You may need to install required packages if not already installed
    # pip install fuzzywuzzy python-levenshtein requests
    # Also set your GitHub API key: export GITHUB_API_KEY=your_token_here
    
    # Run your main function and get file matches
    all_matches = main()

    # Get just the file names (what you see in File Match column)
    matched_files = []
    for report_title, matches in all_matches.items():
        if matches:  # Only high confidence matches are in all_matches
            matched_files.append(matches[0]['file_name'])  # Top match

    print("Matched Files:", matched_files)