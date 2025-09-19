import json
from multiprocessing import context
import re
import os
from pathlib import Path
from typing import List, Dict, Set, Tuple
from fuzzywuzzy import fuzz
from github_analysis_scripts.determine_relevant_files import get_relevant_files, process_fix_url, process_source_url, find_file_before_change
from github_file_retrieval_scripts.retrieve_all_smart_contract_functions import extract_function_names
from github_analysis_scripts.match_files_to_report_with_heuristics import match_bug_to_files
from github_analysis_scripts.match_files_to_report_with_AI import VulnerabilityFileMatcher
from code_context_scripts.analyze_valid_code_snippets import VulnerabilityAnalyzer
from code_context_scripts.github_retrieve_code_context import GitHubCodeAnalyzer
import requests
import time
from urllib.parse import urlparse, unquote

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

GITHUB_API_KEY = os.getenv("GITHUB_API_KEY")

SMART_CONTRACT_EXTENSIONS = (
        '.sol', '.tsol', '.vy', '.rs', '.move', '.cairo', '.fc', '.func', '.circom'
    )

def parse_github_url(github_url: str) -> Dict:
    """Parse GitHub URL and extract components."""
    url = github_url.rstrip('/').replace('.git', '')
    parsed = urlparse(url)
    path = parsed.path.lstrip('/')
    
    path_parts = path.split('/')
    if len(path_parts) < 2:
        raise ValueError(f"Invalid GitHub URL format: {github_url}")
    
    owner = path_parts[0]
    repo = path_parts[1]
    branch = 'main'  # Default
    subpath = ''
    
    # Handle tree URLs
    if len(path_parts) > 2 and path_parts[2] == 'tree':
        if len(path_parts) > 3:
            branch = unquote(path_parts[3])
            if len(path_parts) > 4:
                subpath = '/'.join(path_parts[4:])
    
    return owner, repo, branch, subpath


def find_files_up_commit_history(report, source_url, max_commits=5):
    """
    Walks up the commit history starting from the given source_url,
    checking each commit for relevant file changes until a match is found.
    """
    try:
        owner, repo, branch, path = parse_github_url(source_url)
    except Exception as e:
        print(f"Error parsing GitHub URL: {e}")
        return [], None
        
    headers = {"Authorization": f"token {GITHUB_API_KEY}"}
    
    # Get commits for the entire repo, not just a specific path
    commits_url = f"https://api.github.com/repos/{owner}/{repo}/commits"
    params = {"sha": branch, "per_page": 10}  # Get more commits per request
    
    current_sha = branch
    
    for i in range(max_commits):
        params["sha"] = current_sha
        resp = requests.get(commits_url, headers=headers, params=params)
        
        if resp.status_code == 403:  # Rate limit
            print("Rate limit exceeded, waiting...")
            time.sleep(300)
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
            matched_files = match_bug_to_files(report, set(changed_files), GITHUB_API_KEY)
            if matched_files:
                return matched_files, commit_url

        # Move to next batch of commits
        if len(commits) < 10:  # No more commits
            break
        current_sha = commits[-1]["sha"]

    return [], None

def validate_api_keys():
    """Validate that GitHub API key is available."""
    
    if not GITHUB_API_KEY:
        print("Error: GITHUB_API_KEY environment variable is not set")
        print("Please set your GitHub API token: export GITHUB_API_KEY=your_token_here")
        raise ValueError("GITHUB_API_KEY environment variable is required")


    if not OPENAI_API_KEY:
        print("Error: OPENAI_API_KEY environment variable is not set")
        print("Please set your GitHub API token: export OPENAI_API_KEY=your_token_here")
        raise ValueError("OPENAI_API_KEY environment variable is required")


def normalize_reports_data(reports):
    """Ensure reports data is in list format."""
    if not isinstance(reports, list):
        reports = [reports]  # Handle single report case
    return reports


def create_single_file_match(report, single_file_url, report_id):
    """Create match result for reports with only one relevant file."""
    from pathlib import Path
    
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
    
    return matched_files


def process_commit_history_matching(report):
    """Handle matching for reports with no relevant files by checking commit history."""
    source_url = report.get("source_code_url", "") or report.get("fix_commit_url", "")
    if not source_url:
        return None, None
    
    print(f"  ⚠️ No relevant files found for {source_url}, walking commit history...")
    matched_files, fix_commit = find_files_up_commit_history(report, source_url)
    
    if matched_files and fix_commit:
        report["fix_commit_url"] = fix_commit
    
    return matched_files, fix_commit




def check_single_positive_match(matched_files):
    """
    Check if there's only one match with a positive score and all others are 0.
    If so, return that match as the only result (even if below normal threshold).
    """
    if not matched_files or len(matched_files) < 2:
        return matched_files
    
    # Find matches with positive scores
    positive_matches = [match for match in matched_files if match['total_score'] > 0]
    zero_matches = [match for match in matched_files if match['total_score'] == 0]
    
    # If exactly one positive match and all others are zero
    if len(positive_matches) == 1 and len(zero_matches) == len(matched_files) - 1:
        single_match = positive_matches[0]
        original_score = single_match['total_score']
        
        # Add a note about why this match was selected
        single_match['match_reasons'].append(f'Single positive match among all candidates (score: {original_score:.1f})')
        
        print(f"  ✓ Selected single positive match: {single_match['file_path']} (score: {original_score:.1f}, all others scored 0)")
        
        return [single_match]  # Return only the single positive match
    
    return matched_files


def assign_afflicted_blob_url(report, high_confidence_matches):
    """
    Assign afflicted_github_code_blob:
    - Always consider the top match for score
    - Include subsequent matches only if within 40 points of top total_score
    - Always include any match scoring over 600
    - Only include matches with a valid blob_url
    """
    report['afflicted_github_code_blob'] = []

    if not high_confidence_matches:
        return

    # Sort descending by total_score
    sorted_matches = sorted(high_confidence_matches, key=lambda m: m.get("total_score", 0), reverse=True)

    top_score = sorted_matches[0].get("total_score", 0)

    selected = []
    for m in sorted_matches:
        score = m.get("total_score", 0)
        blob_url = m.get("blob_url")
        if not blob_url:
            continue

        # Include if within 40 points of top OR score > 600
        if top_score - score <= 40 or score > 600:
            selected.append(blob_url)
        else:
            break  # stop as soon as difference > 40 and score <= 600

    report['afflicted_github_code_blob'] = selected



def create_summary_result(report_id, report_title, report, top_match):
    """Create a summary result entry for reporting."""
    return {
        'id': report_id,
        'title': report_title,
        'severity': report.get('severity', 'Unknown'),
        'top_match': top_match,
    }


def print_match_results(report_title, matched_files, high_confidence_matches):
    """Print the matching results for a report."""
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
        _print_high_confidence_matches(high_confidence_matches)


def _print_high_confidence_matches(high_confidence_matches):
    """Print detailed information about high-confidence matches."""
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


def save_updated_reports(json_file, reports):
    """Save the updated reports with afflicted_github_code_blob fields back to JSON."""
    import json
    from pathlib import Path
    
    json_path = Path(json_file)
    json_dir = json_path.parent
    print(f"Using pathlib - parent dir: {json_dir}")
    print(f"Parent dir exists (pathlib): {json_dir.exists()}")
    
    if json_dir != Path('.'):  # Only create directory if there's a path
        print(f"Creating directory: {json_dir}")
        json_dir.mkdir(parents=True, exist_ok=True)
    
    # Try the write operation
    print(f"Attempting to write {len(reports)} reports...")
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(reports, f, indent=2)
    
    print(f"✓ Successfully wrote file")
    print(f"✓ Updated JSON with afflicted_github_code_blob fields saved to: {json_file}")


def print_summary_header():
    """Print the summary section header."""
    print(f"\n{'='*80}")
    print("FINAL SUMMARY - HIGH CONFIDENCE MATCHES ONLY (150+ SCORE)")
    print(f"{'='*80}")
    print(f"{'ID':<8} {'Severity':<12} {'Title':<35} {'File Match':<30} {'Score':<8}")
    print("-" * 80)


def print_summary_row(result):
    """Print a single row in the summary table."""
    report_id = str(result['id'])[:7]  # Truncate long IDs
    severity = result['severity'][:11]  # Truncate long severities
    title = result['title'][:34] + '...' if len(result['title']) > 34 else result['title']
    
    if result['top_match']:
        top_match = result["top_match"]
        file_name = top_match.file_path.split('/')[-1][:29]  # Get filename, truncate if needed
        score = f"{top_match.total_score:.1f}"
        
        
        print(f"{report_id:<8} {severity:<12} {title:<35} {file_name:<30} {score:<8}")
    else:
        print(f"{report_id:<8} {severity:<12} {title:<35} {'NO HIGH CONF MATCH':<30} {'N/A':<8}")


def print_statistics(summary_results):
    """Print overall statistics about the matching process."""
    total_reports = len(summary_results)
    successful_matches = sum(1 for result in summary_results if result['top_match'])
    
    print(f"\n{'='*80}")
    print(f"STATISTICS:")
    print(f"  Total Reports Processed: {total_reports}")
    print(f"  High Confidence Matches (≥150): {successful_matches}")
    print(f"  No High Confidence Matches: {total_reports - successful_matches}")
    print(f"  High Confidence Rate: {(successful_matches/total_reports)*100:.1f}%")
    print(f"{'='*80}")


def print_severity_breakdown(summary_results):
    """Print breakdown of matches by severity level."""
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


def print_blob_assignment_summary(reports):
    """Print summary of afflicted_github_code_blob assignments."""
    blob_assignments = sum(1 for report in reports if report.get('afflicted_github_code_blob'))
    print(f"\nBLOB URL ASSIGNMENTS:")
    print(f"  Reports with afflicted_github_code_blob assigned: {blob_assignments}/{len(reports)}")
    print(f"  Assignment rate: {(blob_assignments/len(reports))*100:.1f}%")


def print_final_summary(all_matches):
    """Print the final count of returned matches."""
    total_returned_matches = sum(len(matches) for matches in all_matches.values())
    print(f"\nTOTAL HIGH CONFIDENCE MATCHES RETURNED: {total_returned_matches}")


MAX_FILES_TO_CHECK = 20
MAX_FIELD_LENGTH = 1000

def truncate_field(value, default, max_len=MAX_FIELD_LENGTH):
    """Return string value truncated to max_len, or default if None."""
    val = value if value is not None else default
    return str(val)[:max_len]

def extract_report_fields(report, i):
    """Extract and normalize all fields from a report dynamically."""
    fields = {}
    for key, value in report.items():
        # Use key-based default like Report_{i+1}, ID_{i+1}, etc.
        default_value = f'{key}_{i+1}' if value is None else ''
        fields[key] = truncate_field(value, default_value)
    return fields

def should_use_ai(report, relevant_files):
    """Decide whether to use AI first, based on URLs and number of files."""
    if report.get("fix_commit_url") and len(relevant_files) < MAX_FILES_TO_CHECK:
        return "fix_commit"
    elif report.get("source_code_url") and len(relevant_files) < MAX_FILES_TO_CHECK:
        return "source_code"
    return None

MIN_HEURISTICS_THRESHOLD = 20

def filter_high_confidence_matches(matched_files, threshold=MIN_HEURISTICS_THRESHOLD):
    """Filter matches to only include those above the confidence threshold.
    If only one file scored above 0, include it regardless of threshold."""
    if not matched_files:
        return []
    
    # Check if there's only one file with a positive score
    positive_matches = [match for match in matched_files if match['total_score'] > 0]
    
    # If only one positive match, return it regardless of threshold
    if len(positive_matches) == 1:
        single_match = positive_matches[0]
        if single_match['total_score'] < threshold:
            # Add a note that this was included despite being below threshold
            if 'Single positive match among all candidates' not in single_match.get('match_reasons', []):
                single_match['match_reasons'] = single_match.get('match_reasons', []) + [f'Only file with positive score ({single_match["total_score"]:.1f})']
        return [single_match["blob_url"]]
    
    # Otherwise, apply normal threshold filtering
    return [match["blob_url"] for match in matched_files if match['total_score'] >= threshold]

def run_heuristics_matching(report, relevant_files):
    """Run heuristics matching pipeline with confidence filtering."""
    relevant_files_set = set(relevant_files)
    matched_files = match_bug_to_files(report, relevant_files_set, GITHUB_API_KEY)

    high_confidence_matches = filter_high_confidence_matches(matched_files)
    if matched_files and not high_confidence_matches:
        print(f"  ⚠️ Found {len(matched_files)} matches but none scored above the threshold"
              f"Highest score: {matched_files[0]['total_score']:.1f}")

    #assign_afflicted_blob_url(report, high_confidence_matches)
    #print_match_results(report["title"], matched_files, high_confidence_matches)
    return high_confidence_matches

def process_single_report(report, i, relevant_files_dict):
    """Process a single bug report and return match results."""

    # Extract normalized fields
    fields = extract_report_fields(report, i)
    report.update(fields)  # overwrite with truncated values

    # Get relevant files
    relevant_files = relevant_files_dict.get(fields["title"], [])
    print(f"\nProcessing report: {fields['title']}")
    print(f"Found {len(relevant_files)} relevant files")

    #Run heuristics matching to determine relevant files before processing with AI
    #heuristics_processed_files = run_heuristics_matching(report, relevant_files)
    print(heuristics_processed_files)
    print(f"Heuristics Matching returned {len(heuristics_processed_files)}, now using GPT4.1")

    # Decide strategy
    ai_strategy = should_use_ai(report, heuristics_processed_files)
    
    if ai_strategy == "fix_commit":

        #Use AI to check files that were returned by heuristics matching 
        if heuristics_processed_files:
            matcher = VulnerabilityFileMatcher(OPENAI_API_KEY, GITHUB_API_KEY)
            matches = matcher.process_files(fields, heuristics_processed_files)

            #No High Confidance Match? Check all smart contract files in repo in case the commit/pull is wrong
            if not matches:
                relevant_files = process_fix_url(report.get("fix_commit_url"), False)
                matcher = VulnerabilityFileMatcher(OPENAI_API_KEY, GITHUB_API_KEY)
                matches = matcher.process_files(fields, relevant_files)
        
        #No Heuristics matched files? default to AI to check them all
        else:
            relevant_files = process_fix_url(report.get("fix_commit_url"), False)
            matcher = VulnerabilityFileMatcher(OPENAI_API_KEY, GITHUB_API_KEY)
            matches = matcher.process_files(fields, relevant_files)

        #Still no high confidance matches? Return empty
        if not matches:
            return []

        else:
            #Commit url isn't necessary the one where the file was changed
            #Determine the commit where the file was changed
            for match in matches:
                fix_commit_url = report.get("fix_commit_url", "")
                if any(keyword in fix_commit_url for keyword in ["tree", "compare", "commit"]):
                    # Call the renamed function
                    original_blob_url = find_file_before_change(fix_commit_url, match.blob_url)
                    
                    # Only update if we found a valid result
                    if original_blob_url and original_blob_url != "NEW FILE":
                        match.blob_url = original_blob_url
            return matches

    elif ai_strategy == "source_code":

        if heuristics_processed_files:
            matcher = VulnerabilityFileMatcher(OPENAI_API_KEY, GITHUB_API_KEY)
            matches = matcher.process_files(fields, heuristics_processed_files)

            if not matches:
                relevant_files = process_source_url(report.get("source_code_url"))
                matcher = VulnerabilityFileMatcher(OPENAI_API_KEY, GITHUB_API_KEY)
                matches = matcher.process_files(fields, relevant_files)

        else:
            relevant_files = process_source_url(report.get("source_code_url"))
            matcher = VulnerabilityFileMatcher(OPENAI_API_KEY, GITHUB_API_KEY)
            matches = matcher.process_files(fields, relevant_files)

        if not matches:
            return []

        else: 
            return matches

    else:
        return []

def analyze_relevant_files(json_file):
    """Main function to process bug reports from JSON file and match them to files."""
    print(json_file)

    validate_api_keys()

    #Retrieve relevant code context from afflicted blobs to train AI
    github_source_code_analyzer = GitHubCodeAnalyzer(GITHUB_API_KEY, OPENAI_API_KEY)

    #Determine if broken/fixed code snippets have enough context to train AI
    code_snippet_analyzer =  VulnerabilityAnalyzer(OPENAI_API_KEY, "gpt-4.1-mini")

    # Get all relevant files AND the reports data from the JSON
    relevant_files_dict, reports = get_relevant_files(json_file)
        
    # Normalize reports data
    reports = normalize_reports_data(reports)
    
    all_matches = {}
    summary_results = []  # Store top results for final summary
    
    # Process each report
    for i, report in enumerate(reports):

        # ✅ Just get code context if afflicted_github_code_blob already exists and is non-empty
        if report.get("afflicted_github_code_blob"):
            print(f"Report {report.get('id', i)} already has afflicted_github_code_blob, retrieving context")
            report = github_source_code_analyzer.process_json_object(report)
            continue

        # ✅ Check if report has a source_code_url field
        source_code_url = report.get("source_code_url")
        afflicted_code_blobs = []

        #If source code url is already in blob form
        if source_code_url:
            # Handle both string and list cases
            urls_to_check = source_code_url if isinstance(source_code_url, list) else [source_code_url]

            for url in urls_to_check:
                if isinstance(url, str) and "github.com" in url and "/blob/" in url:
                    afflicted_code_blobs.append(url)

            if afflicted_code_blobs:
                # Assign afflicted_github_code_blob and skip normal processing
                report["afflicted_github_code_blob"] = afflicted_code_blobs
                print("Source code is already github blob")
                
                #Get context from blob files
                report = github_source_code_analyzer.process_json_object(report)
                continue  # Skip the normal matching logic

        # Process the individual report and get all github blobs
        matched_files = process_single_report(
            report, i, relevant_files_dict
        )

        #If no github source blob
        if not matched_files:
            #Validate just the broken/fixed snippet fields if they exist
            report, _ = code_snippet_analyzer.process_json_object(report)
            continue
        
        report_title = report.get('title', f'Report_{i+1}')
        report_id = report.get('id', f'ID_{i+1}')

        # Store results
        all_matches[report_title] = matched_files
        
        # Add to summary
        summary_result = create_summary_result(
            report_id, report_title, report, all_matches[report_title][0], 
        )
        summary_results.append(summary_result)

        afflicted_code_blobs = []
        for match in all_matches[report_title]:
            afflicted_code_blobs.append(match.blob_url)
        report["afflicted_github_code_blob"] = afflicted_code_blobs

        #If github source blob is generated, pull relevant context from blob sources
        if report["afflicted_github_code_blob"]:
            report = github_source_code_analyzer.process_json_object(report)
    
    # Save updated JSON
    save_updated_reports(json_file, reports)
    
    # Print comprehensive summary
    print_summary_header()
    
    if summary_results:
        # Print each result row
        for result in summary_results:
            print_summary_row(result)
        
        # Print statistics
        print_statistics(summary_results)
        print_severity_breakdown(summary_results)
        print_blob_assignment_summary(reports)
        print_final_summary(all_matches)
        
    return all_matches  # Returns ONLY high confidence matches



def main():
    script_dir = os.path.dirname(os.path.realpath(__file__))
    
    # Use the CORRECT filename (note "copy.json" instead of ".json")
    json_file = "/mnt/d/golden_dataset/bailsec/filtered_Bailsec - Defi Money Fee Module - Final Report.json"
    
    analyze_relevant_files(json_file)
    #json_file = "veridise/filtered_VAR_SmoothCryptoLib_240718_V3-findings.json"
    #json_file = "veridise/filtered_VAR-Untangled-250508-vaults-V2-findings.json"
        

if __name__ == "__main__":
    # Note: You may need to install required packages if not already installed
    # pip install fuzzywuzzy python-levenshtein requests
    # Also set your GitHub API key: export GITHUB_API_KEY=your_token_here
    
    # Run your main function and get file matches
    all_matches = main()

    # # Get just the file names (what you see in File Match column)
    # matched_files = []
    # for report_title, matches in all_matches.items():
    #     if matches:  # Only high confidence matches are in all_matches
    #         matched_files.append(matches[0]['file_name'])  # Top match

    print("Matched Files:", all_matches)