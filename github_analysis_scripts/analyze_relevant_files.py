import json
from multiprocessing import context
import re
import os
from pathlib import Path
from typing import List, Dict, Set, Tuple
from fuzzywuzzy import fuzz
from github_analysis_scripts.determine_relevant_files import determine_relevant_files, process_fix_url, process_source_url, find_file_before_change
from github_analysis_scripts.match_files_to_report_with_heuristics import match_bug_to_files
from github_analysis_scripts.match_files_to_report_with_AI import VulnerabilityFileMatcher
import requests
import time
from urllib.parse import urlparse, unquote
from config import SMART_CONTRACT_EXTENSIONS, SMART_CONTRACT_LANGUAGES

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

GITHUB_API_KEY = os.getenv("GITHUB_API_KEY")

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
    if isinstance(top_match, list):
        top_match = top_match[0]
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
    
    # Extract and format basic fields
    report_id = str(result.get('id', 'N/A'))[:7]
    severity = result.get('severity', 'Unknown')[:11]
    title = result.get('title', 'No title')
    title_display = (title[:34] + '...') if len(title) > 34 else title[:35]
    
    # Extract filename and score from top_match
    file_match = "No match"
    score = "N/A"
    
    if result.get("top_match"):
        top_match = result["top_match"]
        
        # Parse the string to extract URL
        if isinstance(top_match, str):
            import re
            urls = re.findall(r'https://github\.com/[^\s\'\]]+', top_match)
            if urls:
                # Extract just the filename from the URL
                filename = urls[0].split('/')[-1]
                file_match = filename[:29] if len(filename) <= 29 else filename[:26] + '...'
        elif isinstance(top_match, list) and top_match:
            filename = str(top_match[0]).split('/')[-1]
            file_match = filename[:29] if len(filename) <= 29 else filename[:26] + '...'
    
    # Get score if available
    if result.get("score"):
        score = str(result["score"])
    elif result.get("top_match_score"):
        score = str(result["top_match_score"])
    
    # Print formatted row matching header alignment
    print(f"{report_id:<8} {severity:<12} {title_display:<35} {file_match:<30} {score:<8}")

# Alternative: Simple table format without colors
def print_summary_row_simple(result):
    """Print a single row in a simple table format."""
    
    report_id = str(result.get('id', 'N/A'))[:12]
    severity = result.get('severity', 'Unknown')[:10]
    title = result.get('title', 'No title')
    title_display = (title[:45] + '...') if len(title) > 45 else title
    
    # Extract filename from top_match
    top_match_file = "No match"
    if result.get("top_match"):
        top_match = result["top_match"]
        if isinstance(top_match, str):
            import re
            urls = re.findall(r'https://[^\s\'\]]+', top_match)
            if urls:
                top_match_file = urls[0].split('/')[-1][:25]
        elif isinstance(top_match, list) and top_match:
            top_match_file = str(top_match[0]).split('/')[-1][:25]
    
    # Print as a clean table row
    print(f"{report_id:<13} | {severity:<10} | {top_match_file:<26} | {title_display}")

# Alternative: Compact format
def print_summary_row_compact(result):
    """Print in a compact, readable format."""
    
    report_id = result.get('id', 'N/A')
    severity = result.get('severity', 'Unknown')
    title = result.get('title', 'No title')
    
    # Extract clean filename
    match_file = "No match found"
    if result.get("top_match"):
        import re
        top_match = str(result["top_match"])
        urls = re.findall(r'https://github\.com/[^\s\'\]]+', top_match)
        if urls:
            # Get repo/file path
            parts = urls[0].replace('https://github.com/', '').split('/')
            if len(parts) >= 5:
                match_file = f"{parts[0]}/{parts[1]}/.../{parts[-1]}"
    
    print(f"\n[{severity.upper()}] {report_id}")
    print(f"  Title: {title}")
    print(f"  Match: {match_file}")
    print("-" * 80)



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
        if result.get("top_match"):
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


MAX_FIELD_LENGTH = 1000

def truncate_field(value, default, max_len=MAX_FIELD_LENGTH):
    """Return value truncated to max_len if it's a string; use default if None."""
    if value is None:
        return default
    if isinstance(value, str):
        return value[:max_len]
    return value  # leave lists, dicts, numbers, etc. as-is


def extract_report_fields(report, i):
    """Extract and normalize all fields from a report dynamically."""
    fields = {}
    for key, value in report.items():
        # Use key-based default only when the value is None
        default_value = f"{key}_{i+1}" if value is None else value
        fields[key] = truncate_field(value, default_value)
    return fields


def should_use_ai(report, relevant_files):
    MAX_FILES_TO_CHECK = 20
    """Decide whether to use AI first, based on URLs and number of files."""
    if report.get("source_code_url"):# and len(relevant_files) < MAX_FILES_TO_CHECK:
        return "source_code"
    elif report.get("fix_commit_url"):# and len(relevant_files) < MAX_FILES_TO_CHECK:
        return "fix_commit"   
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

def initialize_report_fields(report):
    """Ensure required fields exist in the report."""
    report.setdefault("afflicted_github_code_blob", [])
    report.setdefault("fixed_github_code_blob", [])
    report.setdefault("relevant_functions", {})
    report.setdefault("languages", [])

def handle_source_blob_urls(report):
    """Check source_code_url for direct GitHub blob references."""
    source_code_url = report.get("source_code_url")
    if not source_code_url:
        return 

    urls_to_check = source_code_url if isinstance(source_code_url, list) else [source_code_url]
    afflicted_github_code_blobs = []
    for url in urls_to_check:
        if isinstance(url, str) and "github.com" in url and "/blob/" in url:
            filename = url.strip().split("/")[-1]
            if filename and any(filename.endswith(SMART_CONTRACT_EXTENSIONS)):
                afflicted_github_code_blob.append(url)
    
    report["afflicted_github_code_blob"] = afflicted_github_code_blobs
    if report.get("afflicted_github_code_blob") and not report.get("context"):
        print("Case 2: source code url is already a blob")
        determine_relevant_functions(report)


def handle_fix_commit_blobs(report):
    """Extract fixed blobs from fix_commit_url if present."""
    fix_commit_url = report.get("fix_commit_url")
    if not fix_commit_url:
        return

    urls_to_check = fix_commit_url if isinstance(fix_commit_url, list) else [fix_commit_url]
    for url in urls_to_check:
        if isinstance(url, str) and "github.com" in url and "/blob/" in url:
            filename = url.strip().split("/")[-1]
            if filename and any(filename.endswith(SMART_CONTRACT_EXTENSIONS)):
                report["fixed_github_code_blob"].append(url)

    if report.get("fixed_github_code_blob"):
        print("Case 3: fix commit url is already a blob")



def handle_ai_strategy(report, fields, relevant_files):
    """Run AI-based processing depending on strategy, with robust error handling."""

    print("Using AI strategy")

    try:
        ai_strategy = should_use_ai(report, relevant_files)
    except Exception as e:
        print(f"[Error] Failed to determine AI strategy: {e}")
        report["ai_strategy_error"] = str(e)
        return report  # stop early since we can’t proceed

    try:
        matcher = VulnerabilityFileMatcher(OPENAI_API_KEY, GITHUB_API_KEY)
    except Exception as e:
        print(f"[Error] Failed to initialize VulnerabilityFileMatcher: {e}")
        report["matcher_init_error"] = str(e)
        return report

    try:
        if ai_strategy == "fix_commit":
            print("Using fix commit strategy")
            matches = matcher.process_files(fields, relevant_files)

            if not matches:
                print("[Info] No matches found initially, trying fix_commit_url...")
                try:
                    relevant_files = process_fix_url(report.get("fix_commit_url"), False)
                    matches = matcher.process_files(fields, relevant_files)
                except Exception as e:
                    print(f"[Error] Failed processing fix_commit_url: {e}")
                    report["fix_commit_error"] = str(e)

            fixed_code_blobs = []
            for match in matches or []:
                try:
                    fix_commit_url = report.get("fix_commit_url", "")
                    if any(k in fix_commit_url for k in ["tree", "compare", "commit"]):
                        original_blob_url = find_file_before_change(fix_commit_url, match.blob_url)
                        if original_blob_url and original_blob_url != "NEW FILE":
                            match.blob_url = original_blob_url
                            fixed_blob = matcher.construct_blob_from_ref(
                                report.get("fix_commit_url"), original_blob_url
                            )
                            fixed_code_blobs.append(fixed_blob)
                except Exception as e:
                    print(f"[Warning] Error handling match {match}: {e}")

            report["afflicted_github_code_blob"] = [m.blob_url for m in matches] if matches else []
            report["fixed_github_code_blob"] = fixed_code_blobs or []

        elif ai_strategy == "source_code":
            print("Using source code strategy")
            try:
                matches = matcher.process_files(fields, relevant_files)
                report["afflicted_github_code_blob"] = [m.blob_url for m in matches] if matches else []
            except Exception as e:
                print(f"[Error] Failed processing source_code strategy: {e}")
                report["source_code_error"] = str(e)

        else:
            print(f"[Info] No recognized AI strategy: {ai_strategy}")
            report["ai_strategy_error"] = f"Unrecognized strategy: {ai_strategy}"

    except Exception as e:
        print(f"[Critical] Unexpected error in handle_ai_strategy: {e}")
        report["general_ai_error"] = str(e)

    return report


def determine_relevant_functions(report):
    """
    Determines relevant functions from a vulnerability report with error handling.
    
    Args:
        report: Dictionary containing vulnerability report data
        
    Returns:
        dict: The report with added context, or None if critical errors occur
    """
    try:
        # Validate report input
        if not report or not isinstance(report, dict):
            print("Error: Invalid report - must be a non-empty dictionary")
            return None
        
        # Extract fields with error handling
        try:
            fields = extract_report_fields(report, 0)
            if not fields:
                print("Warning: No fields extracted from report")
                return report
        except Exception as e:
            print(f"Error extracting report fields: {e}")
            return report
        
        # Initialize matcher with error handling
        try:
            matcher = VulnerabilityFileMatcher(OPENAI_API_KEY, GITHUB_API_KEY)
        except Exception as e:
            print(f"Error initializing VulnerabilityFileMatcher: {e}")
            return report
        
        context = []
        
        # Process GitHub code blobs
        blobs = report.get("afflicted_github_code_blob", [])
        if blobs and not isinstance(blobs, list):
            print("Warning: afflicted_github_code_blob is not a list, skipping")
            blobs = []
        
        for blob in blobs:
            try:
                result = matcher.score_function_matches(fields, blob)
                
                if not result or not isinstance(result, dict):
                    print(f"Warning: Invalid result for blob, skipping")
                    continue
                
                print(f"Found {result.get('total_functions_found', 0)} functions")
                print(f"Analyzed in {result.get('total_chunks', 1)} chunks")
                
                # Extract high-risk functions safely
                functions = result.get("functions", [])
                if not isinstance(functions, list):
                    print("Warning: Functions is not a list, skipping")
                    continue
                
                high_risk_functions = [
                    func for func in functions 
                    if isinstance(func, dict) and func.get('score', 0) > 85
                ]
                
                if high_risk_functions:
                    context.append({
                        "source": blob,
                        "functions": high_risk_functions
                    })
                    
            except Exception as e:
                print(f"Error processing blob: {e}")
                continue
        
        # Process afflicted source code
        afflicted_code = report.get("afflicted_source_code")
        if afflicted_code:
            try:
                result = matcher._analyze_code_chunk(
                    fields, 
                    afflicted_code, 
                    "", 
                    0, 
                    1
                )
                
                if result and isinstance(result, dict):
                    functions = result.get("functions", [])
                    if isinstance(functions, list):
                        high_risk_functions = [
                            func for func in functions 
                            if isinstance(func, dict) and func.get('score', 0) > 85
                        ]
                        
                        if high_risk_functions:
                            # Note: Using afflicted_code as source since blob isn't defined here
                            context.append({
                                "source": "afflicted_source_code",
                                "functions": high_risk_functions
                            })
                else:
                    print("Warning: Invalid result from afflicted_source_code analysis")
                    
            except Exception as e:
                print(f"Error processing afflicted_source_code: {e}")
        
        # Add context to report
        report["context"] = context
        return report
        
    except Exception as e:
        print(f"Critical error in determine_relevant_functions: {e}")
        return None

def assign_functions_and_languages(report):
    """Determine relevant functions and detect languages from afflicted blobs."""

    languages = []
    determine_relevant_functions(report)
    for github_blob in report["afflicted_github_code_blob"]: 
        print(github_blob)       
        # Detect language from extension
        ext = '.' + github_blob.split('.')[-1].lower()
        lang = SMART_CONTRACT_LANGUAGES.get(ext)
        languages.append(lang)

    if not report.get("language"):
        report["language"] = languages

def process_single_report(report, i, processed_urls, json_file):
    """
    Orchestrator: process a single bug report in-place and update it.
    """
    # Extract normalized fields
    fields = extract_report_fields(report, i)
    report.update(fields)

    # Attach relevant files
    print(f"\nProcessing report: {fields['title']}")

    # Case 1: already has afflicted blobs → just get functions/languages, no further processing
    if report.get("afflicted_github_code_blob"):
        print("Case 1: already has afflicted blobs")
        assign_functions_and_languages(report)
        return report

    # Case 2: source code url is already a blob -> needs special processing
    handle_source_blob_urls(report)

    # Case 3: fix commit url is already a blob -> needs special processing
    handle_fix_commit_blobs(report)

    # Case 4 (Normal Case): Process source/fix url using AI-based matching strategy
    relevant_files = determine_relevant_files(report, i, processed_urls, json_file)
    handle_ai_strategy(report, fields, relevant_files)

    # Case 5: extract relevant function names + coding language used
    assign_functions_and_languages(report)

    return report

def analyze_relevant_files(json_file):

    print(json_file)
    validate_api_keys()

    with open(json_file, "r", encoding="utf-8") as f:
        reports = json.load(f)
    reports = normalize_reports_data(reports)

    all_matches = {}
    summary_results = []
    processed_urls = {}

    for i, report in enumerate(reports):
        
        # Process report in-place
        report = process_single_report(report, i, processed_urls, json_file)

        if not report["afflicted_github_code_blob"]:
            continue

        report_title = report.get('title', f'Report_{i+1}')
        report_id = report.get('id', f'ID_{i+1}')

        all_matches[report_title] = report["afflicted_github_code_blob"]

        # Add to summary using first blob for high-confidence
        summary_result = create_summary_result(
            report_id, report_title, report, report["afflicted_github_code_blob"]
        )
        summary_results.append(summary_result)

    # Save updated JSON
    save_updated_reports(json_file, reports)

    # Print comprehensive summary
    if summary_results:
        print_summary_header()
        for result in summary_results:
            print_summary_row(result)
        print_statistics(summary_results)
        print_severity_breakdown(summary_results)
        print_blob_assignment_summary(reports)
        #print_final_summary(all_matches)

    return all_matches

def main():
    script_dir = os.path.dirname(os.path.realpath(__file__))
    
    # Use the CORRECT filename (note "copy.json" instead of ".json")
    json_file = "test_dataset/0xGuard/filtered_Anyrand.json"
    
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