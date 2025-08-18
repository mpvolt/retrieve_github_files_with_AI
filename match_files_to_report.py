import re
import requests
import os
import base64
from pathlib import Path
from typing import Dict, List, Set, Optional
from fuzzywuzzy import fuzz

SMART_CONTRACT_EXTENSIONS = (
    '.sol', '.vy', '.rs', '.move', '.cairo', '.fc', '.func'
)

def get_file_content_from_blob_url(blob_url: str, api_key: str) -> str:
    """Get file content using GitHub API from blob URL"""
    try:
        # Parse the blob URL to extract repo info and file path
        # Example: https://github.com/owner/repo/blob/branch/path/to/file.sol
        parts = blob_url.replace('https://github.com/', '').split('/')
        if len(parts) < 4:
            return ""
        
        owner = parts[0]
        repo = parts[1]
        # Skip 'blob' and branch name
        file_path = '/'.join(parts[4:])  # Everything after owner/repo/blob/branch
        
        # Use GitHub API to get file content
        api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}"
        
        headers = {
            'Authorization': f'token {api_key}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'File-Matcher/1.0'
        }
        
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        
        # GitHub API returns base64 encoded content
        content = base64.b64decode(data['content']).decode('utf-8')
        return content
        
    except Exception as e:
        print(f"Error fetching content from {blob_url}: {e}")
        # Fallback to raw URL method
        try:
            raw_url = blob_url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
            response = requests.get(raw_url)
            response.raise_for_status()
            return response.text
        except Exception as e2:
            print(f"Fallback method also failed: {e2}")
            return ""

def get_file_path_from_blob_url(blob_url: str) -> str:
    """Extract file path from GitHub blob URL"""
    parts = blob_url.replace('https://github.com/', '').split('/')
    if len(parts) >= 4:
        return '/'.join(parts[4:])  # Everything after owner/repo/blob/branch
    return ""

def extract_code_snippets(bug_report: Dict) -> List[str]:
    """Extract all code snippets from bug report."""
    snippets = []
    
    # Check for broken_code_snippets (array)
    broken_snippets = bug_report.get('broken_code_snippets', [])
    if isinstance(broken_snippets, list):
        for snippet in broken_snippets:
            if isinstance(snippet, str) and snippet.strip():
                snippets.append(snippet.strip())
    
    # Check for fixed_code_snippets (array)
    fixed_snippets = bug_report.get('fixed_code_snippets', [])
    if isinstance(fixed_snippets, list):
        for snippet in fixed_snippets:
            if isinstance(snippet, str) and snippet.strip():
                snippets.append(snippet.strip())
    
    # Check for single broken_code_snippet field (fallback)
    single_snippet = bug_report.get('broken_code_snippet', '')
    if isinstance(single_snippet, str) and single_snippet.strip():
        snippets.append(single_snippet.strip())
    
    return snippets

def extract_function_names_from_text(text: str) -> Set[str]:
    """Extract function names mentioned in text descriptions."""
    function_names = set()
    
    # Common patterns for function mentions in descriptions
    patterns = [
        r'(\w+)\(\)\s*function',  # functionName() function
        r'the\s+(\w+)\(\)\s*function',  # the functionName() function
        r'function\s+(\w+)\(',  # function functionName(
        r'_(\w+)\(\)',  # _functionName()
        r'(\w+)\(\)\s*(?:method|call)',  # functionName() method/call
        r'call\s+(\w+)\(',  # call functionName(
        r'calls?\s+(\w+)\(\)',  # call/calls functionName()
        r'(\w+)\(\)\s*(?:first|afterward|then)',  # functionName() first/afterward/then
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        function_names.update(m for m in matches if len(m) > 2 and m.isalpha())
    
    return function_names

def extract_variable_names_from_text(text: str) -> Set[str]:
    """Extract variable names mentioned in text descriptions."""
    variable_names = set()
    
    # Common patterns for variable mentions
    patterns = [
        r'the\s+(\w+)\s+value',  # the variableName value
        r'(\w+)\s+(?:is|are)\s+being',  # variableName is being
        r'(\w+)\s+(?:does not|doesn\'t)',  # variableName does not
        r'balances\[_user\]\.(\w+)',  # balances[_user].fieldName
        r'(\w+)\s*=\s*',  # variableName =
        r'(\w+)\s*/\s*100',  # variableName / 100
        r'(\w+)\s*\*\s*\w+',  # variableName * something
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        variable_names.update(m for m in matches if len(m) > 2)
    
    return variable_names

def calculate_code_similarity(snippet: str, file_content: str) -> float:
    """Calculate similarity between code snippet and file content."""
    if not snippet or not file_content:
        return 0.0
    
    # Normalize code (remove extra whitespace, standardize formatting)
    def normalize_code(code):
        # Remove comments
        code = re.sub(r'//.*?\n', '\n', code)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        # Normalize whitespace
        code = re.sub(r'\s+', ' ', code.strip())
        return code.lower()
    
    normalized_snippet = normalize_code(snippet)
    normalized_file = normalize_code(file_content)
    
    # Check for exact substring match first
    if normalized_snippet in normalized_file:
        return 100.0
    
    # Use fuzzy matching for similarity
    similarity = fuzz.partial_ratio(normalized_snippet, normalized_file)
    
    # Boost score if key elements match
    snippet_tokens = set(re.findall(r'\b\w+\b', normalized_snippet))
    file_tokens = set(re.findall(r'\b\w+\b', normalized_file))
    common_tokens = snippet_tokens & file_tokens
    
    if common_tokens:
        token_ratio = len(common_tokens) / len(snippet_tokens) if snippet_tokens else 0
        similarity += token_ratio * 20  # Boost based on common tokens
    
    return min(similarity, 100.0)

def calculate_function_match_score(bug_report: Dict, file_content: str) -> tuple[float, List[str]]:
    """Calculate score based on function name matches."""
    match_reasons = []
    max_score = 0.0
    
    # Extract function names from title and description
    title = bug_report.get('title', '')
    description = bug_report.get('description', '')
    all_text = f"{title} {description}"
    
    mentioned_functions = extract_function_names_from_text(all_text)
    
    # Also extract from code snippets
    snippets = extract_code_snippets(bug_report)
    for snippet in snippets:
        snippet_functions = extract_function_names_from_text(snippet)
        mentioned_functions.update(snippet_functions)
        
        # Extract function calls from code
        func_calls = re.findall(r'(\w+)\s*\(', snippet)
        mentioned_functions.update(f for f in func_calls if len(f) > 2)
    
    print(f"    Extracted function names: {mentioned_functions}")
    
    # Check for function definitions and calls in file
    for func_name in mentioned_functions:
        # Check for function definition
        def_patterns = [
            rf'function\s+{re.escape(func_name)}\s*\(',
            rf'{re.escape(func_name)}\s*\([^)]*\)\s*(?:public|private|internal|external)'
        ]
        
        for pattern in def_patterns:
            if re.search(pattern, file_content, re.IGNORECASE):
                max_score = max(max_score, 95.0)
                match_reasons.append(f"Function definition found: {func_name}")
                break
        else:
            # Check for function calls
            call_patterns = [
                rf'\b{re.escape(func_name)}\s*\(',
                rf'\.{re.escape(func_name)}\s*\(',
            ]
            for pattern in call_patterns:
                if re.search(pattern, file_content, re.IGNORECASE):
                    max_score = max(max_score, 70.0)
                    match_reasons.append(f"Function call found: {func_name}")
                    break
            else:
                # Check for simple mention
                if func_name.lower() in file_content.lower():
                    max_score = max(max_score, 40.0)
                    match_reasons.append(f"Function mentioned: {func_name}")
    
    return max_score, match_reasons

def calculate_variable_match_score(bug_report: Dict, file_content: str) -> tuple[float, List[str]]:
    """Calculate score based on variable name matches."""
    match_reasons = []
    max_score = 0.0
    
    # Extract variable names from title and description
    title = bug_report.get('title', '')
    description = bug_report.get('description', '')
    all_text = f"{title} {description}"
    
    mentioned_variables = extract_variable_names_from_text(all_text)
    
    # Also extract from code snippets
    snippets = extract_code_snippets(bug_report)
    for snippet in snippets:
        snippet_variables = extract_variable_names_from_text(snippet)
        mentioned_variables.update(snippet_variables)
        
        # Extract variable assignments and references
        var_patterns = [
            r'(\w+)\s*=\s*',
            r'balances\[_user\]\.(\w+)',
            r'(\w+)\s*\*\s*\w+',
            r'(\w+)\s*/\s*\d+',
        ]
        for pattern in var_patterns:
            matches = re.findall(pattern, snippet)
            mentioned_variables.update(m for m in matches if len(m) > 2)
    
    print(f"    Extracted variable names: {mentioned_variables}")
    
    # Check for variables in file content
    for var_name in mentioned_variables:
        if var_name.lower() in file_content.lower():
            # Check if it's a proper variable usage (not just substring)
            var_patterns = [
                rf'\b{re.escape(var_name)}\s*=',
                rf'\b{re.escape(var_name)}\s*\*',
                rf'\b{re.escape(var_name)}\s*/',
                rf'\.{re.escape(var_name)}\b',
                rf'\b{re.escape(var_name)}\b'
            ]
            for pattern in var_patterns:
                if re.search(pattern, file_content, re.IGNORECASE):
                    max_score = max(max_score, 60.0)
                    match_reasons.append(f"Variable found: {var_name}")
                    break
    
    return max_score, match_reasons

def calculate_language_match_score(bug_report: Dict, file_path: str) -> tuple[float, List[str]]:
    """Calculate score based on programming language match."""
    language = bug_report.get('language', '').lower()
    file_extension = Path(file_path).suffix.lower()
    
    language_map = {
        'solidity': ['.sol'],
        'vyper': ['.vy'],
        'rust': ['.rs'],
        'move': ['.move'],
        'cairo': ['.cairo'],
        'func': ['.fc', '.func']
    }
    
    if language in language_map:
        if file_extension in language_map[language]:
            return 20.0, [f"Language match: {language}"]
    
    return 0.0, []

def filter_relevant_files(file_urls: Set[str], bug_report: Dict) -> Set[str]:
    """Filter files based on smart contract extensions and exclude test files."""
    # Get language from report
    language = bug_report.get('language', '').lower()
    
    # Filter out test files and error files
    non_test_files = {
        file_url for file_url in file_urls 
        if not any(keyword in file_url.lower() for keyword in ['test', 'spec', 'mock', 'errors'])
    }
    
    # Filter by smart contract extensions
    filtered_files = set()
    for file_url in non_test_files:
        file_path = get_file_path_from_blob_url(file_url)
        file_extension = Path(file_path).suffix.lower()
        if file_extension in SMART_CONTRACT_EXTENSIONS:
            filtered_files.add(file_url)
    
    return filtered_files

def match_bug_to_files(bug_report: Dict, github_blob_urls: Set[str], api_key: str, max_results: int = 10) -> List[Dict]:
    """
    Match a bug report to the most relevant GitHub files.
    
    Args:
        bug_report: Dictionary containing bug report data
        github_blob_urls: Set of GitHub blob URLs to search
        api_key: GitHub API key
        max_results: Maximum number of results to return
    
    Returns:
        List of matched files sorted by relevance score
    """
    
    print(f"\n=== Analyzing Bug Report ===")
    print(f"Title: {bug_report.get('title', 'N/A')}")
    print(f"Severity: {bug_report.get('severity', 'N/A')}")
    print(f"Language: {bug_report.get('language', 'N/A')}")
    
    # Extract code snippets
    code_snippets = extract_code_snippets(bug_report)
    print(f"Found {len(code_snippets)} code snippets")
    
    # Filter relevant files
    relevant_files = filter_relevant_files(github_blob_urls, bug_report)
    print(f"Filtered to {len(relevant_files)} relevant files")
    
    if not relevant_files:
        print("No relevant smart contract files found!")
        return []
    
    matched_files = []
    
    for blob_url in relevant_files:
        file_path = get_file_path_from_blob_url(blob_url)
        file_name = Path(file_path).name
        
        print(f"\n--- Analyzing: {file_path} ---")
        
        # Get file content
        file_content = get_file_content_from_blob_url(blob_url, api_key)
        if not file_content:
            print(f"  WARNING: Could not fetch content for {blob_url}")
            continue
        
        total_score = 0.0
        match_reasons = []
        score_breakdown = {}
        
        # 1. Language match
        lang_score, lang_reasons = calculate_language_match_score(bug_report, file_path)
        if lang_score > 0:
            total_score += lang_score
            match_reasons.extend(lang_reasons)
            score_breakdown['language'] = lang_score
        
        # 2. Code snippet similarity
        if code_snippets:
            max_code_score = 0.0
            best_snippet_idx = -1
            for i, snippet in enumerate(code_snippets):
                similarity = calculate_code_similarity(snippet, file_content)
                print(f"    Snippet {i+1} similarity: {similarity:.1f}%")
                if similarity > max_code_score:
                    max_code_score = similarity
                    best_snippet_idx = i
            
            if max_code_score > 30:  # Only count if reasonably similar
                # Weight code similarity heavily as it's the most reliable indicator
                weighted_score = max_code_score * 2.0  # Double weight for code similarity
                total_score += weighted_score
                match_reasons.append(f"Best code similarity (snippet {best_snippet_idx + 1}): {max_code_score:.1f}%")
                score_breakdown['code_similarity'] = weighted_score
        
        # 3. Function name matches
        func_score, func_reasons = calculate_function_match_score(bug_report, file_content)
        if func_score > 0:
            total_score += func_score
            match_reasons.extend(func_reasons)
            score_breakdown['functions'] = func_score
        
        # 4. Variable name matches
        var_score, var_reasons = calculate_variable_match_score(bug_report, file_content)
        if var_score > 0:
            total_score += var_score
            match_reasons.extend(var_reasons)
            score_breakdown['variables'] = var_score
        
        print(f"    Total Score: {total_score:.1f}")
        print(f"    Score Breakdown: {score_breakdown}")
        
        if total_score > 0:
            matched_files.append({
                'file_path': file_path,
                'file_name': file_name,
                'blob_url': blob_url,
                'total_score': total_score,
                'match_reasons': match_reasons,
                'score_breakdown': score_breakdown,
                'bug_id': bug_report.get('id', 'unknown')
            })
    
    # Sort by score (highest first) and return top results
    matched_files.sort(key=lambda x: x['total_score'], reverse=True)
    return matched_files[:max_results]

# Example usage function
def example_usage():
    """Example of how to use the bug matching system."""
    
    # Example bug report (from your provided JSON)
    bug_report = {
        "id": "1",
        "title": "Invalid Calculations",
        "status": "Fixed",
        "severity": "Critical",
        "description": "In the _calculateVestingTokens() function, the tokensPerSecond value is being counted incorrectly. This is because the calculation does not take into account the portion of the tokens that can be released on the TGE. This deduction needs to be done always, not optionally, as seen in line:\n\n\n\nThis leads to situations in which more tokens can be released than the vested amount. Users can wait the whole vesting period and call withdraw() first and withdrawInitial() afterward to extract 115% of the vested amount.",
        "recommendation": "When calculating the tokensPerSecond value, always subtract the balances[_user].amount * INITIAL_WITHDRAW_PERCENTAGE / 100 from the balances[_user].amount.",
        "source_code_url": "https://github.com/jgomes79/LitLabGames/commit/1b7b59ccdb29c3d95ebdb9080819abbb707a93ba",
        "broken_code_snippets": [
            "uint256 amountMinusFirstWithdraw = balances[_user].amount - (balances[_user].claimedInitial ? balances[_user].amount * INITIAL_WITHDRAW_PERCENTAGE / 100 : 0);"
        ],
        "language": "Solidity",
        "fixed_code_snippets": [],
        "type": "State machine and invariant violations"
    }
    
    # Example GitHub blob URLs (you would provide these)
    github_blobs = {
        "https://github.com/jgomes79/LitLabGames/blob/1b7b59ccdb29c3d95ebdb9080819abbb707a93ba/smartcontracts/contracts/vesting/VestingContract.sol",
        "https://github.com/jgomes79/LitLabGames/blob/1b7b59ccdb29c3d95ebdb9080819abbb707a93ba/smartcontracts/contracts/vesting/TokenContract.sol",
        "https://github.com/jgomes79/LitLabGames/blob/070807740a6ce9cb113e7f122065f2203d8351bd/smartcontracts/contracts/staking/LitlabPreStakingBox.sol"
    }
    
    # Your GitHub API key
    api_key = os.getenv('GITHUB_API_KEY')
    
    # Match the bug to files
    results = match_bug_to_files(bug_report, github_blobs, api_key)
    
    print(f"\n=== FINAL RESULTS ===")
    for i, result in enumerate(results):
        print(f"\n{i+1}. {result['file_path']}")
        print(f"   Score: {result['total_score']:.1f}")
        print(f"   Reasons: {', '.join(result['match_reasons'])}")

if __name__ == "__main__":
    example_usage()