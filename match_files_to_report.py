import re
import requests
import os
import base64
import time
from pathlib import Path
from typing import Dict, List, Set, Optional
from fuzzywuzzy import fuzz
from urllib.parse import quote

SMART_CONTRACT_EXTENSIONS = (
    '.sol', '.tsol', '.vy', '.rs', '.move', '.cairo', '.fc', '.func', '.circom'
)

def search_github_for_code(code_snippet: str, repo_owner: str, repo_name: str, api_key: str) -> List[str]:
    """
    Search GitHub repository for code snippet using GitHub's search API.
    
    Args:
        code_snippet: Code snippet to search for
        repo_owner: Repository owner
        repo_name: Repository name
        api_key: GitHub API key
    
    Returns:
        List of file paths that contain the code snippet
    """
    # Take first 30 characters and clean up for search
    search_query = code_snippet[:30].strip()
    if not search_query:
        return []
    
    # GitHub search API endpoint
    url = "https://api.github.com/search/code"
    
    # Search parameters
    params = {
        'q': f'"{search_query}" repo:{repo_owner}/{repo_name}',
        'per_page': 10  # Limit results
    }
    
    headers = {
        'Authorization': f'token {api_key}',
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'Bug-Matcher/1.0'
    }
    
    try:
        response = requests.get(url, params=params, headers=headers)
        
        # Handle rate limiting
        if response.status_code == 403 and 'rate limit' in response.text.lower():
            print(f"    GitHub search rate limited, waiting")
            time.sleep(200)
            search_github_for_code(code_snippet, repo_owner, repo_name, api_key)
        
        if response.status_code == 200:
            data = response.json()
            file_paths = []
            for item in data.get('items', []):
                file_paths.append(item['path'])
            print(f"    GitHub search found {len(file_paths)} files with code snippet")
            return file_paths
        else:
            print(f"    GitHub search failed: {response.status_code}")
            return []
            
    except Exception as e:
        print(f"    GitHub search error: {str(e)}")
        return []

def extract_repo_info_from_blob_url(blob_url: str) -> tuple:
    """
    Extract repository owner and name from a GitHub blob URL.
    
    Args:
        blob_url: GitHub blob URL
    
    Returns:
        Tuple of (repo_owner, repo_name)
    """
    # Example URL: https://github.com/owner/repo/blob/main/path/to/file.sol
    try:
        parts = blob_url.split('/')
        if 'github.com' in blob_url and len(parts) >= 5:
            repo_owner = parts[3]
            repo_name = parts[4]
            return repo_owner, repo_name
    except Exception:
        pass
    return None, None

def get_file_content_from_blob_url(blob_url: str, api_key: str) -> str:
    """Get file content using GitHub API from blob URL with rate limiting"""
    try:
        # Parse the blob URL to extract repo info and file path
        # Example: https://github.com/owner/repo/blob/branch/path/to/file.sol
        parts = blob_url.replace('https://github.com/', '').split('/')
        if len(parts) < 4 or parts[2] != 'blob':
            return ""
        
        owner = parts[0]
        repo = parts[1]
        ref = parts[3]  # branch or commit hash
        file_path = '/'.join(parts[4:])  # Everything after owner/repo/blob/ref
        
        # Use GitHub API to get file content with explicit ref parameter
        api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}"
        
        headers = {
            'Authorization': f'token {api_key}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'File-Matcher/1.0'
        }
        
        params = {'ref': ref}
        
        # Retry loop for rate limiting
        max_retries = 10
        for attempt in range(max_retries):
            response = requests.get(api_url, headers=headers, params=params)
            
            # Check if we hit rate limit (status code 403 with rate limit message)
            if response.status_code == 403:
                rate_limit_remaining = response.headers.get('X-RateLimit-Remaining', '0')
                if rate_limit_remaining == '0':
                    print(f"Rate limit exceeded. Waiting 5 min before retry (attempt {attempt + 1}/{max_retries})...")
                    if attempt < max_retries - 1:  # Don't wait on the last attempt
                        time.sleep(300)
                        continue
            
            # If successful, break the retry loop
            if response.status_code == 200:
                break
                
            # For other errors, raise immediately
            response.raise_for_status()
            
        else:
            # This else clause executes if the loop completed without breaking
            # (meaning all retries failed due to rate limiting)
            print("Maximum retries attempted, retrying function")
            return get_file_content_from_blob_url(blob_url, api_key)
        
        data = response.json()
        
        # GitHub API returns base64 encoded content
        content = base64.b64decode(data['content']).decode('utf-8')
        return content
        
    except requests.exceptions.HTTPError as e:
        # Check if the exception was due to rate limiting
        if hasattr(e, 'response') and e.response is not None:
            if e.response.status_code == 403:
                rate_limit_remaining = e.response.headers.get('X-RateLimit-Remaining', '0')
                if rate_limit_remaining == '0':
                    print(f"Rate limit hit in exception handler. Waiting 5 minutes before retrying entire function...")
                    time.sleep(300)
                    return get_file_content_from_blob_url(blob_url, api_key)
        
        print(f"HTTP Error fetching content from {blob_url}: {e}")
        # Fallback to raw URL method (no rate limiting needed for raw URLs)
        try:
            raw_url = blob_url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
            response = requests.get(raw_url, timeout=30)
            response.raise_for_status()
            return response.text
                
        except Exception as e2:
            print(f"Fallback method also failed: {e2}")
            return ""
            
    except Exception as e:
        print(f"Error fetching content from {blob_url}: {e}")
        # Fallback to raw URL method (no rate limiting needed for raw URLs)
        try:
            raw_url = blob_url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
            response = requests.get(raw_url, timeout=30)
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

def is_valid_function_name(name: str) -> bool:
    """Check if a string looks like a valid function name."""
    if not name:
        return False
    
    # Should start with letter or underscore
    if not (name[0].isalpha() or name[0] == '_'):
        return False
    
    # Should only contain alphanumeric characters and underscores
    if not name.replace('_', '').isalnum():
        return False
    
    # Should not be all uppercase (likely a constant)
    if name.isupper() and len(name) > 3:
        return False
    
    return True

def extract_function_names_from_text(text: str) -> Set[str]:
    """Extract function names mentioned in text descriptions with better filtering."""
    function_names = set()
    
    # Common words that should NOT be considered function names
    EXCLUDE_WORDS = {
        'the', 'and', 'for', 'with', 'from', 'this', 'that', 'when', 'where', 
        'what', 'how', 'can', 'will', 'does', 'not', 'are', 'being', 'have',
        'has', 'had', 'said', 'get', 'set', 'new', 'old', 'way', 'use', 'call',
        'view', 'pure', 'true', 'false', 'null', 'void', 'int', 'uint', 'bool',
        'string', 'address', 'bytes', 'mapping', 'array', 'struct', 'enum',
        'public', 'private', 'internal', 'external', 'constant', 'immutable',
        'override', 'virtual', 'abstract', 'interface', 'contract', 'library',
        'function', 'modifier', 'event', 'error', 'using', 'import', 'pragma',
        'require', 'assert', 'revert', 'emit', 'return', 'if', 'else', 'while',
        'for', 'do', 'break', 'continue', 'try', 'catch', 'throw', 'finally'
    }
    
    # Start with the simple, working patterns from your first function
    simple_patterns = [
        r'(\w+)\(\)\s*function',  # functionName() function
        r'the\s+(\w+)\(\)\s*function',  # the functionName() function
        r'function\s+(\w+)\(',  # function functionName(
        r'_(\w+)\(\)',  # _functionName()
        r'(\w+)\(\)\s*(?:method|call)',  # functionName() method/call
        r'call\s+(\w+)\(',  # call functionName(
        r'calls?\s+(\w+)\(\)',  # call/calls functionName()
        r'(\w+)\(\)\s*(?:first|afterward|then)',  # functionName() first/afterward/then
        r'(\w+)\s+functions?',  # functionName function/functions
    ]
    
    # Process simple patterns first
    for pattern in simple_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            if match and len(match) > 2 and match.lower() not in EXCLUDE_WORDS:
                if is_valid_function_name(match):
                    function_names.add(match)
    
    # If we found functions with simple patterns, return them
    if function_names:
        return function_names
    
    # Only try complex patterns if simple patterns didn't work
    complex_patterns = [
        r'call(?:s|ing)?\s+(\w+)\s*\(',  # call/calls/calling functionName(
        r'invoke(?:s|ing)?\s+(\w+)\s*\(',  # invoke/invokes/invoking functionName(
        r'execute(?:s|ing)?\s+(\w+)\s*\(',  # execute/executes/executing functionName(
        r'trigger(?:s|ing)?\s+(\w+)\s*\(',  # trigger/triggers/triggering functionName(
        r'(?:first|then|afterward|before|after)\s+(\w+)\s*\(',  # first/then functionName(
        r'(?:will|should|must|may|might)\s+(\w+)\s*\(',  # will/should functionName(
        r'(?:does not|doesn\'t|cannot|can\'t)\s+(\w+)\s*\(',  # does not functionName(
        r'_(\w+)\s*\(',  # _functionName(
        r'\.(\w+)\s*\(\)',  # .functionName() - method calls
        r'(?:in|during|when)\s+(\w+)\s*\(',  # in/during/when functionName(
        r'(\w+)\(\)\s*(?:reverts?|fails?|errors?)',  # functionName() reverts/fails/errors
    ]
    
    for pattern in complex_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            if match and len(match) > 2 and match.lower() not in EXCLUDE_WORDS:
                if is_valid_function_name(match):
                    function_names.add(match)
    
    return function_names

def extract_variable_names_from_text(text: str) -> Set[str]:
    """Extract variable names mentioned in text descriptions."""
    variable_names = set()
    
    # Common words that should NOT be considered variable names
    EXCLUDE_WORDS = {
        'the', 'and', 'for', 'with', 'from', 'this', 'that', 'when', 'where', 
        'what', 'how', 'can', 'will', 'does', 'not', 'are', 'being', 'have',
        'has', 'had', 'said', 'get', 'set', 'new', 'old', 'way', 'use', 'call',
        'user', 'owner', 'admin', 'contract', 'address', 'amount', 'value',
        'balance', 'fee', 'fees', 'token', 'tokens', 'transfer', 'transfers',
        'current', 'total', 'minimum', 'maximum', 'result', 'error', 'true', 
        'false', 'null', 'void', 'public', 'private', 'internal', 'external'
    }
    
    # Enhanced patterns for variable mentions
    patterns = [
        # File path patterns (extension-agnostic) - added at the beginning for priority
        r'@[\w-]+(?:/[\w-]+)*/(\w+)\.\w+',  # @org/repo/.../ClassName.ext
        r'(?:^|[\s/])[\w-]+(?:/[\w-]+)*/(\w+)\.\w+',  # path/.../ClassName.ext
        r'(?:^|[\s/])(\w+)\.\w+(?:\s|$)',  # ClassName.ext (standalone)
        
        # Direct variable references with context
        r'the\s+(\w+)\s+(?:value|amount|variable|field)',  # the variableName value/amount/variable/field
        r'(\w+)\s+(?:is|are)\s+being',  # variableName is being
        r'(\w+)\s+(?:does not|doesn\'t)',  # variableName does not
        
        # Assignment patterns
        r'(\w+)\s*=\s*',  # variableName =
        r'set\s+(\w+)\s+to',  # set variableName to
        r'(\w+)\s+(?:is|was)\s+set\s+to',  # variableName is/was set to
        
        # Mathematical operations
        r'(\w+)\s*/\s*\d+',  # variableName / 100
        r'(\w+)\s*\*\s*\w+',  # variableName * something
        r'(\w+)\s*[+\-]\s*\w+',  # variableName + something or variableName - something
        
        # Comparison patterns
        r'(\w+)\s*(?:>=|<=|>|<|==|!=)\s*',  # variableName >= something
        r'(?:>=|<=|>|<|==|!=)\s*(\w+)',  # >= variableName
        r'than\s+(?:the\s+)?(\w+)\s+(?:amount|value)',  # than the variableName amount
        
        # Solidity-specific patterns
        r'balances\[.*?\]\.(\w+)',  # balances[user].fieldName
        r'(\w+)\[.*?\]',  # variableName[index] - mapping/array access
        r'\.(\w+)\s+(?:amount|value|balance)',  # .variableName amount/value/balance
        
        # Variable mentions with underscores (common in Solidity)
        r'(?:the\s+)?(_\w+)\s+(?:amount|value|variable|field)',  # the _variableName amount
        r'(?:current|total|minimum|maximum)\s+(_\w+)',  # current _variableName
        r'(_\w+)\s+(?:is|are|was|were)',  # _variableName is/are/was/were
        
        # Fee-specific patterns (since your example is about fees)
        r'(\w*[Ff]ees?)\s+(?:amount|value)',  # fees/Fees amount
        r'(?:pay|paying|paid)\s+(?:a\s+)?(?:higher\s+)?(\w*[Ff]ees?)',  # pay higher fees
        r'(?:the\s+)?(\w*[Ff]ees?)\s+(?:than|amount)',  # the fees than
        
        # Generic variable context patterns
        r'(?:the\s+)?(\w+)\s+(?:parameter|property|attribute)',  # the variableName parameter
        r'(\w+)\s+(?:contains|holds|stores)',  # variableName contains/holds/stores
        r'(?:update|updates|updating)\s+(?:the\s+)?(\w+)',  # update the variableName
        r'(?:modify|modifies|modifying)\s+(?:the\s+)?(\w+)',  # modify the variableName
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            # Clean up the match
            clean_match = match.strip()
            
            # Basic validation
            if (clean_match and 
                len(clean_match) > 1 and  # Allow shorter variable names like 'x', 'i'
                clean_match.lower() not in EXCLUDE_WORDS and
                is_valid_variable_name(clean_match)):
                variable_names.add(clean_match)
    
    return variable_names

def is_valid_variable_name(name: str) -> bool:
    """Check if a string looks like a valid variable name."""
    if not name:
        return False
    
    # Should start with letter or underscore
    if not (name[0].isalpha() or name[0] == '_'):
        return False
    
    # Should only contain alphanumeric characters and underscores
    if not name.replace('_', '').isalnum():
        return False
    
    # Should not be all uppercase with length > 3 (likely a constant)
    if name.isupper() and len(name) > 3:
        return False
    
    return True


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
    recommendation = bug_report.get('recommendation', '')
    all_text = f"{title} {description} {recommendation}"
    
    mentioned_variables = extract_variable_names_from_text(all_text)
    
    # Also extract from code snippets
    snippets = extract_code_snippets(bug_report)
    for snippet in snippets:
        snippet_variables = extract_variable_names_from_text(snippet)
        mentioned_variables.update(snippet_variables)
        
        # Extract variable assignments and references
        var_patterns = [
            r'([a-zA-Z_]\w*)\s*=\s*',
            r'balances\[_user\]\.([a-zA-Z_]\w*)',
            r'([a-zA-Z_]\w*)\s*\*\s*\w+',
            r'([a-zA-Z_]\w*)\s*/\s*\d+',
            r'\b([A-Z_][A-Z0-9_]*)\b',  # CONSTANT_STYLE variables
            r'\b([a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*)\b',  # camelCase variables
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
                r'([a-zA-Z_]\w*)\s*=\s*',
                r'balances\[_user\]\.([a-zA-Z_]\w*)',
                r'([a-zA-Z_]\w*)\s*\*\s*\w+',
                r'([a-zA-Z_]\w*)\s*/\s*\d+',
                r'\b([A-Z_][A-Z0-9_]*)\b',  # CONSTANT_STYLE variables
                r'\b([a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*)\b',  # camelCase variables
                r'\b([A-Z][a-z][a-zA-Z0-9]*)\b',  # PascalCase variables like "Amount"
                r'\b([a-z]+)\s*[-+*/]\s*',  # simple lowercase vars in expressions
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
        if not any(keyword in file_url.lower() for keyword in ['test', 'spec', 'mock', 'errors', 'interface'])
    }
    
    # Filter by smart contract extensions
    filtered_files = set()
    for file_url in non_test_files:
        file_path = get_file_path_from_blob_url(file_url)
        file_extension = Path(file_path).suffix.lower()
        if file_extension in SMART_CONTRACT_EXTENSIONS:
            filtered_files.add(file_url)
    
    return filtered_files

def calculate_filename_mention_score(bug_report: Dict, file_path: str) -> tuple[float, List[str]]:
    """Calculate score if filename is explicitly mentioned in the bug report."""
    match_reasons = []
    max_score = 0.0
    
    # Get all text from the bug report
    title = bug_report.get('title', '')
    description = bug_report.get('description', '')
    recommendation = bug_report.get('recommendation', '')
    files = bug_report.get('files', '')
    
    # Extract code snippets
    snippets = extract_code_snippets(bug_report)
    snippet_text = ' '.join(snippets)
    
    # Combine all text
    all_text = f"{title} {description} {recommendation} {snippet_text} {files}"
    
    # Get filename variations
    full_filename = Path(file_path).name  # e.g., "VestingContract.sol"
    filename_stem = Path(file_path).stem  # e.g., "VestingContract"
    
    # Also check path components
    path_parts = file_path.split('/')
    
    print(f"    Checking filename mentions for: {full_filename}")
    
    # Count exact filename mentions
    exact_filename_patterns = [
        # Exact filename with word boundaries
        rf'\b{re.escape(full_filename)}\b',
        # Filename at start of sentence or after common punctuation
        rf'(?:^|[.\s,;:])\s*{re.escape(full_filename)}(?=\s|[.,;:]|$)',
        # Filename in common contexts
        rf'(?:in|file|contract|from|see|check|review)\s+{re.escape(full_filename)}',
    ]
    
    exact_mentions_count = 0
    for pattern in exact_filename_patterns:
        matches = re.findall(pattern, all_text, re.IGNORECASE)
        exact_mentions_count += len(matches)
    
    if exact_mentions_count > 0:
        # Base score for first mention
        base_score = 350.0
        # Progressive bonus for additional mentions (diminishing returns)
        bonus_score = 0
        if exact_mentions_count > 1:
            # Each additional mention adds less value: 50, 30, 20, 15, 10, ...
            for i in range(1, exact_mentions_count):
                bonus_multiplier = max(0.1, 1.0 - (i * 0.2))  # Diminishing returns
                bonus_score += 50 * bonus_multiplier
        
        total_exact_score = base_score + bonus_score
        max_score = max(max_score, total_exact_score)
        match_reasons.append(f"Exact filename mentioned {exact_mentions_count} times: {full_filename} (score: {total_exact_score:.1f})")
        print(f"      ✓ Exact filename found {exact_mentions_count} times: {full_filename} (score: {total_exact_score:.1f})")
    
    # If no exact match found, check for filename without extension (with word boundaries)
    if max_score < 200.0:
        stem_patterns = [
            rf'\b{re.escape(filename_stem)}\b',
            # Also check with common extensions
            rf'\b{re.escape(filename_stem)}\.(sol|vy|rs|move|cairo|fc|func|js|ts|py|java|cpp|c|h)\b',
        ]
        
        stem_mentions_count = 0
        for pattern in stem_patterns:
            matches = re.findall(pattern, all_text, re.IGNORECASE)
            stem_mentions_count += len(matches)
        
        if stem_mentions_count > 0:
            # Base score for first mention
            base_score = 180.0
            # Progressive bonus for additional mentions
            bonus_score = 0
            if stem_mentions_count > 1:
                for i in range(1, stem_mentions_count):
                    bonus_multiplier = max(0.1, 1.0 - (i * 0.2))
                    bonus_score += 40 * bonus_multiplier
            
            total_stem_score = base_score + bonus_score
            max_score = max(max_score, total_stem_score)
            match_reasons.append(f"Filename stem mentioned {stem_mentions_count} times: {filename_stem} (score: {total_stem_score:.1f})")
            print(f"      ✓ Filename stem found {stem_mentions_count} times: {filename_stem} (score: {total_stem_score:.1f})")
    
    # Check for additional filename patterns only if no strong match found yet
    if max_score < 180.0:
        filename_patterns = [
            # Mention in context (e.g., "In InterchainGasPaymaster.sol")
            rf'(?:in|file|contract|from)\s+{re.escape(full_filename)}\b',
            rf'(?:in|file|contract|from)\s+{re.escape(filename_stem)}\b',
            # File paths or imports
            rf'/{re.escape(full_filename)}\b',
            rf'/{re.escape(filename_stem)}\b',
        ]
        
        pattern_mentions_count = 0
        matched_patterns = []
        for pattern in filename_patterns:
            matches = re.findall(pattern, all_text, re.IGNORECASE)
            if matches:
                pattern_mentions_count += len(matches)
                matched_patterns.append(pattern)
        
        if pattern_mentions_count > 0:
            # Base score depends on whether it's full filename or stem
            base_score = 195.0 if any(full_filename.lower() in pattern.lower() for pattern in matched_patterns) else 175.0
            # Bonus for multiple pattern matches
            bonus_score = 0
            if pattern_mentions_count > 1:
                for i in range(1, pattern_mentions_count):
                    bonus_multiplier = max(0.1, 1.0 - (i * 0.25))
                    bonus_score += 30 * bonus_multiplier
            
            total_pattern_score = base_score + bonus_score
            max_score = max(max_score, total_pattern_score)
            match_reasons.append(f"Filename pattern matches {pattern_mentions_count} times (score: {total_pattern_score:.1f})")
            print(f"      ✓ Filename pattern found {pattern_mentions_count} times (score: {total_pattern_score:.1f})")
    
    # Check for any path components mentioned (with word boundaries for shorter components)
    path_component_scores = []
    for part in path_parts:
        if len(part) > 3:
            part_mentions_count = 0
            
            if len(part) >= 6 or part == filename_stem:
                # For longer parts, use simple substring matching first
                if part.lower() in all_text.lower():
                    # But verify it's not a substring of a longer word
                    matches = re.findall(rf'\b{re.escape(part)}\b', all_text, re.IGNORECASE)
                    part_mentions_count = len(matches)
            else:
                # For shorter path components, always use word boundaries
                matches = re.findall(rf'\b{re.escape(part)}\b', all_text, re.IGNORECASE)
                part_mentions_count = len(matches)
            
            if part_mentions_count > 0:
                # Base score
                base_score = 150.0 if part == filename_stem else 100.0
                # Bonus for multiple mentions
                bonus_score = 0
                if part_mentions_count > 1:
                    for i in range(1, part_mentions_count):
                        bonus_multiplier = max(0.1, 1.0 - (i * 0.3))
                        bonus_score += 25 * bonus_multiplier
                
                total_part_score = base_score + bonus_score
                path_component_scores.append(total_part_score)
                match_reasons.append(f"Path component '{part}' mentioned {part_mentions_count} times (score: {total_part_score:.1f})")
                print(f"      ✓ Path component '{part}' found {part_mentions_count} times (score: {total_part_score:.1f})")
    
    # Take the highest path component score
    if path_component_scores:
        max_score = max(max_score, max(path_component_scores))
    
    # Check for common contract naming patterns in smart contract files
    file_extension = Path(file_path).suffix.lower()
    if file_extension in SMART_CONTRACT_EXTENSIONS:
        # Look for contract/module names that might match the filename
        contract_patterns = []
        
        if file_extension == '.sol':  # Solidity
            contract_patterns = [
                rf'contract\s+{re.escape(filename_stem)}\b',
                rf'interface\s+{re.escape(filename_stem)}\b',
                rf'library\s+{re.escape(filename_stem)}\b'
            ]
        elif file_extension == '.vy':  # Vyper
            contract_patterns = [
                rf'contract\s+{re.escape(filename_stem)}\b',
                rf'interface\s+{re.escape(filename_stem)}\b'
            ]
        elif file_extension == '.rs':  # Rust (for smart contracts)
            contract_patterns = [
                rf'mod\s+{re.escape(filename_stem)}\b',
                rf'contract\s+{re.escape(filename_stem)}\b',
                rf'impl\s+{re.escape(filename_stem)}\b'
            ]
        elif file_extension == '.move':  # Move
            contract_patterns = [
                rf'module\s+{re.escape(filename_stem)}\b',
                rf'resource\s+{re.escape(filename_stem)}\b',
                rf'script\s+{re.escape(filename_stem)}\b'
            ]
        elif file_extension == '.cairo':  # Cairo
            contract_patterns = [
                rf'contract\s+{re.escape(filename_stem)}\b',
                rf'namespace\s+{re.escape(filename_stem)}\b'
            ]
        elif file_extension in ['.fc', '.func']:  # FunC
            contract_patterns = [
                rf'contract\s+{re.escape(filename_stem)}\b',
                rf'global\s+{re.escape(filename_stem)}\b'
            ]
        
        contract_mentions_count = 0
        for pattern in contract_patterns:
            matches = re.findall(pattern, all_text, re.IGNORECASE)
            contract_mentions_count += len(matches)
        
        if contract_mentions_count > 0:
            # Base score for contract declarations
            base_score = 190.0
            # Bonus for multiple contract declarations (rare but possible)
            bonus_score = 0
            if contract_mentions_count > 1:
                for i in range(1, contract_mentions_count):
                    bonus_score += 20  # Fixed bonus since multiple contract declarations are significant
            
            total_contract_score = base_score + bonus_score
            max_score = max(max_score, total_contract_score)
            match_reasons.append(f"Contract/module name matches filename {contract_mentions_count} times: {filename_stem} (score: {total_contract_score:.1f})")
            print(f"      ✓ Contract/module declaration found {contract_mentions_count} times: {filename_stem} (score: {total_contract_score:.1f})")
    
    # Special handling for compound names (e.g., InterchainGasPaymaster)
    # Split camelCase/PascalCase names and check for partial matches
    if len(filename_stem) > 8:  # Only for longer names
        # Split on capital letters to get compound words
        words = re.findall(r'[A-Z][a-z]*', filename_stem)
        if len(words) >= 2:  # Must have at least 2 compound words
            compound_score = 0
            found_words = []
            word_mention_counts = {}
            
            for word in words:
                if len(word) >= 4:
                    # Count mentions of each compound word
                    matches = re.findall(rf'\b{re.escape(word)}\b', all_text, re.IGNORECASE)
                    word_count = len(matches)
                    if word_count > 0:
                        word_mention_counts[word] = word_count
                        found_words.append(word)
                        # Base score per word found
                        base_word_score = 30
                        # Bonus for multiple mentions of the same word
                        bonus_word_score = 0
                        if word_count > 1:
                            for i in range(1, word_count):
                                bonus_multiplier = max(0.2, 1.0 - (i * 0.2))
                                bonus_word_score += 10 * bonus_multiplier
                        
                        compound_score += base_word_score + bonus_word_score
            
            # If we found multiple compound words, it's likely the right file
            if len(found_words) >= 2:
                compound_score = min(compound_score, 140.0)  # Cap the score
                max_score = max(max_score, compound_score)
                word_details = [f"{word}({word_mention_counts[word]}x)" for word in found_words]
                match_reasons.append(f"Compound words found: {', '.join(word_details)} from {filename_stem} (score: {compound_score:.1f})")
                print(f"      ✓ Compound words found: {word_details} (score: {compound_score:.1f})")
    
    return max_score, match_reasons


def is_valid_function_name(name: str) -> bool:
    """Validate if a string looks like a valid function name."""
    if not name or len(name) < 3:
        return False
    
    # Must start with letter or underscore
    if not (name[0].isalpha() or name[0] == '_'):
        return False
    
    # Can only contain alphanumeric characters and underscores
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
        return False
    
    # Exclude common programming keywords and types
    KEYWORDS = {
        'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default',
        'break', 'continue', 'return', 'try', 'catch', 'throw', 'finally',
        'class', 'struct', 'enum', 'union', 'typedef', 'sizeof', 'typeof',
        'true', 'false', 'null', 'undefined', 'void', 'var', 'let', 'const'
    }
    
    if name.lower() in KEYWORDS:
        return False
    
    # Exclude very common English words that might appear in code contexts
    COMMON_WORDS = {
        'user', 'data', 'info', 'type', 'size', 'length', 'count', 'index',
        'value', 'item', 'list', 'array', 'map', 'key', 'name', 'text',
        'code', 'file', 'path', 'url', 'link', 'page', 'view', 'form'
    }
    
    if name.lower() in COMMON_WORDS and len(name) <= 5:
        return False
    
    return True

def calculate_function_match_score(bug_report: Dict, file_content: str) -> tuple[float, List[str]]:
    """Calculate score based on function name matches with improved extraction."""
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
        
        # Extract function calls from code with better patterns
        func_call_patterns = [
            r'(\w+)\s*\(',  # Basic function call
            r'\.(\w+)\s*\(',  # Method call
            r'(\w+)\.(\w+)\s*\(',  # Contract.function call
        ]
        
        for pattern in func_call_patterns:
            func_calls = re.findall(pattern, snippet)
            for call in func_calls:
                if isinstance(call, tuple):
                    for subcall in call:
                        if subcall and is_valid_function_name(subcall):
                            mentioned_functions.add(subcall)
                else:
                    if is_valid_function_name(call):
                        mentioned_functions.add(call)
    
    print(f"    Extracted function names: {mentioned_functions}")
    
    # Check for function definitions and calls in file
    for func_name in mentioned_functions:
        found_match = False
        
        # Check for function definition (highest score)
        def_patterns = [
            rf'function\s+{re.escape(func_name)}\s*\(',
            rf'{re.escape(func_name)}\s*\([^)]*\)\s*(?:public|private|internal|external)',
            rf'function\s+{re.escape(func_name)}\b',  # Function declaration without immediate (
        ]
        
        for pattern in def_patterns:
            if re.search(pattern, file_content, re.IGNORECASE):
                max_score = max(max_score, 95.0)
                match_reasons.append(f"Function definition found: {func_name}")
                found_match = True
                break
        
        # Check for function calls (medium score)
        if not found_match:
            call_patterns = [
                rf'\b{re.escape(func_name)}\s*\(',  # Direct function call
                rf'\.{re.escape(func_name)}\s*\(',  # Method call
                rf'{re.escape(func_name)}\s*\(\s*\)',  # Function call with empty params
            ]
            for pattern in call_patterns:
                if re.search(pattern, file_content, re.IGNORECASE):
                    max_score = max(max_score, 70.0)
                    match_reasons.append(f"Function call found: {func_name}")
                    found_match = True
                    break
        
        # Check for simple mention only if it's a longer, distinctive name
        if not found_match and len(func_name) >= 6:
            # Use word boundaries to avoid substring matches
            if re.search(rf'\b{re.escape(func_name)}\b', file_content, re.IGNORECASE):
                max_score = max(max_score, 40.0)
                match_reasons.append(f"Function mentioned: {func_name}")
    
    return max_score, match_reasons

def extract_function_names_from_description(bug_report: Dict) -> Set[str]:
    """
    Extract function names from bug report description that have () after them.
    Uses the improved extraction logic.
    """
    description = bug_report.get('description', '')
    if not description:
        return set()
    
    return extract_function_names_from_text(description)

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
    
    # GitHub search boost preparation
    github_search_matches = set()
    if github_blob_urls:
        # Get repo info from first blob URL (assuming all URLs are from same repo)
        first_url = next(iter(github_blob_urls))
        repo_owner, repo_name = extract_repo_info_from_blob_url(first_url)
        
        if repo_owner and repo_name:
            print(f"\n--- GitHub Search Boost ---")
            print(f"Searching repo: {repo_owner}/{repo_name}")
            
            search_performed = False
            
            # First priority: Search for first code snippet (first 30 characters)
            if code_snippets and code_snippets[0]:
                print(f"Searching for code snippet: '{code_snippets[0][:30]}...'")
                search_results = search_github_for_code(code_snippets[0], repo_owner, repo_name, api_key)
                github_search_matches.update(search_results)
                search_performed = True
                
                # Small delay to avoid rate limiting
                time.sleep(0.1)
            
            # If no results from code snippet search, try function names from description
            if not github_search_matches and not search_performed:
                print("No code snippets found, searching for function names in description...")
                function_names = extract_function_names_from_description(bug_report)

                print(f"Raw function_names result: {function_names}")  # Add this
                print(f"Function_names type: {type(function_names)}")  # Add this
                
                if function_names:
                    print(f"Found function names in description: {list(function_names)}")
                    
                    # Try searching for each function name
                    for func_name in list(function_names)[:3]:  # Limit to first 3 to avoid rate limiting
                        print(f"Searching for function: '{func_name}'")
                        search_results = search_github_for_code(func_name, repo_owner, repo_name, api_key)
                        if search_results:
                            github_search_matches.update(search_results)
                            print(f"    Found matches for function '{func_name}': {len(search_results)} files")
                            break  # Stop after first successful function search
                        
                        # Small delay to avoid rate limiting
                        time.sleep(0.1)
                else:
                    print("No function names found in description")
            elif not github_search_matches and search_performed:
                print("No results from code snippet search, trying function names...")
                function_names = extract_function_names_from_description(bug_report)

                print(f"🔍 DEBUG: Raw function_names result: {function_names}")
                print(f"🔍 DEBUG: Function_names type: {type(function_names)}")
                print(f"🔍 DEBUG: Function_names size: {len(function_names)}")
                
                if function_names:
                    print(f"Found function names in description: {list(function_names)}")
                    
                    # Try searching for each function name
                    for func_name in list(function_names)[:3]:  # Limit to first 3 to avoid rate limiting
                        print(f"Searching for function: '{func_name}'")
                        search_results = search_github_for_code(func_name, repo_owner, repo_name, api_key)
                        if search_results:
                            github_search_matches.update(search_results)
                            print(f"    Found matches for function '{func_name}': {len(search_results)} files")
                            break  # Stop after first successful function search
                        
                        # Small delay to avoid rate limiting
                        time.sleep(0.1)
            
            if github_search_matches:
                print(f"Total GitHub search matches found: {len(github_search_matches)} files")
            else:
                print("No GitHub search matches found")
        else:
            print("Could not extract repo info for GitHub search")
    
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
        
        # 1. GitHub Search Boost (HIGHEST PRIORITY - but reduced to make room for code similarity)
        if file_path in github_search_matches:
            github_boost_score = 150.0  # Reduced from 200.0
            total_score += github_boost_score
            match_reasons.append("GitHub search found exact code snippet match")
            score_breakdown['github_search_boost'] = github_boost_score
            print(f"    🚀 GitHub Search Boost: {github_boost_score:.1f} (EXACT CODE MATCH!)")
        
        # 2. Code snippet similarity (NOW VERY HIGH PRIORITY)
        if code_snippets:
            max_code_score = 0.0
            best_snippet_idx = -1
            best_similarity_percentage = 0.0
            
            for i, snippet in enumerate(code_snippets):
                similarity = calculate_code_similarity(snippet, file_content)
                print(f"    Snippet {i+1} similarity: {similarity:.1f}%")
                if similarity > max_code_score:
                    max_code_score = similarity
                    best_snippet_idx = i
                    best_similarity_percentage = similarity
            
            # Enhanced scoring system for code similarity
            if max_code_score > 10:  # Lower threshold to capture more matches
                # Tiered scoring system based on similarity percentage
                if best_similarity_percentage >= 80:
                    # Extremely high similarity - nearly identical code
                    weighted_score = max_code_score * 6.0  # 5x multiplier
                    match_reasons.append(f"EXCELLENT code similarity (snippet {best_snippet_idx + 1}): {max_code_score:.1f}% - Nearly identical!")
                elif best_similarity_percentage >= 60:
                    # Very high similarity - substantial match
                    weighted_score = max_code_score * 5.0  # 4x multiplier
                    match_reasons.append(f"VERY HIGH code similarity (snippet {best_snippet_idx + 1}): {max_code_score:.1f}% - Strong match!")
                elif best_similarity_percentage >= 40:
                    # High similarity - good match
                    weighted_score = max_code_score * 3.5  # 3.5x multiplier
                    match_reasons.append(f"HIGH code similarity (snippet {best_snippet_idx + 1}): {max_code_score:.1f}% - Good match!")
                elif best_similarity_percentage >= 25:
                    # Moderate similarity - decent match
                    weighted_score = max_code_score * 3.0  # 3x multiplier
                    match_reasons.append(f"MODERATE code similarity (snippet {best_snippet_idx + 1}): {max_code_score:.1f}% - Decent match!")
                else:
                    # Low but relevant similarity
                    weighted_score = max_code_score * 2.0  # 2x multiplier (original weight)
                    match_reasons.append(f"Code similarity (snippet {best_snippet_idx + 1}): {max_code_score:.1f}%")
                
                total_score += weighted_score
                score_breakdown['code_similarity'] = weighted_score
                print(f"    🎯 Code Similarity Score: {weighted_score:.1f} (similarity: {best_similarity_percentage:.1f}%)")
        
        # 3. Filename mention check (MEDIUM PRIORITY - reduced weight)
        filename_score, filename_reasons = calculate_filename_mention_score(bug_report, file_path)
        if filename_score > 0:
            # Reduce filename score to not overshadow code similarity
            adjusted_filename_score = filename_score * 0.7  # Reduce by 30%
            total_score += adjusted_filename_score
            match_reasons.extend([f"(filename) {reason}" for reason in filename_reasons])
            score_breakdown['filename_mention'] = adjusted_filename_score
            print(f"    Filename mention score: {adjusted_filename_score:.1f}")
        
        # 4. Function name matches (LOWER PRIORITY)
        func_score, func_reasons = calculate_function_match_score(bug_report, file_content)
        if func_score > 0:
            # Reduce function score weight
            adjusted_func_score = func_score * 0.6  # Reduce by 40%
            total_score += adjusted_func_score
            match_reasons.extend([f"(function) {reason}" for reason in func_reasons])
            score_breakdown['functions'] = adjusted_func_score
        
        # 5. Variable name matches (LOWER PRIORITY)
        var_score, var_reasons = calculate_variable_match_score(bug_report, file_content)
        if var_score > 0:
            # Reduce variable score weight
            adjusted_var_score = var_score * 0.5  # Reduce by 50%
            total_score += adjusted_var_score
            match_reasons.extend([f"(variable) {reason}" for reason in var_reasons])
            score_breakdown['variables'] = adjusted_var_score
        
        print(f"    💯 TOTAL SCORE: {total_score:.1f}")
        print(f"    📊 Score Breakdown: {score_breakdown}")
        
        if total_score > 0:
            matched_files.append({
                'file_path': file_path,
                'file_name': file_name,
                'blob_url': blob_url,
                'total_score': total_score,
                'match_reasons': match_reasons,
                'score_breakdown': score_breakdown,
                'bug_id': bug_report.get('id', 'unknown'),
                'github_search_match': file_path in github_search_matches,
                'best_code_similarity': best_similarity_percentage if code_snippets else 0.0
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
        print(f"   GitHub Search Match: {result['github_search_match']}")
        print(f"   Reasons: {', '.join(result['match_reasons'])}")

if __name__ == "__main__":
    example_usage()