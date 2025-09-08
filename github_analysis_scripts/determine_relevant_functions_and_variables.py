#!/usr/bin/env python3
"""
Bug Report File Analysis Script

This script analyzes bug reports to determine which functions, variables, and line numbers
in source files are relevant to the reported issues.
"""

import json
import re
import sys
import requests
from typing import Dict, List, Tuple, Set, Optional
from urllib.parse import urlparse, parse_qs
from fuzzywuzzy import fuzz


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


def extract_function_names_from_text(text: str) -> Set[str]:
    """Extract potential function names from text."""
    function_names = set()
    
    # Common function definition patterns
    patterns = [
        r'function\s+(\w+)\s*\(',           # function functionName(
        r'def\s+(\w+)\s*\(',               # def functionName(
        r'(\w+)\s*\([^)]*\)\s*{',          # functionName() {
        r'(\w+)\s*\([^)]*\)\s*=>',         # functionName() =>
        r'(\w+)\s*:\s*function',           # functionName: function
        r'\.(\w+)\s*\(',                   # .functionName(
        r'(\w+)\(\)',                      # functionName()
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        function_names.update(m for m in matches if len(m) > 2 and m.isidentifier())
    
    return function_names


def extract_variable_names_from_text(text: str) -> Set[str]:
    """Extract potential variable names from text."""
    variable_names = set()
    
    # Common variable patterns
    patterns = [
        r'\b([a-zA-Z_]\w*)\s*=\s*',                    # variable =
        r'\b([A-Z_][A-Z0-9_]*)\b',                     # CONSTANT_STYLE
        r'\b([a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*)\b',   # camelCase
        r'\b([A-Z][a-z][a-zA-Z0-9]*)\b',               # PascalCase
        r'\.(\w+)\b',                                  # .variableName
        r'\[(\w+)\]',                                  # [variableName]
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, text)
        variable_names.update(m for m in matches if len(m) > 2 and m.isidentifier())
    
    return variable_names


def extract_code_snippets(bug_report: Dict) -> List[str]:
    """Extract code snippets from bug report."""
    snippets = []
    
    # Get text content
    content = ""
    for field in ['title', 'description', 'recommendation']:
        if field in bug_report:
            content += bug_report[field] + "\n"
    
    # Extract code blocks (markdown style)
    code_blocks = re.findall(r'```[\w]*\n(.*?)\n```', content, re.DOTALL)
    snippets.extend(code_blocks)
    
    # Extract inline code
    inline_code = re.findall(r'`([^`]+)`', content)
    snippets.extend(inline_code)
    
    # Extract function-like patterns
    function_patterns = re.findall(r'(\w+\s*\([^)]*\)\s*{[^}]*})', content)
    snippets.extend(function_patterns)
    
    return [s.strip() for s in snippets if s.strip()]


def calculate_function_match_score(bug_report: Dict, file_content: str) -> Tuple[float, List[str]]:
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


def calculate_variable_match_score(bug_report: Dict, file_content: str) -> Tuple[float, List[str]]:
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


def fetch_github_file_content(url: str) -> Optional[str]:
    """Fetch file content from GitHub URL."""
    try:
        # Convert GitHub URL to raw content URL
        if 'github.com' in url:
            # Handle different GitHub URL formats
            if '/blob/' in url:
                # Regular file view URL
                raw_url = url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
            elif '/tree/' in url:
                # Directory view - can't fetch content
                print(f"Warning: Cannot fetch directory content from {url}")
                return None
            else:
                # Assume it's already a raw URL or API URL
                raw_url = url
            
            response = requests.get(raw_url)
            response.raise_for_status()
            return response.text
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None


def extract_line_numbers_from_url(url: str) -> Optional[Tuple[int, int]]:
    """Extract line number range from GitHub URL."""
    # Look for #L patterns in URL
    match = re.search(r'#L(\d+)(?:-L(\d+))?', url)
    if match:
        start_line = int(match.group(1))
        end_line = int(match.group(2)) if match.group(2) else start_line
        return (start_line, end_line)
    return None


def get_lines_from_content(content: str, start_line: int, end_line: int) -> str:
    """Extract specific lines from file content."""
    lines = content.split('\n')
    if start_line <= len(lines):
        return '\n'.join(lines[start_line-1:end_line])
    return ""


def analyze_github_diff(url: str) -> List[Dict]:
    """Analyze GitHub commit/PR diff to find changed functions and lines."""
    try:
        # Convert to patch/diff URL
        if '/pull/' in url:
            diff_url = url + '.diff'
        elif '/commit/' in url:
            diff_url = url + '.diff'
        else:
            print(f"Unsupported URL format: {url}")
            return []
        
        response = requests.get(diff_url)
        response.raise_for_status()
        diff_content = response.text
        
        # Parse diff to find changed files and lines
        changed_files = []
        current_file = None
        
        for line in diff_content.split('\n'):
            if line.startswith('diff --git'):
                # New file in diff
                file_path = line.split(' ')[-1][2:]  # Remove 'b/' prefix
                
                # Only process smart contract files
                if not any(file_path.lower().endswith(ext) for ext in SMART_CONTRACT_EXTENSIONS):
                    print(f"Skipping non-smart-contract file in diff: {file_path}")
                    current_file = None
                    continue
                    
                current_file = {
                    'file_path': file_path,
                    'changed_lines': [],
                    'changed_functions': set()
                }
                changed_files.append(current_file)
            elif line.startswith('@@') and current_file:
                # Line number information
                match = re.search(r'@@ -\d+,?\d* \+(\d+),?(\d*) @@', line)
                if match:
                    start_line = int(match.group(1))
                    line_count = int(match.group(2)) if match.group(2) else 1
                    current_file['changed_lines'].append((start_line, start_line + line_count - 1))
            elif line.startswith('+') and not line.startswith('+++') and current_file:
                # Added line - look for function definitions
                func_patterns = [
                    r'function\s+(\w+)\s*\(',
                    r'def\s+(\w+)\s*\(',
                    r'(\w+)\s*\([^)]*\)\s*{',
                ]
                for pattern in func_patterns:
                    matches = re.findall(pattern, line)
                    current_file['changed_functions'].update(matches)
        
        # Convert sets to lists for JSON serialization
        for file_info in changed_files:
            file_info['changed_functions'] = list(file_info['changed_functions'])
        
        return changed_files
        
    except Exception as e:
        print(f"Error analyzing diff {url}: {e}")
        return []


def analyze_bug_report(bug_report: Dict) -> Dict:
    """Analyze a single bug report and return relevance analysis."""
    result = {
        'title': bug_report.get('title', ''),
        'severity': bug_report.get('severity', ''),
        'relevant_files': [],
        'extracted_functions': list(extract_function_names_from_text(
            f"{bug_report.get('title', '')} {bug_report.get('description', '')}"
        )),
        'extracted_variables': list(extract_variable_names_from_text(
            f"{bug_report.get('title', '')} {bug_report.get('description', '')} {bug_report.get('recommendation', '')}"
        )),
        'code_snippets': extract_code_snippets(bug_report)
    }
    
    print(f"\nAnalyzing: {result['title']}")
    print(f"Functions found: {result['extracted_functions']}")
    print(f"Variables found: {result['extracted_variables']}")
    
    # Track if we successfully processed any source code
    source_code_processed = False
    
    # Process source code URLs first
    if 'source_code_url' in bug_report:
        for url in bug_report['source_code_url']:
            print(f"\nProcessing source URL: {url}")
            
            # Extract line numbers if present
            line_range = extract_line_numbers_from_url(url)
            
            # Fetch file content
            file_content = fetch_github_file_content(url)
            if file_content:
                source_code_processed = True
                file_info = {
                    'url': url,
                    'type': 'source',
                    'functions_found': [],
                    'variables_found': [],
                    'line_range': line_range,
                    'relevance_score': 0.0,
                    'match_reasons': []
                }
                
                # If specific lines mentioned, focus on those
                if line_range:
                    relevant_content = get_lines_from_content(file_content, line_range[0], line_range[1])
                    file_info['relevant_lines'] = relevant_content
                else:
                    relevant_content = file_content
                
                # Calculate relevance scores
                func_score, func_reasons = calculate_function_match_score(bug_report, relevant_content)
                var_score, var_reasons = calculate_variable_match_score(bug_report, relevant_content)
                
                # Calculate code similarity with snippets
                snippet_scores = []
                for snippet in result['code_snippets']:
                    snippet_score = calculate_code_similarity(snippet, relevant_content)
                    snippet_scores.append(snippet_score)
                
                max_snippet_score = max(snippet_scores) if snippet_scores else 0.0
                
                file_info['relevance_score'] = max(func_score, var_score, max_snippet_score)
                file_info['match_reasons'] = func_reasons + var_reasons
                
                if max_snippet_score > 50:
                    file_info['match_reasons'].append(f"Code snippet similarity: {max_snippet_score:.1f}%")
                
                result['relevant_files'].append(file_info)
    
    # Only process fix commit URLs if no source code was successfully processed
    if not source_code_processed and 'fix_commit_url' in bug_report:
        print(f"\nNo source code found, processing fix commit URLs...")
        for url in bug_report['fix_commit_url']:
            print(f"\nProcessing fix URL: {url}")
            
            changed_files = analyze_github_diff(url)
            for file_change in changed_files:
                file_info = {
                    'url': url,
                    'type': 'fix_commit',
                    'file_path': file_change['file_path'],
                    'changed_lines': file_change['changed_lines'],
                    'changed_functions': file_change['changed_functions'],
                    'relevance_score': 90.0,  # High relevance for fix commits
                    'match_reasons': ['File was modified in fix commit']
                }
                
                result['relevant_files'].append(file_info)
    elif source_code_processed and 'fix_commit_url' in bug_report:
        print(f"\nSource code URLs processed successfully, skipping fix commit URLs")
    
    return result


def main():
    """Main function to process bug reports from JSON file."""
    if len(sys.argv) != 2:
        print("Usage: python script.py <bug_reports.json>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            bug_reports = json.load(f)
    except Exception as e:
        print(f"Error reading input file: {e}")
        sys.exit(1)
    
    if not isinstance(bug_reports, list):
        bug_reports = [bug_reports]
    
    results = []
    
    for i, bug_report in enumerate(bug_reports):
        print(f"\n{'='*60}")
        print(f"Processing bug report {i+1}/{len(bug_reports)}")
        print(f"{'='*60}")
        
        try:
            analysis = analyze_bug_report(bug_report)
            results.append(analysis)
        except Exception as e:
            print(f"Error processing bug report {i+1}: {e}")
            continue
    
    # Output results
    output_file = input_file.replace('.json', '_analysis.json')
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n\nAnalysis complete! Results saved to: {output_file}")
    except Exception as e:
        print(f"Error saving results: {e}")
        # Print to stdout as fallback
        print("\n\nResults:")
        print(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()