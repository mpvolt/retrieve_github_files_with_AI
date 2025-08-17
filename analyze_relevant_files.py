import json
import re
import os
from pathlib import Path
from typing import List, Dict, Set, Tuple
from fuzzywuzzy import fuzz
from determine_relevant_files import get_relevant_files 
from retrieve_all_smart_contract_functions import extract_function_names
import requests

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
        import base64
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

def extract_identifiers_from_code(code_snippet: str) -> Dict[str, List[str]]:
    """Extract function names, contract names, and variables from code snippet"""
    identifiers = {
        'functions': [],
        'contracts': [],
        'variables': [],
        'modifiers': []
    }
    
    if not code_snippet:
        return identifiers
    
    # Extract function names
    func_patterns = [
        r'function\s+(\w+)\s*\(',
        r'(\w+)\s*\([^)]*\)\s*(?:public|private|internal|external)',
        r'def\s+(\w+)\s*\('  # For Vyper
    ]
    for pattern in func_patterns:
        identifiers['functions'].extend(re.findall(pattern, code_snippet, re.IGNORECASE))
    
    # Extract contract names
    contract_patterns = [
        r'contract\s+(\w+)',
        r'interface\s+(\w+)',
        r'library\s+(\w+)'
    ]
    for pattern in contract_patterns:
        identifiers['contracts'].extend(re.findall(pattern, code_snippet, re.IGNORECASE))
    
    # Extract modifiers
    modifier_patterns = [r'modifier\s+(\w+)', r'(\w+)\s+modifier']
    for pattern in modifier_patterns:
        identifiers['modifiers'].extend(re.findall(pattern, code_snippet, re.IGNORECASE))
    
    # Extract variables (basic pattern)
    var_patterns = [
        r'(?:uint256|uint|int|bool|address|string|bytes)\s+(\w+)',
        r'mapping\s*\([^)]+\)\s+(\w+)',
        r'(\w+)\s*=\s*[^;]+;'
    ]
    for pattern in var_patterns:
        identifiers['variables'].extend(re.findall(pattern, code_snippet, re.IGNORECASE))
    
    # Clean up and deduplicate
    for key in identifiers:
        identifiers[key] = list(set([name for name in identifiers[key] if name and len(name) > 1]))
    
    return identifiers

def extract_file_paths_from_text(text: str) -> List[str]:
    """Extract potential file paths from text"""
    file_patterns = [
        r'["\']([^"\']*\.(?:sol|vy|rs|move|cairo|fc|func))["\']',  # Quoted file paths
        r'(?:^|\s)([a-zA-Z_][a-zA-Z0-9_/.-]*\.(?:sol|vy|rs|move|cairo|fc|func))(?:\s|$)',  # Unquoted
        r'(?:in|at|file)\s+([a-zA-Z_][a-zA-Z0-9_/.-]+\.(?:sol|vy|rs|move|cairo|fc|func))',  # "in file.sol"
    ]
    
    file_paths = []
    for pattern in file_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        file_paths.extend(matches)
    
    return list(set(file_paths))

def get_file_path_from_blob_url(blob_url: str) -> str:
    """Extract file path from GitHub blob URL"""
    # Example: https://github.com/owner/repo/blob/branch/path/to/file.sol
    # Extract: path/to/file.sol
    try:
        parts = blob_url.split('/blob/')
        if len(parts) > 1:
            # Remove branch name and get file path
            path_parts = parts[1].split('/', 1)
            if len(path_parts) > 1:
                return path_parts[1]  # Everything after branch name
        return Path(blob_url).name  # Fallback to just filename
    except:
        return Path(blob_url).name

def calculate_code_similarity(code_snippet: str, file_content: str) -> float:
    """Calculate similarity between code snippet and file content"""
    if not code_snippet or not file_content:
        return 0.0
    
    # Remove whitespace and normalize for comparison
    snippet_clean = re.sub(r'\s+', ' ', code_snippet.strip())
    
    # Check if snippet appears directly in file
    if snippet_clean.lower() in file_content.lower():
        return 100.0
    
    # Use fuzzy matching to find similar code blocks
    lines = file_content.split('\n')
    max_similarity = 0.0
    
    # Check against chunks of similar size
    snippet_lines = len(code_snippet.split('\n'))
    chunk_size = max(snippet_lines, 5)
    
    for i in range(0, len(lines), chunk_size // 2):
        chunk = '\n'.join(lines[i:i + chunk_size])
        chunk_clean = re.sub(r'\s+', ' ', chunk.strip())
        
        similarity = fuzz.partial_ratio(snippet_clean.lower(), chunk_clean.lower())
        max_similarity = max(max_similarity, similarity)
    
    return max_similarity

SMART_CONTRACT_EXTENSIONS = (
        '.sol', '.vy', '.rs', '.move', '.cairo', '.fc', '.func'
    )

def _paths_have_similar_structure(mentioned_path: str, actual_path: str) -> bool:
    """Check if two paths have similar directory structure"""
    mentioned_parts = Path(mentioned_path).parts
    actual_parts = Path(actual_path).parts
    
    # Check if they share significant directory components
    if len(mentioned_parts) < 2 or len(actual_parts) < 2:
        return False
    
    # Count matching directory components (excluding filename)
    mentioned_dirs = mentioned_parts[:-1]
    actual_dirs = actual_parts[:-1]
    
    common_dirs = set(mentioned_dirs) & set(actual_dirs)
    
    # Consider similar if they share at least 60% of directory components
    min_dirs = min(len(mentioned_dirs), len(actual_dirs))
    return len(common_dirs) / max(min_dirs, 1) >= 0.6

def _files_semantically_related(mentioned_file: str, actual_file: str) -> bool:
    """Check if two filenames are semantically related"""
    mentioned_name = Path(mentioned_file).stem.lower()
    actual_name = Path(actual_file).stem.lower()
    
    # Extract keywords from filenames
    def extract_keywords(filename):
        # Split on common separators and filter short words
        words = re.split(r'[_\-\./]', filename)
        return set(word for word in words if len(word) > 2)
    
    mentioned_keywords = extract_keywords(mentioned_name)
    actual_keywords = extract_keywords(actual_name)
    
    # Check for semantic relationships
    semantic_pairs = [
        (['time', 'travel'], ['travel', 'call']),
        (['verifier', 'verify'], ['call', 'executor']),
        (['engine', 'core'], ['service', 'handler']),
        (['validator', 'verifier'], ['checker', 'validator']),
    ]
    
    # Direct keyword overlap (at least 50% shared keywords)
    if mentioned_keywords and actual_keywords:
        overlap = mentioned_keywords & actual_keywords
        if len(overlap) / max(len(mentioned_keywords), len(actual_keywords)) >= 0.5:
            return True
    
    # Check semantic pairs
    for group1, group2 in semantic_pairs:
        mentioned_has_group1 = any(word in mentioned_keywords for word in group1)
        mentioned_has_group2 = any(word in mentioned_keywords for word in group2)
        actual_has_group1 = any(word in actual_keywords for word in group1)
        actual_has_group2 = any(word in actual_keywords for word in group2)
        
        if (mentioned_has_group1 and actual_has_group2) or (mentioned_has_group2 and actual_has_group1):
            return True
    
    # Fuzzy string similarity as fallback
    similarity = fuzz.ratio(mentioned_name, actual_name)
    return similarity > 70
    
def match_files_to_report(report: Dict, relevant_files: Set[str], api_key: str) -> List[Dict]:
    """Match files to a specific vulnerability report - HIGHEST SIMILARITY SCORING"""
    matched_files = []
    
    # Extract information from the report
    title = report.get('title', '')
    description = report.get('description', '')
    
    # Handle both singular and plural broken_code fields - collect ALL snippets
    broken_code_snippets = []
    
    # Check singular field first
    single_snippet = report.get('broken_code_snippet', '')
    if single_snippet and isinstance(single_snippet, str) and single_snippet.strip():
        broken_code_snippets.append(single_snippet)
    
    # Check plural field and collect all non-empty snippets
    plural_snippets = report.get('broken_code_snippets', [])
    if plural_snippets and isinstance(plural_snippets, list):
        for snippet in plural_snippets:
            if isinstance(snippet, str) and snippet.strip():
                broken_code_snippets.append(snippet)
    
    mentioned_files = report.get('files', [])
    
    # Extract file paths from title and description
    all_text = f"{title} {description}"
    mentioned_paths = extract_file_paths_from_text(all_text)
    
    # NEW: Detect smart contract extensions in the report
    required_extensions = set()
    all_report_text = f"{title} {description} {' '.join(mentioned_files) if mentioned_files else ''} {' '.join(broken_code_snippets)}"
    
    for ext in SMART_CONTRACT_EXTENSIONS:
        if ext in all_report_text:
            required_extensions.add(ext)
    
    # Filter out test files first
    non_test_files = set()
    for file_url in relevant_files:
        if 'test' not in file_url.lower() and 'errors' not in file_url.lower():
            non_test_files.add(file_url)
    
    print(f"Filtered out test files: {len(relevant_files)} -> {len(non_test_files)} files")
    relevant_files = non_test_files
    
    # If smart contract extensions are found, filter relevant_files to only include those extensions
    if required_extensions:
        print(f"Smart contract extensions detected: {required_extensions}")
        filtered_files = set()
        for file_url in relevant_files:
            file_path = get_file_path_from_blob_url(file_url)
            file_ext = Path(file_path).suffix.lower()
            if file_ext in required_extensions:
                filtered_files.add(file_url)
        
        print(f"Filtered from {len(relevant_files)} to {len(filtered_files)} files with matching extensions")
        relevant_files = filtered_files
        
        # If no files match the required extensions, return empty result
        if not relevant_files:
            print("No files found with the required smart contract extensions")
            return []
    
    # Extract identifiers from ALL broken code snippets
    all_code_identifiers = {'functions': set(), 'contracts': set(), 'variables': set(), 'modifiers': set()}
    for snippet in broken_code_snippets:
        snippet_identifiers = extract_identifiers_from_code(snippet)
        for key in all_code_identifiers:
            all_code_identifiers[key].update(snippet_identifiers[key])
    
    # Convert sets back to lists for compatibility
    code_identifiers = {k: list(v) for k, v in all_code_identifiers.items()}
    
    print(f"\nAnalyzing report: {title[:50]}...")
    print(f"Found {len(broken_code_snippets)} code snippets")
    print(f"Files mentioned: {mentioned_files}")
    print(f"Code identifiers: {code_identifiers}")
    
    # Always fetch file content for all files to enable maximum matching
    for blob_url in relevant_files:
        file_path = get_file_path_from_blob_url(blob_url)
        file_name = Path(file_path).name
        file_stem = Path(file_path).stem  # filename without extension
        
        score = 0.0
        match_reasons = []
        max_scores = {}  # Track maximum scores for each type
        
        print(f"\n  Processing: {file_path}")
        
        # ALWAYS fetch file content for comprehensive matching
        file_content = get_file_content_from_blob_url(blob_url, api_key)
        if not file_content:
            print(f"  WARNING: Could not fetch content for {blob_url}")
            continue
        
        # HIGHEST PRIORITY: Direct file name matches with files field
        if mentioned_files:
            file_match_scores = []
            for mentioned_file in mentioned_files:
                mentioned_clean = mentioned_file.lower().strip()
                mentioned_name = Path(mentioned_file).name.lower()
                mentioned_stem = Path(mentioned_file).stem.lower()
                
                # Exact filename match
                if mentioned_clean == file_name.lower():
                    file_match_scores.append(100.0)
                    match_reasons.append(f"Exact filename: {mentioned_file}")
                # Exact path match
                elif mentioned_clean == file_path.lower():
                    file_match_scores.append(100.0)
                    match_reasons.append(f"Exact path: {mentioned_file}")
                # Filename without extension match  
                elif mentioned_stem == file_stem.lower():
                    file_match_scores.append(90.0)
                    match_reasons.append(f"Filename stem: {mentioned_file}")
                # Mentioned file in full path
                elif mentioned_clean in file_path.lower():
                    file_match_scores.append(80.0)
                    match_reasons.append(f"Path contains: {mentioned_file}")
                # Full path contains mentioned file
                elif file_name.lower() in mentioned_clean:
                    file_match_scores.append(70.0)
                    match_reasons.append(f"File in mention: {mentioned_file}")
                # Similar path structure (same directory structure)
                elif _paths_have_similar_structure(mentioned_file, file_path):
                    file_match_scores.append(75.0)
                    match_reasons.append(f"Similar path structure: {mentioned_file}")
                # Semantic filename similarity (e.g., time_travel.rs vs travel_call.rs)
                elif _files_semantically_related(mentioned_file, file_path):
                    file_match_scores.append(85.0)
                    match_reasons.append(f"Semantically related: {mentioned_file}")
                # Partial filename match
                elif any(part in file_name.lower() for part in mentioned_clean.split('/') if len(part) > 2):
                    file_match_scores.append(60.0)
                    match_reasons.append(f"Partial filename: {mentioned_file}")
                    
            if file_match_scores:
                max_scores['file_name'] = max(file_match_scores)
        
        # HIGH PRIORITY: Code snippet similarity (check ALL snippets)
        if broken_code_snippets:
            code_sim_scores = []
            for i, snippet in enumerate(broken_code_snippets):
                similarity = calculate_code_similarity(snippet, file_content)
                print(f"    Code snippet {i+1} similarity: {similarity:.1f}%")
                
                if similarity > 85:  # Near-perfect match
                    code_sim_scores.append(similarity * 1.2)  # Boost high similarity
                    match_reasons.append(f"Near-perfect code match {i+1}: {similarity:.1f}%")
                elif similarity > 70:  # High similarity
                    code_sim_scores.append(similarity)
                    match_reasons.append(f"High code similarity {i+1}: {similarity:.1f}%")
                elif similarity > 50:  # Medium similarity
                    code_sim_scores.append(similarity * 0.8)
                    match_reasons.append(f"Code similarity {i+1}: {similarity:.1f}%")
                elif similarity > 30:  # Low but relevant similarity
                    code_sim_scores.append(similarity * 0.6)
                    match_reasons.append(f"Partial code match {i+1}: {similarity:.1f}%")
                        
            if code_sim_scores:
                max_scores['code_similarity'] = max(code_sim_scores)
                print(f"    Best code similarity score: {max_scores['code_similarity']:.1f}")
        
        # SPECIAL CHECK: Look for exact function signature + similar logic
        if broken_code_snippets:
            for i, snippet in enumerate(broken_code_snippets):
                # Extract function signature from snippet
                func_sig_match = re.search(r'function\s+(\w+)\s*\([^)]*\)\s*[^{]*\{', snippet, re.IGNORECASE | re.DOTALL)
                if func_sig_match:
                    func_name = func_sig_match.group(1)
                    print(f"    Looking for exact function: {func_name}")
                    
                    # Look for this exact function in file content
                    file_func_match = re.search(rf'function\s+{re.escape(func_name)}\s*\([^)]*\)\s*[^{{]*\{{([^}}]+)\}}', 
                                              file_content, re.IGNORECASE | re.DOTALL)
                    
                    if file_func_match:
                        file_func_body = file_func_match.group(1)
                        snippet_body = snippet[func_sig_match.end():].strip()
                        
                        # Remove function wrapper to compare just the logic
                        if snippet_body.endswith('}'):
                            snippet_body = snippet_body[:-1].strip()
                        
                        # Calculate similarity of function bodies
                        body_similarity = fuzz.ratio(
                            re.sub(r'\s+', ' ', snippet_body.lower()),
                            re.sub(r'\s+', ' ', file_func_body.lower())
                        )
                        
                        print(f"    Function body similarity: {body_similarity:.1f}%")
                        
                        if body_similarity > 60:  # Good function body match
                            function_bonus = 150.0 + (body_similarity - 60) * 2  # 150-230 points
                            if 'exact_function_match' not in max_scores:
                                max_scores['exact_function_match'] = 0
                            max_scores['exact_function_match'] = max(max_scores['exact_function_match'], function_bonus)
                            match_reasons.append(f"Exact function with similar logic: {func_name} ({body_similarity:.1f}%)")
                            print(f"    BONUS: Exact function match with {body_similarity:.1f}% logic similarity = {function_bonus:.1f} points")
        
        # ENHANCED: Look for semantic variable relationships
        if broken_code_snippets:
            semantic_bonus = 0
            for snippet in broken_code_snippets:
                # Extract key variables from snippet
                snippet_vars = re.findall(r'\b(\w*(?:Price|Decimals|Token|Amount|Contract))\b', snippet, re.IGNORECASE)
                file_vars = re.findall(r'\b(\w*(?:Price|Decimals|Token|Amount|Contract))\b', file_content, re.IGNORECASE)
                
                var_pairs = [
                    (['exercisePrice', 'exerciseprice'], ['repurchasePrice', 'repurchaseprice', 'purchasePrice']),
                    (['exerciseTokenDecimals', 'exercisetokendecimals'], ['repurchaseTokenDecimals', 'repurchasetokendecimals']),
                    (['exerciseToken', 'exercisetoken'], ['repurchaseToken', 'repurchasetoken']),
                ]
                
                for snippet_group, file_group in var_pairs:
                    snippet_found = any(var.lower() in [sv.lower() for sv in snippet_vars] for var in snippet_group)
                    file_found = any(var.lower() in [fv.lower() for fv in file_vars] for var in file_group)
                    
                    if snippet_found and file_found:
                        semantic_bonus += 25.0
                        match_reasons.append(f"Semantic variable mapping: {snippet_group[0]} ↔ file variables")
            
            if semantic_bonus > 0:
                max_scores['semantic_mapping'] = semantic_bonus
                print(f"    Semantic variable bonus: {semantic_bonus} points")
        
        # HIGH PRIORITY: Function name matches (from any snippet or extracted names)
        all_function_names = set()
        
        # Add extracted function names
        all_function_names.update(code_identifiers['functions'])
        
        # Extract function names directly from all snippets with more patterns
        for snippet in broken_code_snippets:
            func_patterns = [
                r'function\s+(\w+)\s*\(',
                r'(\w+)\s*\([^)]*\)\s*(?:public|private|internal|external)',
                r'(\w+)\s*\(',  # Any function call pattern
                r'\.(\w+)\s*\(',  # Method calls
            ]
            for pattern in func_patterns:
                matches = re.findall(pattern, snippet, re.IGNORECASE)
                all_function_names.update([m for m in matches if len(m) > 2])
        
        if all_function_names:
            func_match_scores = []
            for func_name in all_function_names:
                print(f"    Checking function: {func_name}")
                
                # Exact function definition patterns
                def_patterns = [
                    rf'function\s+{re.escape(func_name)}\s*\(',
                    rf'{re.escape(func_name)}\s*\([^)]*\)\s*(?:public|private|internal|external)'
                ]
                
                found_definition = False
                for pattern in def_patterns:
                    if re.search(pattern, file_content, re.IGNORECASE):
                        func_match_scores.append(95.0)
                        match_reasons.append(f"Function definition: {func_name}")
                        found_definition = True
                        break
                
                # Fuzzy function name matching for similar names
                if not found_definition:
                    # Extract all function names from file content
                    file_func_pattern = r'function\s+(\w+)\s*\('
                    file_functions = re.findall(file_func_pattern, file_content, re.IGNORECASE)
                    
                    for file_func in file_functions:
                        similarity = fuzz.ratio(func_name.lower(), file_func.lower())
                        if similarity > 80:  # High similarity threshold
                            func_match_scores.append(90.0)
                            match_reasons.append(f"Similar function: {func_name} ≈ {file_func}")
                            found_definition = True
                            break
                        elif similarity > 60:  # Medium similarity
                            func_match_scores.append(75.0)
                            match_reasons.append(f"Related function: {func_name} ≈ {file_func}")
                            found_definition = True
                            break
                
                # Function calls/references
                if not found_definition:
                    call_patterns = [
                        rf'\b{re.escape(func_name)}\s*\(',
                        rf'\.{re.escape(func_name)}\s*\(',
                        rf'{re.escape(func_name)}\b'
                    ]
                    
                    for pattern in call_patterns:
                        if re.search(pattern, file_content, re.IGNORECASE):
                            func_match_scores.append(65.0)
                            match_reasons.append(f"Function call: {func_name}")
                            break
                    else:
                        # Fuzzy function name match in content
                        if func_name.lower() in file_content.lower():
                            func_match_scores.append(45.0)
                            match_reasons.append(f"Function mention: {func_name}")
                            
            if func_match_scores:
                max_scores['function_match'] = max(func_match_scores)
        
        # HIGH PRIORITY: Contract name matches
        all_contract_names = set(code_identifiers['contracts'])

        if not isinstance(mentioned_files, list):
            mentioned_files = [mentioned_files] if mentioned_files is not None else []

        
        # Extract contract names from snippets and file references
        for snippet in broken_code_snippets + mentioned_files:
            if isinstance(snippet, str):
                contract_patterns = [
                    r'contract\s+(\w+)',
                    r'interface\s+(\w+)', 
                    r'library\s+(\w+)',
                    r'(\w+)\s*\.\s*\w+',  # Contract.method calls
                    r'(\w+Controller)',   # Common contract naming
                    r'(\w+Manager)',
                    r'(\w+Factory)',
                    r'(\w+)(?:Contract|Token|Storage)'
                ]
                for pattern in contract_patterns:
                    matches = re.findall(pattern, snippet, re.IGNORECASE)
                    all_contract_names.update([m for m in matches if len(m) > 2])
        
        if all_contract_names:
            contract_match_scores = []
            for contract_name in all_contract_names:
                print(f"    Checking contract: {contract_name}")
                
                # Contract definition patterns
                def_patterns = [
                    rf'contract\s+{re.escape(contract_name)}\b',
                    rf'interface\s+{re.escape(contract_name)}\b',
                    rf'library\s+{re.escape(contract_name)}\b'
                ]
                
                found_definition = False
                for pattern in def_patterns:
                    if re.search(pattern, file_content, re.IGNORECASE):
                        contract_match_scores.append(100.0)
                        match_reasons.append(f"Contract definition: {contract_name}")
                        found_definition = True
                        break
                
                # Contract usage/inheritance
                if not found_definition:
                    usage_patterns = [
                        rf'\b{re.escape(contract_name)}\s*\(',
                        rf'is\s+{re.escape(contract_name)}\b',
                        rf'import.*{re.escape(contract_name)}',
                        rf'{re.escape(contract_name)}\b'
                    ]
                    
                    for pattern in usage_patterns:
                        if re.search(pattern, file_content, re.IGNORECASE):
                            contract_match_scores.append(80.0)
                            match_reasons.append(f"Contract usage: {contract_name}")
                            break
                    else:
                        # Check if contract name is in filename
                        if contract_name.lower() in file_name.lower():
                            contract_match_scores.append(85.0)
                            match_reasons.append(f"Contract in filename: {contract_name}")
                        elif contract_name.lower() in file_content.lower():
                            contract_match_scores.append(60.0)
                            match_reasons.append(f"Contract mention: {contract_name}")
                            
            if contract_match_scores:
                max_scores['contract_match'] = max(contract_match_scores)
        
        # MEDIUM PRIORITY: Variable and modifier matches with similarity
        all_variable_names = set(code_identifiers['variables'])
        
        # Extract additional variables from code snippets
        for snippet in broken_code_snippets:
            var_patterns = [
                r'(?:uint256|uint|int|bool|address|string|bytes)\s+(\w+)',
                r'(\w+)\s*=\s*[^;]+;',
                r'\.(\w+)\s*\(',  # Property/method access
                r'(\w+)(?:Decimals|Price|Token|Amount|Contract)',  # Common variable suffixes
            ]
            for pattern in var_patterns:
                matches = re.findall(pattern, snippet, re.IGNORECASE)
                all_variable_names.update([m for m in matches if len(m) > 2])
        
        if all_variable_names:
            var_match_scores = []
            for var_name in all_variable_names:
                print(f"    Checking variable: {var_name}")
                
                # Exact variable match
                if var_name.lower() in file_content.lower():
                    var_match_scores.append(50.0)
                    match_reasons.append(f"Variable: {var_name}")
                else:
                    # Find similar variables in file content
                    file_var_patterns = [
                        r'(?:uint256|uint|int|bool|address|string|bytes)\s+(\w+)',
                        r'(\w+)\s*=',
                        r'\.(\w+)\s*\('
                    ]
                    
                    file_variables = set()
                    for pattern in file_var_patterns:
                        matches = re.findall(pattern, file_content, re.IGNORECASE)
                        file_variables.update([m for m in matches if len(m) > 2])
                    
                    # Check for similar variable names
                    for file_var in file_variables:
                        similarity = fuzz.ratio(var_name.lower(), file_var.lower())
                        if similarity > 75:  # High similarity for variables
                            var_match_scores.append(45.0)
                            match_reasons.append(f"Similar variable: {var_name} ≈ {file_var}")
                            break
                        elif similarity > 60:  # Medium similarity
                            var_match_scores.append(35.0)
                            match_reasons.append(f"Related variable: {var_name} ≈ {file_var}")
                            break
                    
                    # Check for variables with similar semantic meaning
                    semantic_groups = [
                        ['exercise', 'repurchase', 'purchase', 'buy'],
                        ['token', 'contract', 'asset'],
                        ['decimals', 'precision'],
                        ['price', 'rate', 'amount', 'value'],
                        ['payment', 'cost', 'fee']
                    ]
                    
                    for group in semantic_groups:
                        if any(word in var_name.lower() for word in group):
                            for file_var in file_variables:
                                if any(word in file_var.lower() for word in group):
                                    var_match_scores.append(30.0)
                                    match_reasons.append(f"Semantic variable: {var_name} ~ {file_var}")
                                    break
                            break
            
            if var_match_scores:
                max_scores['variable_match'] = max(var_match_scores)
        
        # Modifier matches
        for mod_name in code_identifiers['modifiers']:
            if mod_name.lower() in file_content.lower():
                if 'modifier_match' not in max_scores:
                    max_scores['modifier_match'] = 0
                max_scores['modifier_match'] = max(max_scores['modifier_match'], 45.0)
                match_reasons.append(f"Modifier: {mod_name}")
        
        # Calculate final score using maximum scores
        if max_scores:
            score = sum(max_scores.values())
            print(f"    Max scores: {max_scores}")
            print(f"    Total score: {score:.1f}")
            
            matched_files.append({
                'path': file_path,
                'blob_url': blob_url,
                'score': score,
                'match_reasons': match_reasons,
                'score_breakdown': max_scores
            })
        else:
            print(f"    No matches found")
    
    # Sort by score and return
    matched_files.sort(key=lambda x: x['score'], reverse=True)
    
    return matched_files

def main():
    #json_file = "veridise/filtered_VAR_VLayer250210-1-findings.json"
    #json_file = "veridise/filtered_VAR_SmoothCryptoLib_240718_V3-findings.json"
    #json_file = "zellic/filtered_WOOFi Swap.json"
    #json_file = "zellic/filtered_Nibiru.json"
    #json_file = "zellic/filtered_Metavest.json"
    #json_file = "zellic/filtered_Biconomy Smart Account.json"
    #json_file = "zellic/filtered_AccountRecoveryModule.json"
    
    # Get GitHub API key
    api_key = os.getenv('GITHUB_API_KEY')
    if not api_key:
        print("Error: GITHUB_API_KEY environment variable is not set")
        print("Please set your GitHub API token: export GITHUB_API_KEY=your_token_here")
        return None
    
    # Get all relevant files from the GitHub URLs in the JSON (now returns a dict)
    relevant_files_dict = get_relevant_files(json_file)
    
    #if we only have one or zero relevant files, no work needs to be done
    if len(relevant_files_dict) > 1:
        print("Relevant files by report:")
        for report_title, files in relevant_files_dict.items():
            print(f"  {report_title}: {len(files)} files")
        
        # Load the JSON to process each report
        with open(json_file, 'r') as f:
            reports = json.load(f)
        
        if not isinstance(reports, list):
            reports = [reports]  # Handle single report case
        
        all_matches = {}
        
        # Process each report
        for i, report in enumerate(reports):
            report_title = report.get('title', f'Report_{i+1}')
            
            # Get the relevant files for this specific report
            report_relevant_files = relevant_files_dict.get(report_title, [])
            
            if not report_relevant_files:
                print(f"\nNo relevant files found for report: {report_title}")
                all_matches[report_title] = []
                continue
                
            print(f"\nProcessing {len(report_relevant_files)} files for: {report_title}")
            
            # Convert list to set for the matching function
            report_relevant_files_set = set(report_relevant_files)
            
            # Find files that match this specific report
            matched_files = match_files_to_report(report, report_relevant_files_set, api_key)
            
            # Store results
            all_matches[report_title] = matched_files
            
            # Print top matches for this report
            print(f"\nTop matches for: {report_title}")
            print("-" * 50)
            
            top_matches = matched_files[:5]  # Show top 5
            if not top_matches:
                print("No matching files found.")
            else:
                for j, match in enumerate(top_matches):
                    print(f"{j+1}. {match['path']} (Score: {match['score']:.1f})")
                    print(f"   Reasons: {', '.join(match['match_reasons'])}")
                    
                    # Extract and display function names for top match
                    if j == 0:  # Only for the top match to avoid too many API calls
                        try:
                            functions = extract_function_names(match['blob_url'])
                            if functions:
                                print(f"   Functions: {', '.join(functions[:5])}")  # Show first 5
                        except Exception as e:
                            print(f"   Could not extract functions: {e}")
                    
                    print(f"   URL: {match['blob_url']}")
                    print()
        # Summary
        print(f"\n{'='*60}")
        print("SUMMARY")
        print(f"{'='*60}")
        
        for report_title, matches in all_matches.items():
            top_match = matches[0] if matches else None
            if top_match:
                print(f"'{report_title[:40]}...' → {top_match['path']} ({top_match['score']:.1f})")
            else:
                print(f"'{report_title[:40]}...' → No matches found")
        
        return all_matches
    else:
        return relevant_files_dict

if __name__ == "__main__":
    # Note: You may need to install required packages if not already installed
    # pip install fuzzywuzzy python-levenshtein requests
    # Also set your GitHub API key: export GITHUB_API_KEY=your_token_here
    
    matches = main()
    print(matches)