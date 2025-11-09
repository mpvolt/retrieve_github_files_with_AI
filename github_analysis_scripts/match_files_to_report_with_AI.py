#!/usr/bin/env python3
"""
Vulnerability File Matcher Script

This script takes a JSON vulnerability report and a list of GitHub blob URLs,
then uses GPT-4 to score how well each file matches the vulnerability description.
"""

import json
import re
import os
import requests
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse
from openai import OpenAI
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

@dataclass
class FileMatch:
    """Represents a file match with its score and metadata."""
    file_path: str
    blob_url: str
    content_preview: str = ""
    functions: Dict[str, str] = field(default_factory=dict)


MIN_THRESHOLD = 70

class VulnerabilityFileMatcher:
    """Main class for matching vulnerability reports to source files."""
    
    def __init__(self, openai_api_key: str, github_token: Optional[str] = None):
        """Initialize the matcher with API credentials."""
        self.openai_client = OpenAI(api_key=openai_api_key)
        self.github_token = github_token
        self.session = requests.Session()
        if github_token:
            self.session.headers.update({'Authorization': f'token {github_token}'})


    # --------------------------------------------------------------------------
    # ---------------------------- HELPER FUNCTIONS -------------------------
    # --------------------------------------------------------------------------

    def construct_blob_from_ref(self, base_url: str, blob_url: str) -> str:
        """
        Construct a GitHub blob URL pointing to the same file as `blob_url`
        but using the ref from `base_url` (commit, tree, pull, compare).
        """
        # --- Step 1. Parse blob URL ---
        blob_parts = urlparse(blob_url).path.strip("/").split("/")
        if "blob" not in blob_parts:
            raise ValueError("Invalid blob URL")
        
        owner, repo, _, ref, *file_path = blob_parts
        file_path_str = "/".join(file_path)
        
        # --- Step 2. Parse base URL ---
        base_parts = urlparse(base_url).path.strip("/").split("/")
        owner2, repo2 = base_parts[:2]
        if owner != owner2 or repo != repo2:
            raise ValueError("Blob URL and base URL must be from same repo")
        
        # --- Step 3. Resolve ref based on URL type ---
        kind = base_parts[2] if len(base_parts) > 2 else None
        ref2 = None
        
        if kind == "commit":
            # e.g. /org/repo/commit/<sha>
            ref2 = base_parts[3]
        
        elif kind == "tree":
            # e.g. /org/repo/tree/<branch_or_tag>
            ref2 = base_parts[3]
        
        elif kind == "compare":
            # e.g. /org/repo/compare/base...head
            base, head = base_parts[3].split("...")
            ref2 = head  # choose the head as "latest"
        
        elif kind == "pull":
            # e.g. /org/repo/pull/123
            pr_number = base_parts[3]
            api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
            resp = self.session.get(api_url)
            resp.raise_for_status()
            data = resp.json()
            ref2 = data["head"]["sha"]  # PR head commit SHA
        
        else:
            raise ValueError(f"Unsupported base URL type: {base_url}")
        
        # --- Step 4. Construct new blob URL ---
        new_blob_url = f"https://github.com/{owner}/{repo}/blob/{ref2}/{file_path_str}"
        return new_blob_url
    
    def fetch_file_content(self, blob_url: str) -> Optional[str]:
        """Fetch content from a GitHub blob URL."""
        try:
            # Convert blob URL to raw content URL
            if 'github.com' in blob_url and '/blob/' in blob_url:
                raw_url = blob_url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
            else:
                raw_url = blob_url
            
            response = self.session.get(raw_url, timeout=30)
            response.raise_for_status()
            
            # Only process text files
            content_type = response.headers.get('content-type', '')
            if 'text' not in content_type and 'application/json' not in content_type:
                # Try to decode as text anyway for source code files
                try:
                    return response.content.decode('utf-8')
                except UnicodeDecodeError:
                    return None
            
            return response.text
        
        except Exception as e:
            print(f"Error fetching {blob_url}: {e}")
            return None
    
    def extract_file_path_from_url(self, blob_url: str) -> str:
        """Extract the file path from a GitHub blob URL."""
        try:
            # Pattern: https://github.com/owner/repo/blob/branch/path/to/file
            parts = blob_url.split('/blob/')
            if len(parts) == 2:
                # Get everything after the branch name
                path_part = '/'.join(parts[1].split('/')[1:])
                return path_part
            return blob_url.split('/')[-1]  # Fallback to filename
        except Exception:
            return blob_url.split('/')[-1]

    # --------------------------------------------------------------------------
    # ---------------------------- FUNCTION EXTRACTION -------------------------
    # --------------------------------------------------------------------------
    def remove_comments(self, code: str, filename: str = None, language: str = None) -> str:
        """
        Removes Solidity, JavaScript, Rust, Python, Go, and Move style comments.
        Handles //, /* */, /** */ safely even across multiple lines.
        """
        # Remove block and doc comments (/* ... */ or /** ... */)
        code = re.sub(r"/\*[\s\S]*?\*/", "", code)
        # Remove single-line comments (// ...)
        code = re.sub(r"//.*", "", code)
        # Optionally handle Python or shell comments (# ...)
        code = re.sub(r"(?m)^\s*#.*$", "", code)
        return code

    def extract_function_code(self, file_content: str, function_name: str, line_number: Optional[int] = None) -> str:
        """
        Extract a specific function or modifier from source code.
        Supports Solidity, JS, Python, Rust, Move, Cairo, and Go.
        """
        if not file_content or not function_name:
            return ""

        # Remove comments first
        clean_code = self.remove_comments(file_content)

        patterns = [
            # Solidity: function name(...) {
            rf"\bfunction\s+{re.escape(function_name)}\s*\([^\)]*\)[^\{{;]*\{{",

            # Solidity: modifier name(...) {
            rf"\bmodifier\s+{re.escape(function_name)}\s*\([^\)]*\)[^\{{;]*\{{",

            # Rust: fn name(...) {
            rf"\bfn\s+{re.escape(function_name)}\s*\([^\)]*\)[^\{{;]*\{{",

            # Kotlin: fun name(...) { or public fun name(...) {
            rf"(?:public\s+)?fun\s+{re.escape(function_name)}\s*\([^\)]*\)[^\{{;]*\{{",

            # Go: func name(...) { or func (receiver) name(...) {
            rf"func\s+(?:\([^\)]*\)\s*)?{re.escape(function_name)}\s*\([^\)]*\)[^\{{;]*\{{",

            # Python: def name(...):
            rf"def\s+{re.escape(function_name)}\s*\([^\)]*\)\s*(?:->[^\:]+)?\s*\:",
        ]

        match = None
        for pat in patterns:
            m = re.search(pat, clean_code)
            if m:
                match = m
                break

        if not match:
            if line_number:
                lines = clean_code.splitlines()
                start = max(line_number - 10, 0)
                end = min(line_number + 40, len(lines))
                return "\n".join(lines[start:end])
            return ""

        start_idx = match.start()
        block_start = match.end() - 1

        # Block-based (curly braces) languages
        if match.group().strip().endswith("{"):
            brace_count = 0
            end_idx = None
            for i, ch in enumerate(clean_code[block_start:], start=block_start):
                if ch == "{":
                    brace_count += 1
                elif ch == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        end_idx = i + 1
                        break
            return clean_code[start_idx:end_idx].strip() if end_idx else clean_code[start_idx:start_idx + 1000].strip()
        else:
            # Python-style indentation
            lines = clean_code.splitlines()
            line_index = clean_code[:match.start()].count("\n")
            indent_match = re.match(r"(\s*)", lines[line_index])
            base_indent = len(indent_match.group(1)) if indent_match else 0

            block_lines = [lines[line_index]]
            for next_line in lines[line_index + 1:]:
                if not next_line.strip():
                    block_lines.append(next_line)
                    continue
                indent = len(re.match(r"(\s*)", next_line).group(1))
                if indent <= base_indent:
                    break
                block_lines.append(next_line)
            return "\n".join(block_lines).strip()


    def extract_all_functions(self, file_content: str) -> Dict[str, str]:
        """
        Extract all function and modifier names and their full code from a source file.
        Returns a dictionary: {function_name: function_code}
        """
        if not file_content:
            return {}

        # Remove comments first
        clean_code = self.remove_comments(file_content)

        # Matches functions and modifiers (Solidity, JS, Rust, Move, Go, Cairo, Python)
        patterns = [
            r"\bfunction\s+([A-Za-z0-9_]+)\s*\([^\)]*\)[^\{;]*\{",
            r"\bmodifier\s+([A-Za-z0-9_]+)\s*\([^\)]*\)[^\{;]*\{",
            r"\bconstructor\s*\([^\)]*\)[^\{;]*\{",
            r"\bfn\s+([A-Za-z0-9_]+)\s*\([^\)]*\)[^\{;]*\{",
            r"(?:public\s+)?fun\s+([A-Za-z0-9_]+)\s*\([^\)]*\)[^\{;]*\{",
            r"func\s+(?:\([^\)]*\)\s*)?([A-Za-z0-9_]+)\s*\([^\)]*\)[^\{;]*\{",
            r"def\s+([A-Za-z0-9_]+)\s*\([^\)]*\)\s*(?:->[^\:]+)?\s*\:",
        ]

        functions = {}
        for pat in patterns:
            for m in re.finditer(pat, clean_code):
                # Handle constructor (no name group)
                if "constructor" in pat:
                    name = "constructor"
                else:
                    # Get the last captured group (handles patterns with multiple groups)
                    groups = [g for g in m.groups() if g and g.strip() and "public" not in g.lower()]
                    if not groups:
                        continue
                    name = groups[-1]
                
                if name not in functions:
                    code = self.extract_function_code(file_content, name)
                    if code:  # Only add if we successfully extracted code
                        functions[name] = code

        return functions
    
    
    # --------------------------------------------------------------------------
    # ---------------------------- FUNCTION SCORING -------------------------
    # --------------------------------------------------------------------------
    def process_files(self, vulnerability_report: Dict[str, Any], blob_urls: List[str], max_workers: int = 5) -> List[FileMatch]:
        """
        Determines which functions are relevant to the bug using parallel processing
        
        Args:
            vulnerability_report: Dictionary containing vulnerability report data
            blob_urls: Blob urls of files that will be checked
            max_workers: Maximum number of parallel workers (default: 5)
            
        Returns:
            list: List of FileMatch objects containing source url and relevant functions (only highest scoring)
        """
        matches = []
        
        print(f"Processing {len(blob_urls)} files in parallel (max {max_workers} workers)...")
        
        def process_single_file(blob_url: str, index: int) -> Tuple[int, FileMatch]:
            """Process a single file and return its match."""
            print(f"Processing file {index}/{len(blob_urls)}: {blob_url}")
            
            # Extract file path
            file_path = self.extract_file_path_from_url(blob_url)
            
            # Fetch file content
            content = self.fetch_file_content(blob_url)
            if not content:
                print(f"  Skipped (could not fetch content): {blob_url}")
                return None
            
            # Score the match (now handles chunking internally)
            function_results = self.score_file_match(vulnerability_report, content, file_path)
            
            # Create match object
            if not function_results:
                print(f"No matching functions found in {blob_url}")
                return None
            
            match = FileMatch(
                file_path=file_path,
                blob_url=blob_url,
                functions=function_results
            )
            
            return (index, match)
        
        # Process files in parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_url = {
                executor.submit(process_single_file, blob_url, i): (i, blob_url) 
                for i, blob_url in enumerate(blob_urls, 1)
            }
            
            # Collect results as they complete
            results = []
            for future in as_completed(future_to_url):
                try:
                    result = future.result()
                    if result is not None:
                        results.append(result)
                except Exception as e:
                    index, blob_url = future_to_url[future]
                    print(f"Error processing {blob_url}: {str(e)}")
            
            # Sort by original index to maintain order
            results.sort(key=lambda x: x[0])
            matches = [match for _, match in results]
        
        # Find the highest score across all files and functions
        if matches:
            max_score = 0
            for match in matches:
                for func in match.functions:
                    if func['score'] > max_score:
                        max_score = func['score']
            
            print(f"\nHighest score across all files: {max_score}")
            
            # Filter matches to only include functions with the highest score
            filtered_matches = []
            for match in matches:
                high_score_functions = [func for func in match.functions if func['score'] == max_score]
                if high_score_functions:
                    filtered_match = FileMatch(
                        file_path=match.file_path,
                        blob_url=match.blob_url,
                        functions=high_score_functions
                    )
                    filtered_matches.append(filtered_match)
            
            print(f"Files with highest scoring functions: {len(filtered_matches)}")
            return filtered_matches
        
        return matches

    def score_file_match(self, vulnerability_report: Dict[str, Any], file_content: str, file_path: str, max_workers: int = 10) -> List[Dict[str, Any]]:
        """Use GPT-4 to score how well functions match the vulnerability report.
        Handles scoring in parallel for better performance.
        
        Args:
            vulnerability_report: Dictionary containing vulnerability report data
            file_content: Content of the file to analyze
            file_path: Path to the file
            max_workers: Maximum number of parallel workers for function scoring (default: 10)
            
        Returns:
            list: List of dicts with function names and scores >= 70
        """
        
        all_functions = self.extract_all_functions(file_content)
        function_results = []
        
        def score_single_function_wrapper(function_name: str, function_code: str) -> Tuple[str, int]:
            """Wrapper to score a single function and return name and score."""
            print(f"Scoring function: {function_name}")
            result = self._score_single_function(vulnerability_report, function_code, file_path, function_name)
            score = result.get('score', 0)
            return (function_name, score)
        
        # Process functions in parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all function scoring tasks
            future_to_function = {
                executor.submit(score_single_function_wrapper, func_name, func_code): func_name
                for func_name, func_code in all_functions.items()
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_function):
                func_name = future_to_function[future]
                try:
                    function_name, score = future.result()
                    print(f"{function_name}: score={score}")
                    if score >= 70:
                        function_results.append(
                            {
                                "function": function_name,
                                "score": score
                            }
                        )
                except Exception as e:
                    print(f"Error scoring function {func_name}: {str(e)}")
        
        print(f"Functions with score >= 70: {function_results}")
        return function_results


    def _score_single_function(self, vulnerability_report: Dict[str, Any], content: str, file_path: str, function_name: str) -> Dict[str, Any]:
        """Score a single chunk of file content."""

        print(f"Analyzing {function_name}")

        # Extract key vulnerability indicators
        vuln_title = vulnerability_report.get('title', '')
        vuln_description = vulnerability_report.get('description', '')
        vuln_recommendation = vulnerability_report.get('recommendation', '')
        severity = vulnerability_report.get('severity', 'Unknown')
        category = vulnerability_report.get('category', 'Unknown')
        files = vulnerability_report.get('files', 'Unknown')
        
        # Combine most relevant fields (truncate intelligently)
        vuln_context = f"""
        Title: {vuln_title[:500]}
        Severity: {severity}
        Category: {category}
        Description: {vuln_description[:1500]}
        Recommendation: {vuln_recommendation[:1000]}
        Files: {files}
        """

        prompt = f"""You are a Web3 security expert analyzing smart contract code for vulnerabilities.

        VULNERABILITY REPORT:
        {vuln_context}

        CODE TO ANALYZE:
        File: {file_path}
        Function: {function_name}
        ```
        {content[:3000]}  
        ```

        ANALYSIS TASK:
        Determine if this function contains or is directly related to the vulnerability described above.

        SCORING CRITERIA:
        - 90-100: Function name, variable names, and logic patterns DIRECTLY match the vulnerability description
        - 70-89: Function contains the problematic code pattern described, with matching context
        - 50-69: Function has related functionality and some matching elements (variables/logic)
        - 30-49: Function is in the same contract/file area but doesn't match specific patterns
        - 10-29: Function has tangential relevance (similar domain but different purpose)
        - 0-9: Completely unrelated to the vulnerability

        FOCUS ON:
        1. Exact function names mentioned in the report (e.g., "_withdrawInOrder", "getExchangeRate")
        2. Specific variable names mentioned (e.g., "exchangeRate", "withdrawableBalance", "totalWithdrawableBalanceInAssets")
        3. Problematic code patterns (e.g., "division before multiplication", "rounding errors")
        4. Mathematical operations and their order
        5. Contract/file context matches

        IMPORTANT:
        - Be STRICT: Only score 70+ if you find SPECIFIC matches to the vulnerability
        - Generic functions that happen to be in the same file should score 30-50 max
        - If the function name doesn't match AND the logic doesn't match, score should be low (0-30)

        Respond ONLY with valid JSON (no markdown, no code blocks):
        {{
            "name": "{function_name}",
            "score": <number 0-100>,
            "reasoning": "<1-2 sentence explanation focusing on specific matches or mismatches>",
            "confidence": "<high|medium|low>",
            "key_matches": ["<specific function names, variables, or patterns found>"]
        }}"""

        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4o",  # Using full gpt-4o for better accuracy
                messages=[
                    {
                        "role": "system", 
                        "content": "You are a smart contract security expert. Analyze code precisely and return only valid JSON responses."
                    },
                    {
                        "role": "user", 
                        "content": prompt
                    }
                ],
                temperature=0.0,  # More deterministic
                max_tokens=600,
                response_format={"type": "json_object"}  # Force JSON output
            )
            
            result_text = response.choices[0].message.content.strip()
            
            # Parse JSON response
            result = json.loads(result_text)
            
            # Validate required fields
            if "score" not in result:
                raise ValueError("Response missing 'score' field")
            
            # Ensure score is in valid range
            result["score"] = max(0, min(100, int(result["score"])))
            
            # Add function name if missing
            if "name" not in result:
                result["name"] = function_name
                
            # Ensure all required fields exist
            result.setdefault("reasoning", "No reasoning provided")
            result.setdefault("confidence", "medium")
            result.setdefault("key_matches", [])
            
            return result
        
        except json.JSONDecodeError as e:
            print(f"JSON parsing error for {file_path}/{function_name}: {e}")
            print(f"Response was: {result_text[:200]}")
            return {
                "name": function_name,
                "score": 0,
                "reasoning": "Failed to parse GPT response as JSON",
                "confidence": "low",
                "key_matches": []
            }
        
        except Exception as e:
            print(f"Error scoring function {function_name} in {file_path}: {e}")
            return {
                "name": function_name,
                "score": 0,
                "reasoning": f"API error: {str(e)[:100]}",
                "confidence": "low",
                "key_matches": []
            }

    def _parse_gpt_response(self, text: str) -> Dict[str, Any]:
        """Try multiple strategies to parse GPT response into JSON."""
        
        # Strategy 1: Direct JSON parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        
        # Strategy 2: Extract JSON from markdown code blocks
        json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass
        
        # Strategy 3: Find first { to last } and parse that
        try:
            start = text.index('{')
            end = text.rindex('}') + 1
            return json.loads(text[start:end])
        except (ValueError, json.JSONDecodeError):
            pass
        
        # Strategy 4: Clean common issues and retry
        try:
            cleaned = text.replace('\n', ' ').replace('\r', '')
            cleaned = re.sub(r',\s*([}\]])', r'\1', cleaned)  # Remove trailing commas
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass
        
        # Strategy 5: Try to fix common JSON errors
        try:
            fixed = text
            # Fix single quotes to double quotes
            fixed = fixed.replace("'", '"')
            # Remove comments
            fixed = re.sub(r'//.*?$', '', fixed, flags=re.MULTILINE)
            fixed = re.sub(r'/\*.*?\*/', '', fixed, flags=re.DOTALL)
            # Try parsing again
            return json.loads(fixed)
        except json.JSONDecodeError:
            pass
        
        return None

def create_summary_result(report_id: str, report_title: str, report: Dict[str, Any], top_match: Optional[FileMatch]):
    """Create a summary result entry for reporting."""
    return {
        'id': report_id,
        'title': report_title,
        'severity': report.get('severity', 'Unknown'),
        'top_match': {
            'file_path': top_match.file_path if top_match else None,
            'score': top_match.total_score if top_match else 0,
            'url': top_match.blob_url if top_match else None
        } if top_match else None,
    }


def print_match_results(report_title: str, matched_files: List[FileMatch], high_confidence_matches: List[FileMatch]):
    """Print the matching results for a report."""
    print(f"\nTop matches for: {report_title}")
    print("-" * 50)
    
    if not matched_files:
        print("No matching files found.")
    elif not high_confidence_matches:
        print(f"Found {len(matched_files)} matches but none met the 60+ score threshold.")
        print("Top candidates (below threshold):")
        for j, match in enumerate(matched_files[:3]):  # Show top 3 low-confidence matches
            print(f"  {j+1}. {match.file_path} (Score: {match.total_score:.1f}) - BELOW THRESHOLD")
    else:
        print(f"High-confidence matches (85+ score):")
        _print_high_confidence_matches(high_confidence_matches)


def _print_high_confidence_matches(high_confidence_matches: List[FileMatch]):
    """Print detailed information about high-confidence matches."""
    for j, match in enumerate(high_confidence_matches[:5]):  # Show top 5 high-confidence
        print(f"{j+1}. {match.file_path} (Score: {match.total_score:.1f})")
        print(f"   Reasons: {', '.join(match.match_reasons) if match.match_reasons else 'No specific reasons provided'}")
        print(f"   URL: {match.blob_url}")
        print()


def main():
    """Main function to run the vulnerability file matcher."""
    
    # Get API key from environment
    openai_api_key = os.getenv("OPENAI_API_KEY")
    if not openai_api_key:
        raise ValueError("OPENAI_API_KEY environment variable is required")
    
    # Optional GitHub token from environment
    github_token = os.getenv("GITHUB_API_KEY")
    
    # Example usage
    vulnerability_report = {
        "title": "Delegation double spend attack",
        "severity": "High",
        "description": "Voting mechamism of the Boltr token is susceptible to double spend attack .",
        "recommendation": "Remove voting mechanism from token if it's not going to be used of fix the\ndegation mechanism by transferring votes in the transfer() and transferFrom() functions.\nUpdate: Issue was fixed by removing voting mechanism.",   
    }
    
    # Example GitHub blob URLs
    blob_urls = [
    "https://github.com/boltrswap/Boltr-Farm/blob/fe4b3b2f3cea7444830ace483eed813d8f828cdb/contracts/libs/SafeKRC20.sol",
    "https://github.com/boltrswap/Boltr-Farm/blob/fe4b3b2f3cea7444830ace483eed813d8f828cdb/contracts/libs/Migrations.sol",
    "https://github.com/boltrswap/Boltr-Farm/blob/fe4b3b2f3cea7444830ace483eed813d8f828cdb/contracts/BoltrSwap.sol",
    "https://github.com/boltrswap/Boltr-Farm/blob/fe4b3b2f3cea7444830ace483eed813d8f828cdb/contracts/libs/KRC20.sol",
    "https://github.com/boltrswap/Boltr-Farm/blob/fe4b3b2f3cea7444830ace483eed813d8f828cdb/contracts/libs/MockKRC20.sol",
    "https://github.com/boltrswap/Boltr-Farm/blob/fe4b3b2f3cea7444830ace483eed813d8f828cdb/contracts/libs/IKRC20.sol",
    "https://github.com/boltrswap/Boltr-Farm/blob/fe4b3b2f3cea7444830ace483eed813d8f828cdb/contracts/Timelock.sol",
    "https://github.com/boltrswap/Boltr-Farm/blob/fe4b3b2f3cea7444830ace483eed813d8f828cdb/contracts/MasterChef.sol"
    ]

    
    # Initialize matcher
    matcher = VulnerabilityFileMatcher(openai_api_key, github_token)
    
    #Process files
    matches = matcher.process_files(vulnerability_report, blob_urls)
    
    # Filter high confidence matches (score >= 85)
    high_confidence_matches = [match for match in matches if match.total_score >= MIN_THRESHOLD]
    
    # Print results
    print_match_results(vulnerability_report['title'], matches, high_confidence_matches)
    
    
    # Create summary
    top_match = matches[0] if matches else None
    summary = create_summary_result("VULN-001", vulnerability_report['title'], vulnerability_report, top_match)

    function_matches = matcher.score_function_matches(vulnerability_report, top_match.blob_url)

    print(f"Function matches: {function_matches}")
    
    print(f"\nSummary:")
    print(json.dumps(summary, indent=2))
    
    print(f"Top match: {top_match}")
    return top_match


if __name__ == "__main__":
    main()