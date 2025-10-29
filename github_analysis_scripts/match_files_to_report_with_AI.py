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
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from openai import OpenAI
from dataclasses import dataclass


@dataclass
class FileMatch:
    """Represents a file match with its score and metadata."""
    file_path: str
    blob_url: str
    total_score: float
    match_reasons: List[str]
    content_preview: str = ""


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
    
    def chunk_file_content(self, content: str, max_chunk_size: int = 8000, overlap: int = 500) -> List[str]:
        """Split file content into overlapping chunks."""
        if len(content) <= max_chunk_size:
            return [content]
        
        chunks = []
        start = 0
        
        while start < len(content):
            end = start + max_chunk_size
            chunk = content[start:end]
            chunks.append(chunk)
            
            # Move start forward, accounting for overlap
            start = end - overlap
            
            # Break if we've covered the whole file
            if end >= len(content):
                break
        
        return chunks


    def score_file_match(self, vulnerability_report: Dict[str, Any], file_content: str, file_path: str) -> Dict[str, Any]:
        """Use GPT-4 to score how well a file matches the vulnerability report.
        Handles large files by chunking and aggregating scores."""
        
        max_chunk_size = 8000
        chunks = self.chunk_file_content(file_content, max_chunk_size)
        
        # If single chunk, process normally
        if len(chunks) == 1:
            return self._score_single_chunk(vulnerability_report, chunks[0], file_path, chunk_info="")
        
        # Process multiple chunks
        print(f"  File too large, processing {len(chunks)} chunks...")
        chunk_results = []
        
        for idx, chunk in enumerate(chunks, 1):
            chunk_info = f" (chunk {idx}/{len(chunks)})"
            result = self._score_single_chunk(vulnerability_report, chunk, file_path, chunk_info)
            chunk_results.append(result)
        
        # Aggregate results: use max score and combine key matches
        max_score_result = max(chunk_results, key=lambda x: x.get('score', 0))
        all_key_matches = []
        for result in chunk_results:
            all_key_matches.extend(result.get('key_matches', []))
        
        # Remove duplicates while preserving order
        unique_matches = []
        seen = set()
        for match in all_key_matches:
            if match not in seen:
                unique_matches.append(match)
                seen.add(match)
        
        return {
            "score": max_score_result.get('score', 0),
            "reasoning": f"Max score from {len(chunks)} chunks: {max_score_result.get('reasoning', 'N/A')}",
            "confidence": max_score_result.get('confidence', 'low'),
            "key_matches": unique_matches
        }


    def _score_single_chunk(self, vulnerability_report: Dict[str, Any], content: str, file_path: str, chunk_info: str = "") -> Dict[str, Any]:
        """Score a single chunk of file content."""
        
        prompt = f"""
    You are a security expert analyzing whether a source code file matches a vulnerability report.

    VULNERABILITY REPORT:
    Title: {vulnerability_report.get('title', 'N/A')}
    Description: {vulnerability_report.get('description', 'N/A')}
    Recommendation: {vulnerability_report.get('recommendation', 'N/A')}
    Broken Code Snippets: {vulnerability_report.get('broken_code_snippets', [])}
    Source Code URL: {vulnerability_report.get('source_code_url', 'N/A')}
    Fix Commit URL: {vulnerability_report.get('fix_commit_url', 'N/A')}
    Files: {vulnerability_report.get('files', 'N/A')}

    FILE TO ANALYZE:
    File Path: {file_path}{chunk_info}
    File Content:
    {content}

    TASK:
    Score this file from 0-100 based on how likely it contains the vulnerability described:
    - 0: Completely irrelevant
    - 1-30: Low relevance (mentions some related concepts but unlikely to be the vulnerable file)
    - 31-60: Medium relevance (contains related functionality but may not be the exact vulnerable code)
    - 61-89: High relevance (strong indicators this contains the vulnerability)
    - 90-100: Very high relevance (almost certainly contains the exact vulnerability)

    Consider:
    1. Function names mentioned in the vulnerability
    2. Code patterns described in the vulnerability
    3. Variable names and logic described
    4. Overall context and purpose of the file

    Respond in JSON format:
    {{
        "score": <number 0-100>,
        "reasoning": "<brief explanation of your scoring>",
        "confidence": "<high|medium|low>",
        "key_matches": ["<list of specific matches found>"]
    }}
    """

        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=500
            )
            
            result_text = response.choices[0].message.content
            # Try to parse JSON from the response
            try:
                result = json.loads(result_text)
                return result
            except json.JSONDecodeError:
                # Fallback: extract score with regex if JSON parsing fails
                score_match = re.search(r'"score":\s*(\d+)', result_text)
                score = int(score_match.group(1)) if score_match else 0
                return {
                    "score": score,
                    "reasoning": "GPT-4o-mini response parsing failed",
                    "confidence": "low",
                    "key_matches": []
                }
        
        except Exception as e:
            print(f"Error scoring file {file_path}{chunk_info}: {e}")
            return {
                "score": 0,
                "reasoning": f"API error: {e}",
                "confidence": "low",
                "key_matches": []
            }


    def process_files(self, vulnerability_report: Dict[str, Any], blob_urls: List[str]) -> List[FileMatch]:
        """Process all files and return sorted matches."""
        matches = []
        
        print(f"Processing {len(blob_urls)} files...")
        
        for i, blob_url in enumerate(blob_urls, 1):
            print(f"Processing file {i}/{len(blob_urls)}: {blob_url}")
            
            # Extract file path
            file_path = self.extract_file_path_from_url(blob_url)
            
            # Fetch file content
            content = self.fetch_file_content(blob_url)
            if not content:
                print(f"  Skipped (could not fetch content)")
                continue
            
            # Score the match (now handles chunking internally)
            score_result = self.score_file_match(vulnerability_report, content, file_path)
            
            # Create match object
            match = FileMatch(
                file_path=file_path,
                blob_url=blob_url,
                total_score=score_result.get('score', 0),
                match_reasons=score_result.get('key_matches', []),
                content_preview=content[:200] + "..." if len(content) > 200 else content
            )
            
            matches.append(match)
            print(f"  Score: {match.total_score}/100 - {score_result.get('reasoning', 'No reasoning')}")

            if match.total_score >= 95:
                print(f"  Found high-confidence match (score >= 95). Returning immediately.")
                return [match]
        
        # Sort by score (highest first)
        matches.sort(key=lambda x: x.total_score, reverse=True)
        high_confidence_matches = [match for match in matches if match.total_score >= MIN_THRESHOLD]
        return high_confidence_matches

    def score_function_matches(self, vulnerability_report: Dict[str, Any], blob_url: str) -> Dict[str, Any]:
        """Use GPT-4 to extract functions from code and rank them by vulnerability relevance."""
        
        file_content = self.fetch_file_content(blob_url)
        max_content_length = 8000
        
        # Check if chunking is needed
        if len(file_content) <= max_content_length:
            # Process single chunk
            return self._analyze_code_chunk(
                vulnerability_report, 
                file_content, 
                blob_url,
                chunk_index=0,
                total_chunks=1
            )
        
        # Process large file in chunks
        return self._analyze_large_file_in_chunks(
            vulnerability_report,
            file_content,
            blob_url,
            max_content_length
        )

    def _analyze_large_file_in_chunks(
        self, 
        vulnerability_report: Dict[str, Any], 
        file_content: str, 
        blob_url: str,
        max_chunk_size: int
    ) -> Dict[str, Any]:
        """Analyze a large file by splitting it into chunks and merging results."""
        
        # Split content into chunks with overlap to avoid splitting functions
        overlap = 500  # Character overlap between chunks to catch split functions
        chunks = []
        start = 0
        
        while start < len(file_content):
            end = start + max_chunk_size
            
            # If not the last chunk, try to break at a logical boundary
            if end < len(file_content):
                # Look for function/class boundaries (common patterns)
                chunk_content = file_content[start:end]
                
                # Try to find a good break point (end of function, class, or blank line)
                last_newlines = chunk_content.rfind('\n\n')
                last_def = chunk_content.rfind('\ndef ')
                last_class = chunk_content.rfind('\nclass ')
                
                # Use the latest boundary found
                break_point = max(last_newlines, last_def, last_class)
                
                if break_point > max_chunk_size * 0.7:  # Only use if in latter 30% of chunk
                    end = start + break_point
            
            chunks.append({
                'content': file_content[start:end],
                'start_pos': start,
                'end_pos': min(end, len(file_content))
            })
            
            # Move to next chunk with overlap
            start = end - overlap if end < len(file_content) else end
        
        print(f"Analyzing {blob_url} in {len(chunks)} chunks...")
        
        # Analyze each chunk
        all_functions = []
        chunk_summaries = []
        
        for i, chunk in enumerate(chunks):
            result = self._analyze_code_chunk(
                vulnerability_report,
                chunk['content'],
                blob_url,
                chunk_index=i,
                total_chunks=len(chunks),
                chunk_start=chunk['start_pos']
            )

            print(f"Result: {result}")
            
            if 'functions' in result:
                all_functions.extend(result['functions'])
            
            if 'file_summary' in result:
                chunk_summaries.append(f"Chunk {i+1}: {result['file_summary']}")
        
        # Deduplicate functions by name (keep highest score)
        unique_functions = {}
        for func in all_functions:
            func_name = func.get('name', 'unknown')
            if func_name not in unique_functions or func.get('score', 0) > unique_functions[func_name].get('score', 0):
                unique_functions[func_name] = func
        
        # Sort by score
        sorted_functions = sorted(
            unique_functions.values(),
            key=lambda x: x.get('score', 0),
            reverse=True
        )
        
        return {
            "functions": sorted_functions,
            "file_summary": f"Large file analyzed in {len(chunks)} chunks. " + "; ".join(chunk_summaries[:3]),
            "total_chunks": len(chunks),
            "total_functions_found": len(sorted_functions)
        }

    def _analyze_code_chunk(
        self,
        vulnerability_report: Dict[str, Any],
        file_content: str,
        blob_url: str,
        chunk_index: int = 0,
        total_chunks: int = 1,
        chunk_start: int = 0
    ) -> Dict[str, Any]:
        """Analyze a single chunk of code."""
        
        chunk_info = f" (Chunk {chunk_index + 1} of {total_chunks})" if total_chunks > 1 else ""
        
        prompt = f"""
    You are a security expert analyzing source code to identify which specific functions are most relevant to a vulnerability report.

    VULNERABILITY REPORT:
    Title: {vulnerability_report.get('title', 'N/A')}
    Description: {vulnerability_report.get('description', 'N/A')}
    Recommendation: {vulnerability_report.get('recommendation', 'N/A')}
    Broken Code Snippets: {vulnerability_report.get('broken_code_snippets', [])}
    Files: {vulnerability_report.get('files', 'N/A')}

    FILE TO ANALYZE{chunk_info}:
    {file_content}

    TASK:
    1. Extract all function/method definitions from this code
    2. For each function, score it from 0-100 based on how likely it contains or relates to the vulnerability:
    - 0: Completely irrelevant
    - 1-30: Low relevance (mentions related concepts but unlikely to be vulnerable)
    - 31-60: Medium relevance (contains related functionality)
    - 61-89: High relevance (strong indicators of vulnerability)
    - 90-100: Very high relevance (almost certainly the vulnerable function)

    3. Rank functions by their relevance scores (highest first)

    Consider:
    - Function names mentioned in the vulnerability
    - Code patterns and logic described in the vulnerability
    - Security-sensitive operations (authentication, authorization, input validation, etc.)
    - Variable names and data flow
    - API endpoints or route handlers mentioned

    Respond ONLY with valid JSON, no markdown formatting or code blocks. Use this exact format:
    {{
        "functions": [
            {{
                "name": "<function_name>",
                "line_number": <approximate line number or null>,
                "score": <number 0-100>,
                "reasoning": "<brief explanation>",
                "confidence": "<high|medium|low>",
                "key_indicators": ["<specific matches or concerns>"]
            }}
        ],
        "file_summary": "<brief summary of this code section's relevance>"
    }}

    Order the functions array by score (highest first). Include all functions found, prioritizing those with higher relevance scores.
    """

        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=1500,
                response_format={"type": "json_object"}
            )
            
            result_text = response.choices[0].message.content.strip()
            
            # Multiple parsing strategies
            result = self._parse_gpt_response(result_text)
            
            if result is None:
                return {
                    "functions": [],
                    "file_summary": "Failed to parse response after multiple attempts",
                    "error": "All parsing strategies failed",
                    "raw_response": result_text[:500]
                }
            
            # Adjust line numbers based on chunk position
            if "functions" in result and chunk_start > 0:
                for func in result["functions"]:
                    if func.get("line_number") is not None:
                        lines_before = file_content[:chunk_start].count('\n')
                        func["line_number"] = func["line_number"] + lines_before
            
            # Ensure functions are sorted by score
            if "functions" in result:
                result["functions"] = sorted(
                    result["functions"],
                    key=lambda x: x.get("score", 0),
                    reverse=True
                )
            
            # Ensure required fields exist
            if "functions" not in result:
                result["functions"] = []
            if "file_summary" not in result:
                result["file_summary"] = "No summary provided"
            
            return result
        
        except Exception as e:
            print(f"Error analyzing chunk in {blob_url}: {e}")
            return {
                "functions": [],
                "file_summary": f"API error: {e}",
                "error": str(e)
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