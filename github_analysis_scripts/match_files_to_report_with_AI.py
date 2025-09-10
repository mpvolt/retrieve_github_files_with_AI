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


MIN_THRESHOLD = 75

class VulnerabilityFileMatcher:
    """Main class for matching vulnerability reports to source files."""
    
    def __init__(self, openai_api_key: str, github_token: Optional[str] = None):
        """Initialize the matcher with API credentials."""
        self.openai_client = OpenAI(api_key=openai_api_key)
        self.github_token = github_token
        self.session = requests.Session()
        if github_token:
            self.session.headers.update({'Authorization': f'token {github_token}'})
    
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
    
    def score_file_match(self, vulnerability_report: Dict[str, Any], file_content: str, file_path: str) -> Dict[str, Any]:
        """Use GPT-4 to score how well a file matches the vulnerability report."""
        
        # Truncate file content if too long (GPT-4 token limits)
        max_content_length = 8000
        if len(file_content) > max_content_length:
            file_content = file_content[:max_content_length] + "\n... [TRUNCATED]"
        
        prompt = f"""
You are a security expert analyzing whether a source code file matches a vulnerability report.

VULNERABILITY REPORT:
Title: {vulnerability_report.get('title', 'N/A')}
Description: {vulnerability_report.get('description', 'N/A')}
Recommendation: {vulnerability_report.get('recommendation', 'N/A')}
Broken Code Snippets: {vulnerability_report.get('broken_code_snippets', [])}

FILE TO ANALYZE:
File Path: {file_path}
File Content:
{file_content}

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
                model="gpt-4.1-mini",
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
                    "reasoning": "GPT-4 response parsing failed",
                    "confidence": "low",
                    "key_matches": []
                }
        
        except Exception as e:
            print(f"Error scoring file {file_path}: {e}")
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
            
            # Score the match
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
        
        # Sort by score (highest first)
        matches.sort(key=lambda x: x.total_score, reverse=True)
        high_confidence_matches = [match for match in matches if match.total_score >= MIN_THRESHOLD]
        return high_confidence_matches


def extract_function_names(file_path: str) -> List[str]:
    """Extract function names from a file path (simplified version)."""
    # This is a placeholder - you might want to implement actual parsing
    # or make another API call to extract function names
    return []


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
        
        # Extract and display function names for top match
        if j == 0:  # Only for the top match to avoid too many API calls
            try:
                functions = extract_function_names(match.file_path)
                if functions:
                    print(f"   Functions: {', '.join(functions[:5])}")  # Show first 5
            except Exception as e:
                print(f"   Could not extract functions: {e}")
        
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
    
    # Process files
    matches = matcher.process_files(vulnerability_report, blob_urls)
    
    # Filter high confidence matches (score >= 85)
    high_confidence_matches = [match for match in matches if match.total_score >= MIN_THRESHOLD]
    
    # Print results
    print_match_results(vulnerability_report['title'], matches, high_confidence_matches)
    
    # Create summary
    top_match = matches[0] if matches else None
    summary = create_summary_result("VULN-001", vulnerability_report['title'], vulnerability_report, top_match)
    
    print(f"\nSummary:")
    print(json.dumps(summary, indent=2))
    
    print(f"Top match: {top_match}")
    return top_match


if __name__ == "__main__":
    main()