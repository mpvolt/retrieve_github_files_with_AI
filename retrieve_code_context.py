#!/usr/bin/env python3
"""
Script to analyze JSON objects containing GitHub code references and extract
relevant code context using GPT-4.1-mini.
"""

import os
import json
import re
import requests
from pathlib import Path
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse
import openai
from openai import OpenAI
import base64
import argparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class GitHubCodeAnalyzer:
    def __init__(self, github_token: str, openai_api_key: str):
        """Initialize the analyzer with API credentials."""
        self.github_token = github_token
        self.github_headers = {
            'Authorization': f'token {github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        self.openai_client = OpenAI(api_key=openai_api_key)
    
    def parse_github_url(self, url: str) -> Dict[str, str]:
        """Parse GitHub URL to extract owner, repo, and file path."""
        # Handle both blob and raw URLs
        pattern = r'github\.com/([^/]+)/([^/]+)/(?:blob|raw)/([^/]+)/(.+)'
        match = re.search(pattern, url)
        
        if not match:
            raise ValueError(f"Invalid GitHub URL format: {url}")
        
        return {
            'owner': match.group(1),
            'repo': match.group(2),
            'ref': match.group(3),
            'path': match.group(4)
        }
    
    def parse_commit_url(self, url: str) -> Dict[str, str]:
        """Parse GitHub commit/pull URL to extract owner, repo, and commit SHA."""
        # Handle commit URLs
        commit_pattern = r'github\.com/([^/]+)/([^/]+)/commit/([a-f0-9]+)'
        commit_match = re.search(commit_pattern, url)
        
        if commit_match:
            return {
                'owner': commit_match.group(1),
                'repo': commit_match.group(2),
                'sha': commit_match.group(3)
            }
        
        # Handle pull request URLs
        pr_pattern = r'github\.com/([^/]+)/([^/]+)/pull/(\d+)'
        pr_match = re.search(pr_pattern, url)
        
        if pr_match:
            owner, repo, pr_number = pr_match.groups()
            # Get the PR data to find the merge commit SHA
            pr_url = f'https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}'
            response = requests.get(pr_url, headers=self.github_headers)
            
            if response.status_code == 200:
                pr_data = response.json()
                return {
                    'owner': owner,
                    'repo': repo,
                    'sha': pr_data['merge_commit_sha'] or pr_data['head']['sha']
                }
            else:
                raise ValueError(f"Failed to fetch PR data: {response.status_code}")
        
        raise ValueError(f"Invalid commit/PR URL format: {url}")
    
    def get_file_content(self, owner: str, repo: str, path: str, ref: str = 'main') -> str:
        """Get file content from GitHub repository."""
        api_url = f'https://api.github.com/repos/{owner}/{repo}/contents/{path}'
        params = {'ref': ref}
        
        response = requests.get(api_url, headers=self.github_headers, params=params)
        
        if response.status_code == 200:
            content_data = response.json()
            if content_data.get('encoding') == 'base64':
                content = base64.b64decode(content_data['content']).decode('utf-8')
                return content
            else:
                return content_data['content']
        else:
            raise Exception(f"Failed to fetch file content: {response.status_code} - {response.text}")
    
    def analyze_code_with_gpt(self, code_content: str, title: str = "", 
                             description: str = "", recommendation: str = "", 
                             broken_code_snippets: List[str] = None) -> str:
        """Send code to GPT-4.1-mini for analysis and context extraction."""
        
        broken_snippets_text = ""
        if broken_code_snippets:
            broken_snippets_text = "\n".join([f"- {snippet}" for snippet in broken_code_snippets])
        
        prompt = f"""
You are analyzing code to identify the specific section and context related to a described issue.

ISSUE DETAILS:
Title: {title}
Description: {description}
Recommendation: {recommendation}

BROKEN CODE SNIPPETS (if provided):
{broken_snippets_text}

FULL FILE CONTENT:
```
{code_content}
```

TASK: Identify the specific section of code that relates to the described issue. Return the relevant code section along with ALL necessary context (variables, functions, classes, imports) that would allow an AI to fully understand the code without seeing the rest of the file.

Return ONLY the relevant code with context, no additional explanation or markdown formatting.
"""

        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4o-mini",  # Using the correct model name
                messages=[
                    {"role": "system", "content": "You are a code analysis expert. Extract relevant code sections with full context."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=4000,
                temperature=0.1
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            raise
    
    def process_json_object(self, json_obj: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single JSON object according to the specified workflow."""
        updated_obj = json_obj.copy()
        
        # Check if object contains afflicted_github_code_blob
        if 'afflicted_github_code_blob' not in json_obj:
            return updated_obj
        
        logger.info(f"Processing object with afflicted_github_code_blob: {json_obj.get('title', 'Unknown')}")
        
        try:
            # Parse GitHub URL and get code content
            github_info = self.parse_github_url(json_obj['afflicted_github_code_blob'][0])
            code_content = self.get_file_content(
                github_info['owner'], 
                github_info['repo'], 
                github_info['path'], 
                github_info['ref']
            )
            
            # Extract relevant fields for GPT analysis
            title = json_obj.get('title', '')
            description = json_obj.get('description', '')
            recommendation = json_obj.get('recommendation', '')
            broken_code_snippets = json_obj.get('broken_code_snippets', [])
            
            # Analyze code with GPT
            full_context = self.analyze_code_with_gpt(
                code_content, title, description, recommendation, broken_code_snippets
            )
            
            updated_obj['full_broken_code_context'] = full_context
            logger.info("Added full_broken_code_context")
            
        except Exception as e:
            logger.error(f"Error processing afflicted_github_code_blob: {e}")
            updated_obj['processing_error'] = str(e)
        
        # Check if object also contains fix_commit_url
        if 'fix_commit_url' in json_obj:
            logger.info(f"Processing fix_commit_url: {json_obj['fix_commit_url']}")
            
            try:
                # Handle both string and array formats for fix_commit_url
                fix_commit = json_obj['fix_commit_url']
                fix_contexts = []
                
                if isinstance(fix_commit, list):
                    if len(fix_commit) == 0:
                        logger.warning("fix_commit_url is empty array, skipping fix processing")
                    else:
                        logger.info(f"Processing {len(fix_commit)} fix commit URLs")
                        commit_urls = fix_commit
                else:
                    commit_urls = [fix_commit]
                
                # Process each commit URL
                for i, commit_url in enumerate(commit_urls):
                    try:
                        logger.info(f"Processing fix commit {i+1}/{len(commit_urls)}: {commit_url}")
                        
                        # Parse commit URL and get updated code
                        commit_info = self.parse_commit_url(commit_url)
                        
                        # Get the updated file content using the commit SHA
                        # Use the same file path from the original github_info
                        updated_code_content = self.get_file_content(
                            commit_info['owner'],
                            commit_info['repo'],
                            github_info['path'],  # This should be available from the afflicted_github_code_blob processing
                            commit_info['sha']
                        )
                        
                        # Analyze updated code with GPT
                        updated_context = self.analyze_code_with_gpt(
                            updated_code_content, title, description, recommendation, broken_code_snippets
                        )
                        
                        fix_contexts.append({
                            'commit_url': commit_url,
                            'commit_sha': commit_info['sha'],
                            'fixed_code_context': updated_context
                        })
                        
                    except Exception as e:
                        logger.error(f"Error processing fix commit {commit_url}: {e}")
                        fix_contexts.append({
                            'commit_url': commit_url,
                            'error': str(e)
                        })
                
                # Store results based on whether we had single or multiple commits
                if len(commit_urls) == 1 and len(fix_contexts) == 1 and 'error' not in fix_contexts[0]:
                    # Single commit - store as before for backward compatibility
                    updated_obj['full_fixed_code_context'] = fix_contexts[0]['fixed_code_context']
                else:
                    # Multiple commits or errors - store as array with metadata
                    updated_obj['full_fixed_code_context'] = fix_contexts
                
                logger.info("Added full_fixed_code_context")
                
            except Exception as e:
                logger.error(f"Error processing fix_commit_url: {e}")
                updated_obj['fix_processing_error'] = str(e)
        
        return updated_obj
    
    def process_directory(self, directory: str) -> None:
        """Process all JSON files in the specified directory and subdirectories."""
        directory_path = Path(directory)
        
        if not directory_path.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")
        
        # Find all JSON files recursively
        json_files = list(directory_path.rglob('*.json'))
        logger.info(f"Found {len(json_files)} JSON files")
        
        for json_file in json_files:
            logger.info(f"Processing file: {json_file}")
            
            try:
                # Read JSON file
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Handle both single objects and arrays
                if isinstance(data, list):
                    processed_data = []
                    for obj in data:
                        if isinstance(obj, dict):
                            processed_obj = self.process_json_object(obj)
                            processed_data.append(processed_obj)
                        else:
                            processed_data.append(obj)
                elif isinstance(data, dict):
                    processed_data = self.process_json_object(data)
                else:
                    logger.warning(f"Skipping non-object/array JSON in {json_file}")
                    continue
                
                # Write back to file
                with open(json_file, 'w', encoding='utf-8') as f:
                    json.dump(processed_data, f, indent=2, ensure_ascii=False)
                
                logger.info(f"Successfully processed {json_file}")
                
            except Exception as e:
                logger.error(f"Error processing {json_file}: {e}")


def main():
    parser = argparse.ArgumentParser(description='Analyze GitHub code references in JSON files')
    parser.add_argument('directory', help='Directory containing JSON files to process')
    args = parser.parse_args()

    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    GITHUB_API_KEY = os.getenv("GITHUB_API_KEY")
    
    # Initialize analyzer
    analyzer = GitHubCodeAnalyzer(GITHUB_API_KEY, OPENAI_API_KEY)
    
    # Process directory
    try:
        analyzer.process_directory(args.directory)
        logger.info("Processing completed successfully")
    except Exception as e:
        logger.error(f"Processing failed: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())