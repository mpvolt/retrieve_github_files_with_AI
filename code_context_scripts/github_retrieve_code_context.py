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
            # Process afflicted code blobs
            file_contexts = self._process_afflicted_blobs(json_obj)
            
            # Process fix commits if they exist
            if 'fix_commit_url' in json_obj:
                self._process_fix_commits(json_obj, file_contexts)
            
            # Add file contexts to the main object
            self._add_file_contexts_to_object(updated_obj, file_contexts)
            
        except Exception as e:
            logger.error(f"Error processing JSON object: {e}")
            updated_obj['processing_error'] = str(e)
        
        return updated_obj

    def _process_afflicted_blobs(self, json_obj: Dict[str, Any]) -> Dict[str, Any]:
        """Process all afflicted GitHub code blobs and return file contexts."""
        afflicted_blobs = json_obj['afflicted_github_code_blob']
        
        # Ensure afflicted_blobs is a list
        if not isinstance(afflicted_blobs, list):
            afflicted_blobs = [afflicted_blobs]
        
        file_contexts = {}
        
        # Extract relevant fields for GPT analysis
        title = json_obj.get('title', '')
        description = json_obj.get('description', '')
        recommendation = json_obj.get('recommendation', '')
        broken_code_snippets = json_obj.get('broken_code_snippets', [])
        
        for i, blob_url in enumerate(afflicted_blobs):
            try:
                logger.info(f"Processing afflicted GitHub blob {i+1}/{len(afflicted_blobs)}: {blob_url}")
                
                file_context = self._process_single_afflicted_blob(
                    blob_url, title, description, recommendation, broken_code_snippets
                )
                
                # Extract filename from the blob URL
                github_info = self.parse_github_url(blob_url)
                filename = github_info['path'].split('/')[-1]
                
                file_contexts[filename] = file_context
                logger.info(f"Added context for file: {filename}")
                
            except Exception as e:
                logger.error(f"Error processing afflicted blob {blob_url}: {e}")
                filename = self._extract_filename_from_url(blob_url, i)
                file_contexts[filename] = {'processing_error': str(e)}
        
        logger.info(f"Processed {len(file_contexts)} afflicted blobs")
        return file_contexts

    def _process_single_afflicted_blob(self, blob_url: str, title: str, description: str, 
                                    recommendation: str, broken_code_snippets: list) -> Dict[str, Any]:
        """Process a single afflicted GitHub blob and return its context."""
        # Parse GitHub URL and get code content
        github_info = self.parse_github_url(blob_url)
        code_content = self.get_file_content(
            github_info['owner'], 
            github_info['repo'], 
            github_info['path'], 
            github_info['ref']
        )
        
        # Analyze code with GPT
        vulnerable_context = self.analyze_code_with_gpt(
            code_content, title, description, recommendation, broken_code_snippets
        )
        
        # Return nested structure
        return {
            'broken': {
                'full_vulnerable_source_code': code_content,
                'vulnerable_code_context': vulnerable_context
            }
        }

    def _process_fix_commits(self, json_obj: Dict[str, Any], file_contexts: Dict[str, Any]) -> None:
        """Process fix commit URLs and update file contexts with patched code."""
        fix_commit = json_obj['fix_commit_url']
        logger.info(f"Processing fix_commit_url: {fix_commit}")
        
        # Handle both string and array formats for fix_commit_url
        commit_urls = self._normalize_commit_urls(fix_commit)
        if not commit_urls:
            return
        
        afflicted_blobs = json_obj['afflicted_github_code_blob']
        if not isinstance(afflicted_blobs, list):
            afflicted_blobs = [afflicted_blobs]
        
        # Extract fields for GPT analysis
        title = json_obj.get('title', '')
        description = json_obj.get('description', '')
        recommendation = json_obj.get('recommendation', '')
        broken_code_snippets = json_obj.get('broken_code_snippets', [])
        
        # Process each commit URL
        for commit_i, commit_url in enumerate(commit_urls):
            try:
                logger.info(f"Processing fix commit {commit_i+1}/{len(commit_urls)}: {commit_url}")
                self._process_single_fix_commit(
                    commit_url, file_contexts, afflicted_blobs, 
                    title, description, recommendation, broken_code_snippets
                )
            except Exception as e:
                logger.error(f"Error processing fix commit {commit_url}: {e}")
                self._add_commit_error_to_all_files(file_contexts, commit_url, str(e))
        
        # Clean up single-item lists for better structure
        self._cleanup_single_commit_lists(file_contexts)
        logger.info("Added patched data to file contexts")

    def _normalize_commit_urls(self, fix_commit) -> list:
        """Normalize fix_commit_url to a list of URLs."""
        if isinstance(fix_commit, list):
            if len(fix_commit) == 0:
                logger.warning("fix_commit_url is empty array, skipping fix processing")
                return []
            logger.info(f"Processing {len(fix_commit)} fix commit URLs")
            return fix_commit
        else:
            return [fix_commit]

    def _process_single_fix_commit(self, commit_url: str, file_contexts: Dict[str, Any], 
                                afflicted_blobs: list, title: str, description: str, 
                                recommendation: str, broken_code_snippets: list) -> None:
        """Process a single fix commit and update file contexts."""
        commit_info = self.parse_commit_url(commit_url)
        
        # Process each file that was in the afflicted blobs
        for filename, file_context in file_contexts.items():
            if 'processing_error' in file_context:
                continue  # Skip files that had processing errors
            
            try:
                # Find the original GitHub info for this file
                original_github_info = self._find_original_github_info(filename, afflicted_blobs)
                if original_github_info is None:
                    logger.warning(f"Could not find original GitHub info for file: {filename}")
                    continue
                
                # Get and analyze the fixed code
                patched_data = self._get_and_analyze_patched_code(
                    commit_info, original_github_info, title, description, recommendation, broken_code_snippets
                )
                
                # Add to file context
                self._add_patched_data_to_file_context(file_context, commit_url, commit_info['sha'], patched_data)
                
            except Exception as e:
                logger.error(f"Error processing fix commit {commit_url} for file {filename}: {e}")
                self._add_patched_error_to_file_context(file_context, commit_url, str(e))

    def _find_original_github_info(self, filename: str, afflicted_blobs: list) -> Dict[str, Any]:
        """Find the original GitHub info for a given filename."""
        for blob_url in afflicted_blobs:
            try:
                github_info = self.parse_github_url(blob_url)
                if github_info['path'].split('/')[-1] == filename:
                    return github_info
            except:
                continue
        return None

    def _get_and_analyze_patched_code(self, commit_info: Dict[str, Any], original_github_info: Dict[str, Any],
                                    title: str, description: str, recommendation: str, 
                                    broken_code_snippets: list) -> Dict[str, Any]:
        """Get the patched code content and analyze it with GPT."""
        # Get the updated file content using the commit SHA
        updated_code_content = self.get_file_content(
            commit_info['owner'],
            commit_info['repo'],
            original_github_info['path'],
            commit_info['sha']
        )
        
        # Analyze updated code with GPT
        patched_context = self.analyze_code_with_gpt(
            updated_code_content, title, description, recommendation, broken_code_snippets
        )
        
        return {
            'full_patched_source_code': updated_code_content,
            'patched_code_context': patched_context
        }

    def _add_patched_data_to_file_context(self, file_context: Dict[str, Any], commit_url: str, 
                                        commit_sha: str, patched_data: Dict[str, Any]) -> None:
        """Add patched data to a file context."""
        if 'patched' not in file_context:
            file_context['patched'] = []
        
        file_context['patched'].append({
            'commit_url': commit_url,
            'commit_sha': commit_sha,
            **patched_data
        })

    def _add_patched_error_to_file_context(self, file_context: Dict[str, Any], commit_url: str, error: str) -> None:
        """Add an error entry to a file context's patched data."""
        if 'patched' not in file_context:
            file_context['patched'] = []
        
        file_context['patched'].append({
            'commit_url': commit_url,
            'error': error
        })

    def _add_commit_error_to_all_files(self, file_contexts: Dict[str, Any], commit_url: str, error: str) -> None:
        """Add a commit processing error to all file contexts."""
        for file_context in file_contexts.values():
            if 'processing_error' not in file_context:
                self._add_patched_error_to_file_context(file_context, commit_url, error)

    def _cleanup_single_commit_lists(self, file_contexts: Dict[str, Any]) -> None:
        """Clean up single-item lists for better structure when there's only one commit."""
        for file_context in file_contexts.values():
            if 'patched' in file_context and len(file_context['patched']) == 1:
                single_fix = file_context['patched'][0]
                if 'error' not in single_fix:
                    file_context['patched'] = {
                        'patched_code_context': single_fix['patched_code_context'],
                        'full_patched_source_code': single_fix['full_patched_source_code']
                    }

    def _extract_filename_from_url(self, blob_url: str, index: int) -> str:
        """Extract filename from blob URL, with fallback for errors."""
        return blob_url.split('/')[-1] if '/' in blob_url else f"error_file_{index}"

    def _add_file_contexts_to_object(self, updated_obj: Dict[str, Any], file_contexts: Dict[str, Any]) -> None:
        """
        Transform file_contexts into a list of code diffs with 'filename', 'broken', and 'patched' keys.
        """
        code_diffs = []
        for filename, context in file_contexts.items():
            # context already contains keys like 'broken' (and possibly 'patched')
            entry = {
                "filename": filename,
                "broken": context.get("broken", {}),
                "patched": context.get("patched", {})
            }
            code_diffs.append(entry)

        updated_obj["code_diff"] = code_diffs
        logger.info(f"Added contexts for {len(file_contexts)} files")

    def process_single_json_file(self, file_path: str) -> None:
        """Process a single JSON file."""
        json_file = Path(file_path)
        
        if not json_file.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if not json_file.suffix.lower() == '.json':
            raise ValueError(f"File must be a JSON file: {file_path}")
        
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
                return
            
            # Write back to file
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(processed_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Successfully processed {json_file}")
            
        except Exception as e:
            logger.error(f"Error processing {json_file}: {e}")
            raise
    
    def process_directory(self, directory: str) -> None:
        """Process all JSON files in the specified directory and subdirectories."""
        directory_path = Path(directory)
        
        if not directory_path.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")
        
        # Find all JSON files recursively
        json_files = list(directory_path.rglob('*.json'))
        logger.info(f"Found {len(json_files)} JSON files")
        
        for json_file in json_files:
            self.process_single_json_file(json_file)


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