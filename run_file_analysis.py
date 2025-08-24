from analyze_relevant_files import analyze_relevant_files
import os
import json
import time
import requests
from pathlib import Path
from typing import Optional, Dict, Any
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class GitHubRateLimitManager:
    """Manages GitHub API rate limiting"""
    
    def __init__(self, api_key: str, min_requests_threshold: int = 100):
        """
        Initialize rate limit manager
        
        Args:
            api_key: GitHub API key
            min_requests_threshold: Minimum requests left before pausing
        """
        self.api_key = api_key
        self.min_requests_threshold = min_requests_threshold
        self.headers = {
            'Authorization': f'token {api_key}',
            'Accept': 'application/vnd.github.v3+json'
        }
    
    def get_rate_limit_info(self) -> Optional[Dict[str, Any]]:
        """
        Get current rate limit information from GitHub API
        
        Returns:
            Dictionary with rate limit info or None if request fails
        """
        try:
            response = requests.get(
                'https://api.github.com/rate_limit',
                headers=self.headers,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to get rate limit info: {e}")
            return None
    
    def check_and_wait_if_needed(self, operation_context: str = "") -> bool:
        """
        Check rate limit and pause if necessary
        
        Args:
            operation_context: Context string for logging
            
        Returns:
            True if we can proceed, False if there was an error
        """
        rate_info = self.get_rate_limit_info()
        if not rate_info:
            logger.warning("Could not retrieve rate limit info, proceeding cautiously...")
            time.sleep(5)  # Conservative pause if we can't check
            return True
        
        core_limit = rate_info['rate']
        remaining = core_limit['remaining']
        reset_time = core_limit['reset']
        
        logger.info(f"GitHub API requests remaining: {remaining}/{core_limit['limit']}")
        
        if remaining < self.min_requests_threshold:
            wait_time = reset_time - time.time() + 10  # Add 10 seconds buffer
            if wait_time > 0:
                logger.warning(
                    f"Rate limit low ({remaining} remaining). "
                    f"Pausing for {wait_time:.0f} seconds until reset. "
                    f"Context: {operation_context}"
                )
                time.sleep(wait_time)
            else:
                # Rate limit should have reset, but let's be safe
                time.sleep(10)
        
        return True


def find_json_files(root_dir: str = ".") -> list[Path]:
    """
    Find all JSON files in the current directory and all subdirectories
    
    Args:
        root_dir: Root directory to search from
        
    Returns:
        List of Path objects for JSON files found, sorted for consistent processing
    """
    root_path = Path(root_dir).resolve()  # Get absolute path for cross-platform compatibility
    json_files = []
    
    try:
        # Search current directory and all subdirectories recursively
        # Using rglob to find all .json files regardless of case (important for cross-platform)
        json_files = list(root_path.rglob("*.json"))
        
        # Also check for .JSON files (uppercase extension) for Windows compatibility
        json_files.extend(root_path.rglob("*.JSON"))
        
        # Remove duplicates (in case a file matches both patterns)
        json_files = list(set(json_files))
        
        # Sort files for consistent processing order across platforms
        json_files.sort()
        
        # Filter out any files that might not actually exist (edge case)
        json_files = [f for f in json_files if f.exists() and f.is_file()]
        
        logger.info(f"Found {len(json_files)} JSON files in {root_path} and its subdirectories")
        
        # Debug: Show first few files found
        if json_files:
            logger.debug(f"First few JSON files found:")
            for i, file in enumerate(json_files[:5]):  # Show first 5
                logger.debug(f"  {i+1}. {file}")
            if len(json_files) > 5:
                logger.debug(f"  ... and {len(json_files) - 5} more files")
        
    except PermissionError as e:
        logger.error(f"Permission denied accessing directory {root_path}: {e}")
        return []
    except Exception as e:
        logger.error(f"Error searching for JSON files in {root_path}: {e}")
        return []
    
    return json_files
 

def process_json_files_with_rate_limiting():
    """
    Main function that processes all JSON files in subdirectories while managing GitHub API rate limits
    """
    # Save the original working directory
    original_cwd = os.getcwd()
    
    try:
        # Get GitHub API key from environment
        api_key = os.getenv('GITHUB_API_KEY')
        if not api_key:
            raise ValueError("GITHUB_API_KEY environment variable is not set")
        
        # Initialize rate limit manager
        rate_manager = GitHubRateLimitManager(api_key, min_requests_threshold=50)
        
        # Find all JSON files in subdirectories
        json_files = find_json_files(".")
        
        if not json_files:
            logger.info("No JSON files found in subdirectories")
            return
        
        processed_count = 0
        failed_count = 0
        
        for json_file in json_files:
            try:
                # Convert Path object to absolute string path for cross-platform compatibility
                json_file_str = str(json_file.resolve())
                
                logger.info(f"Processing file {processed_count + 1}/{len(json_files)}: {json_file}")
                logger.debug(f"Resolved path: {json_file_str}")
                
                # Safely verify and restore working directory
                try:
                    current_dir = os.getcwd()
                    if current_dir != original_cwd:
                        logger.warning(f"Working directory changed, restoring to {original_cwd}")
                        os.chdir(original_cwd)
                except FileNotFoundError:
                    logger.warning("Current working directory no longer exists, restoring to original")
                    if os.path.exists(original_cwd):
                        os.chdir(original_cwd)
                    else:
                        logger.error(f"Original directory {original_cwd} also missing, using home directory")
                        os.chdir(os.path.expanduser('~'))
                
                # Check rate limit before processing each file
                if not rate_manager.check_and_wait_if_needed(f"before processing {json_file}"):
                    logger.error(f"Failed to check rate limit for {json_file}, skipping...")
                    failed_count += 1
                    continue
                
                # Validate JSON file before processing using the resolved path
                try:
                    with open(json_file_str, 'r', encoding='utf-8') as f:
                        json.load(f)  # Validate JSON syntax
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    logger.warning(f"Skipping invalid JSON file {json_file}: {e}")
                    failed_count += 1
                    continue
                
                # Process the file
                max_retries = 3
                retry_count = 0
                
                while retry_count < max_retries:
                    try:
                        # Check rate limit again right before the potentially expensive operation
                        if not rate_manager.check_and_wait_if_needed(f"during processing {json_file}"):
                            raise Exception("Rate limit check failed")
                        
                        # Safely ensure we're still in the correct directory
                        try:
                            current_dir = os.getcwd()
                            if current_dir != original_cwd:
                                logger.warning(f"Working directory changed during processing, restoring to {original_cwd}")
                                os.chdir(original_cwd)
                        except FileNotFoundError:
                            logger.warning("Working directory missing during processing, restoring to original")
                            if os.path.exists(original_cwd):
                                os.chdir(original_cwd)
                        
                        # Call analyze_relevant_files with the resolved string path
                        success = analyze_relevant_files(json_file_str)
                        
                        if success is not None:
                            processed_count += 1
                            logger.info(f"Successfully processed {json_file}")
                            break
                        else:
                            retry_count += 1
                            if retry_count < max_retries:
                                logger.warning(f"analyze_relevant_files() returned None for {json_file}, retrying...")
                                time.sleep(5)
                            
                    except Exception as e:
                        retry_count += 1
                        if retry_count < max_retries:
                            logger.warning(f"Error processing {json_file} (attempt {retry_count}): {e}")
                            time.sleep(10)
                        else:
                            logger.error(f"Failed to process {json_file} after {max_retries} attempts: {e}")
                            failed_count += 1
                            break
                else:
                    if retry_count >= max_retries:
                        failed_count += 1
                        continue
                
                time.sleep(0.5)
                
            except KeyboardInterrupt:
                logger.info("Process interrupted by user")
                break
            except Exception as e:
                logger.error(f"Unexpected error processing {json_file}: {e}")
                failed_count += 1
        
        logger.info(f"Processing complete: {processed_count} successful, {failed_count} failed")
        
    finally:
        # Safely restore the original working directory
        try:
            current_dir = os.getcwd()
            if current_dir != original_cwd:
                logger.info(f"Restoring working directory to {original_cwd}")
                os.chdir(original_cwd)
        except FileNotFoundError:
            logger.warning("Cannot restore working directory - it no longer exists")
            if os.path.exists(original_cwd):
                os.chdir(original_cwd)
                logger.info(f"Successfully restored to {original_cwd}")

def main():
    """Entry point for the script"""
    start_time = time.time()
    
    try:
        process_json_files_with_rate_limiting()
    except Exception as e:
        logger.error(f"Script failed: {e}")
        raise
    finally:
        end_time = time.time()
        execution_time = end_time - start_time
        logger.info(f"Script execution time: {execution_time:.2f} seconds")
        print(f"Script completed in {execution_time:.2f} seconds")
        
if __name__ == "__main__":
    main()