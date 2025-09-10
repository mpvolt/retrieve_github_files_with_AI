import traceback
from github_analysis_scripts.analyze_relevant_files import analyze_relevant_files
import os
import json
import time
import requests
from pathlib import Path
from typing import Optional, Dict, Any
import logging
import concurrent.futures

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


from pathlib import Path

def find_json_files(root_dir: str = ".", start_dir: str = None) -> list[Path]:
    """
    Find all JSON files in the current directory and all subdirectories.
    Optionally start from a directory (alphabetical order).
    
    Args:
        root_dir: Root directory to search from
        start_dir: Optional starting directory name (alphabetical filter). 
                   Example: "e" → skips a-d
    
    Returns:
        List of Path objects for JSON files found, sorted for consistent processing
    """
    root_path = Path(root_dir).resolve()  # Get absolute path for cross-platform compatibility
    json_files = []
    
    try:
        # Search recursively for JSON files
        json_files = list(root_path.rglob("*.json"))
        json_files.extend(root_path.rglob("*.JSON"))
        
        # Remove duplicates
        json_files = list(set(json_files))
        
        # Sort consistently
        json_files.sort()
        
        # Filter out invalid paths
        json_files = [f for f in json_files if f.exists() and f.is_file()]
        
        # ✅ Apply start_dir filter if provided
        if start_dir:
            start_dir = start_dir.lower()
            json_files = [
                f for f in json_files 
                if f.parts[len(root_path.parts)].lower() >= start_dir
            ]
        
        logger.info(f"Found {len(json_files)} JSON files in {root_path} and its subdirectories")
        
        # Debug: Show first few files
        if json_files:
            logger.debug(f"First few JSON files found:")
            for i, file in enumerate(json_files[:5]):
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

 
def process_single_json_file(json_file_str, original_cwd, rate_manager, max_retries=3):
    """
    Worker function to process a single JSON file.
    Returns (success: bool, file: str) for aggregation.
    """

    try:
        # Check rate limit before starting
        if not rate_manager.check_and_wait_if_needed(f"before processing {json_file_str}"):
            return False, json_file_str

        # Validate JSON
        try:
            with open(json_file_str, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.warning(f"Skipping invalid JSON file {json_file_str}: {e}")
            return False, json_file_str

        # Skip if no relevant fields
        if not any(
            key in obj
            for obj in (data if isinstance(data, list) else [data])
            for key in ("source_code_url", "fix_commit_url", "afflicted_github_code_blob")
        ):
            logger.info(f"Skipping {json_file_str}: no relevant fields")
            return True, json_file_str  # Not an error, just skipped

        retry_count = 0
        while retry_count < max_retries:
            try:
                # Check rate limit again before expensive operation
                if not rate_manager.check_and_wait_if_needed(f"during processing {json_file_str}"):
                    raise Exception("Rate limit check failed")

                # Ensure correct working directory
                try:
                    if os.getcwd() != original_cwd:
                        os.chdir(original_cwd)
                except FileNotFoundError:
                    if os.path.exists(original_cwd):
                        os.chdir(original_cwd)

                success = analyze_relevant_files(json_file_str)
                if success is not None:
                    logger.info(f"Successfully processed {json_file_str}")
                    return True, json_file_str
                else:
                    retry_count += 1
                    logger.warning(f"analyze_relevant_files() returned None for {json_file_str}, retrying...")
                    time.sleep(5)

            except Exception as e:
                retry_count += 1
                logger.warning(f"Error processing {json_file_str} (attempt {retry_count}): {e}")
                logger.debug(traceback.format_exc())
                time.sleep(10)

        # Retries exhausted
        logger.error(f"Failed to process {json_file_str} after {max_retries} attempts")
        return False, json_file_str

    except Exception as e:
        logger.error(f"Unexpected error in worker for {json_file_str}: {e}")
        return False, json_file_str


def process_json_files_with_rate_limiting_parallel():
    """
    Main function that processes all JSON files in subdirectories in parallel
    while managing GitHub API rate limits.
    """
    original_cwd = os.getcwd()

    try:
        api_key = os.getenv('GITHUB_API_KEY')
        if not api_key:
            raise ValueError("GITHUB_API_KEY environment variable is not set")

        # Shared rate limit manager (thread-safe)
        rate_manager = GitHubRateLimitManager(api_key, min_requests_threshold=50)

        # Find all JSON files
        json_files = find_json_files("/mnt/d/golden_dataset")
        if not json_files:
            logger.info("No JSON files found")
            return

        processed_count = 0
        failed_files = set()

        # Use ThreadPoolExecutor for I/O + network concurrency
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            future_to_file = {
                executor.submit(process_single_json_file, str(f.resolve()), original_cwd, rate_manager): f
                for f in json_files
            }

            for future in concurrent.futures.as_completed(future_to_file):
                json_file = str(future_to_file[future])
                try:
                    success, file_path = future.result()
                    if success:
                        processed_count += 1
                    else:
                        failed_files.add(file_path)
                except Exception as e:
                    logger.error(f"Unhandled exception processing {json_file}: {e}")
                    failed_files.add(json_file)

        logger.info(f"Processing complete: {processed_count} successful, {len(failed_files)} failed")

        error_file_path = "errors.txt"
        with open(error_file_path, "w", encoding="utf-8") as f:
            f.write("\n".join(failed_files))

    finally:
        try:
            if os.getcwd() != original_cwd:
                os.chdir(original_cwd)
        except FileNotFoundError:
            if os.path.exists(original_cwd):
                os.chdir(original_cwd)

def main():
    """Entry point for the script"""
    start_time = time.time()
    
    try:
        process_json_files_with_rate_limiting_parallel()
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