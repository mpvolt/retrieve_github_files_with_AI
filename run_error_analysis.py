#!/usr/bin/env python3

from analyze_relevant_files import analyze_relevant_files
import os
import json

def check_json_has_required_fields(file_path):
    """
    Check if a JSON file contains objects with 'source_code_url' or 'fix_commit_url' fields.
    
    Args:
        file_path (str): Path to the JSON file
        
    Returns:
        bool: True if file contains at least one object with required fields, False otherwise
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
        
        # Handle different JSON structures
        if isinstance(data, dict):
            # Single object
            return has_required_fields(data)
        elif isinstance(data, list):
            # Array of objects
            for item in data:
                if isinstance(item, dict) and has_required_fields(item):
                    return True
        
        return False
        
    except (json.JSONDecodeError, FileNotFoundError, Exception) as e:
        print(f"  WARNING: Error reading JSON file {file_path}: {str(e)}")
        return False

def has_required_fields(obj):
    """
    Check if a dictionary object has at least one of the required fields.
    
    Args:
        obj (dict): Dictionary to check
        
    Returns:
        bool: True if object has 'source_code_url' or 'fix_commit_url'
    """
    return 'source_code_url' in obj or 'fix_commit_url' in obj

def filter_and_update_errors_txt(errors_file_path="errors.txt"):
    """
    Filter errors.txt to only include JSON files that contain required fields.
    
    Args:
        errors_file_path (str): Path to the errors.txt file
    """
    try:
        with open(errors_file_path, 'r') as file:
            file_paths = [line.strip() for line in file if line.strip()]
        
        print(f"Filtering {len(file_paths)} files from {errors_file_path}...")
        
        valid_files = []
        
        for i, file_path in enumerate(file_paths, 1):
            print(f"\n[{i}/{len(file_paths)}] Checking: {os.path.basename(file_path)}")
            
            # Check if file exists
            if not os.path.exists(file_path):
                print(f"  SKIP: File does not exist")
                continue
            
            # Check if it's a JSON file
            if not file_path.lower().endswith('.json'):
                print(f"  SKIP: Not a JSON file")
                continue
            
            # Check if JSON contains required fields
            if check_json_has_required_fields(file_path):
                print(f"  KEEP: Contains required fields")
                valid_files.append(file_path)
            else:
                print(f"  REMOVE: Missing required fields (source_code_url or fix_commit_url)")
        
        # Write filtered list back to errors.txt
        with open(errors_file_path, 'w') as file:
            for file_path in valid_files:
                file.write(file_path + '\n')
        
        print(f"\nFiltering complete:")
        print(f"  Original files: {len(file_paths)}")
        print(f"  Valid files: {len(valid_files)}")
        print(f"  Removed files: {len(file_paths) - len(valid_files)}")
        print(f"  Updated {errors_file_path}")
        
        return valid_files
        
    except FileNotFoundError:
        print(f"ERROR: Could not find {errors_file_path}")
        return []
    except Exception as e:
        print(f"ERROR: {str(e)}")
        return []
    """
    Read file paths from errors.txt and run analyze_relevant_files on each file.
    
    Args:
        errors_file_path (str): Path to the errors.txt file
    """
    try:
        with open(errors_file_path, 'r') as file:
            file_paths = [line.strip() for line in file if line.strip()]
        
        print(f"Found {len(file_paths)} files to process:")
        
        for i, file_path in enumerate(file_paths, 1):
            print(f"\n[{i}/{len(file_paths)}] Processing: {file_path}")
            
            # Check if file exists before processing
            if not os.path.exists(file_path):
                print(f"  WARNING: File does not exist - {file_path}")
                continue
            
            try:
                # Run analyze_relevant_files on the current file
                result = analyze_relevant_files(file_path)
                print(f"  SUCCESS: Analyzed {os.path.basename(file_path)}")
                
                # Optional: print result if needed
                # print(f"  Result: {result}")
                
            except Exception as e:
                print(f"  ERROR: Failed to analyze {file_path}")
                print(f"    {str(e)}")
                continue
        
        print(f"\nCompleted processing all files from {errors_file_path}")
        
    except FileNotFoundError:
        print(f"ERROR: Could not find {errors_file_path}")
    except Exception as e:
        print(f"ERROR: {str(e)}")

def process_files_from_errors_txt(errors_file_path="errors.txt"):
    """
    Read file paths from errors.txt and run analyze_relevant_files on each file.
    
    Args:
        errors_file_path (str): Path to the errors.txt file
    """
    try:
        with open(errors_file_path, 'r') as file:
            file_paths = [line.strip() for line in file if line.strip()]
        
        print(f"Found {len(file_paths)} files to process:")
        
        for i, file_path in enumerate(file_paths, 1):
            print(f"\n[{i}/{len(file_paths)}] Processing: {file_path}")
            
            # Check if file exists before processing
            if not os.path.exists(file_path):
                print(f"  WARNING: File does not exist - {file_path}")
                continue
            
            try:
                # Run analyze_relevant_files on the current file
                result = analyze_relevant_files(file_path)
                print(f"  SUCCESS: Analyzed {os.path.basename(file_path)}")
                
                # Optional: print result if needed
                # print(f"  Result: {result}")
                
            except Exception as e:
                print(f"  ERROR: Failed to analyze {file_path}")
                print(f"    {str(e)}")
                continue
        
        print(f"\nCompleted processing all files from {errors_file_path}")
        
    except FileNotFoundError:
        print(f"ERROR: Could not find {errors_file_path}")
    except Exception as e:
        print(f"ERROR: {str(e)}")

def main():
    """
    Main function that filters errors.txt first, then processes valid files.
    """
    errors_file_path = "errors.txt"
    
    print("Step 1: Filtering files in errors.txt...")
    valid_files = filter_and_update_errors_txt(errors_file_path)
    
    if valid_files:
        print(f"\nStep 2: Processing {len(valid_files)} valid files...")
        process_files_from_errors_txt(errors_file_path)
    else:
        print("\nNo valid files found to process.")

if __name__ == "__main__":
    main()