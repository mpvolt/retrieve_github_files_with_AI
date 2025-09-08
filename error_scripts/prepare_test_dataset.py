#!/usr/bin/env python3
import json
import os
import glob
from pathlib import Path

def filter_json_files():
    """
    Read all JSON files in current directory and subdirectories, filter objects that have either
    'source_code_url' or 'fix_commit_url' fields, and delete files with no remaining objects.
    """
    required_fields = {"source_code_url", "fix_commit_url"}
    
    # Get all JSON files in current directory and subdirectories recursively
    json_files = glob.glob("**/*.json", recursive=True)
    
    if not json_files:
        print("No JSON files found in current directory or subdirectories.")
        return
    
    files_processed = 0
    files_deleted = 0
    objects_removed = 0
    
    for filename in json_files:
        try:
            print(f"Processing: {filename}")
            file_path = Path(filename)
            
            # Read the JSON file
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Handle different JSON structures
            filtered_data = None
            original_count = 0
            
            if isinstance(data, list):
                # If root is an array of objects
                original_count = len(data)
                print(f"  📋 Found {original_count} objects in array")
                
                filtered_data = []
                for i, obj in enumerate(data):
                    if isinstance(obj, dict):
                        has_fields = [field for field in required_fields if field in obj]
                        if has_fields:
                            filtered_data.append(obj)
                            print(f"    ✅ Object {i+1}: Has fields {has_fields}")
                        else:
                            print(f"    ❌ Object {i+1}: Missing required fields")
                    else:
                        print(f"    ⚠️  Object {i+1}: Not a dictionary, skipping")
                
                print(f"  📊 Kept {len(filtered_data)} out of {original_count} objects")
                
            elif isinstance(data, dict):
                # If root is an object, check if it contains arrays or nested objects
                if any(field in data for field in required_fields):
                    # Root object itself has required fields
                    filtered_data = data
                    original_count = 1
                else:
                    # Check if it's a container with arrays/objects
                    filtered_data = {}
                    for key, value in data.items():
                        if isinstance(value, list):
                            original_count += len(value)
                            filtered_list = [
                                obj for obj in value 
                                if isinstance(obj, dict) and any(field in obj for field in required_fields)
                            ]
                            if filtered_list:
                                filtered_data[key] = filtered_list
                        elif isinstance(value, dict) and any(field in value for field in required_fields):
                            original_count += 1
                            filtered_data[key] = value
                    
                    # If no valid structure found, treat as empty
                    if not filtered_data:
                        original_count = 1
            
            # Calculate objects removed
            if isinstance(filtered_data, list):
                remaining_count = len(filtered_data)
            elif isinstance(filtered_data, dict):
                if any(field in filtered_data for field in required_fields):
                    remaining_count = 1
                else:
                    remaining_count = sum(
                        len(v) if isinstance(v, list) else 1 
                        for v in filtered_data.values()
                    )
            else:
                remaining_count = 0
            
            objects_removed += (original_count - remaining_count)
            
            # Check if we should delete the file or update it
            should_delete = False
            
            if isinstance(filtered_data, list):
                # Delete only if the filtered list is empty
                should_delete = len(filtered_data) == 0
            elif isinstance(filtered_data, dict):
                # Delete if dict is empty or has no valid content
                if not filtered_data:
                    should_delete = True
                else:
                    # Check if dict has required fields directly, or has non-empty arrays/objects
                    has_required_fields = any(field in filtered_data for field in required_fields)
                    has_valid_content = any(
                        (isinstance(v, list) and len(v) > 0) or 
                        (isinstance(v, dict) and len(v) > 0)
                        for v in filtered_data.values()
                    )
                    should_delete = not (has_required_fields or has_valid_content)
            else:
                should_delete = True
            
            if should_delete:
                os.remove(file_path)
                print(f"  ❌ Deleted {filename} (no objects with required fields)")
                files_deleted += 1
            else:
                # Write back the filtered data
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(filtered_data, f, indent=2, ensure_ascii=False)
                print(f"  ✅ Updated {filename} ({remaining_count}/{original_count} objects kept)")
            
            files_processed += 1
            
        except json.JSONDecodeError as e:
            print(f"  ⚠️  Error reading {filename}: Invalid JSON - {e}")
        except Exception as e:
            print(f"  ⚠️  Error processing {filename}: {e}")
    
    # Summary
    print(f"\n📊 Summary:")
    print(f"Files processed: {files_processed}")
    print(f"Files deleted: {files_deleted}")
    print(f"Files updated: {files_processed - files_deleted}")
    print(f"Objects removed: {objects_removed}")
    print(f"Required fields: {', '.join(required_fields)}")

if __name__ == "__main__":
    print("🔍 Starting JSON file filtering...")
    print("Looking for objects with 'source_code_url' OR 'fix_commit_url' fields")
    print("Searching current directory and all subdirectories...")
    print("-" * 60)
    
    filter_json_files()
    
    print("-" * 60)
    print("✨ Done!")