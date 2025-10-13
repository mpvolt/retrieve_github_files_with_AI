#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

def process_directory(root_dir):
    """
    Process all JSON files in directory and subdirectories.
    Remove objects that have BOTH 'afflicted_github_code_blob' AND 'context' fields (non-empty).
    Delete files that become empty after removal.
    """
    root_path = Path(root_dir)
    
    if not root_path.exists():
        print(f"Error: Directory '{root_dir}' does not exist")
        sys.exit(1)
    
    # Statistics counters
    stats = {
        'total_files': 0,
        'total_objects': 0,
        'objects_removed': 0,
        'objects_kept': 0,
        'files_modified': 0,
        'files_deleted': 0,
        'parse_errors': 0
    }
    
    # Find all JSON files
    json_files = list(root_path.rglob('*.json'))
    
    print(f"Found {len(json_files)} JSON files to process\n")
    
    for json_file in json_files:
        stats['total_files'] += 1
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Handle both single objects and arrays of objects
            was_list = isinstance(data, list)
            objects = data if was_list else [data]
            
            # Filter objects - keep only those WITHOUT both fields
            filtered_objects = []
            
            for obj in objects:
                if isinstance(obj, dict):
                    stats['total_objects'] += 1
                    
                    # Check if field exists AND is non-empty
                    has_afflicted = 'afflicted_github_code_blob' in obj and obj['afflicted_github_code_blob']
                    has_context = 'context' in obj and obj['context']
                    
                    # Remove object only if it has BOTH fields (non-empty)
                    if has_afflicted and has_context:
                        stats['objects_removed'] += 1
                    else:
                        # Keep object if it's missing at least one field (or one is empty)
                        filtered_objects.append(obj)
                        stats['objects_kept'] += 1
            
            # Determine what to do with the file
            if len(filtered_objects) == 0:
                # Delete the file if no objects remain
                json_file.unlink()
                stats['files_deleted'] += 1
                print(f"Deleted (empty): {json_file.relative_to(root_path)}")
            elif len(filtered_objects) != len(objects):
                # Write back the filtered data if something was removed
                result = filtered_objects if was_list else filtered_objects[0]
                
                with open(json_file, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)
                
                stats['files_modified'] += 1
                print(f"Modified: {json_file.relative_to(root_path)} ({len(objects)} -> {len(filtered_objects)} objects)")
        
        except json.JSONDecodeError as e:
            stats['parse_errors'] += 1
            print(f"Error parsing {json_file}: {e}")
        except Exception as e:
            print(f"Error processing {json_file}: {e}")
    
    # Print statistics
    print("\n" + "="*60)
    print("STATISTICS")
    print("="*60)
    print(f"Total JSON files processed: {stats['total_files']}")
    print(f"Files with parse errors: {stats['parse_errors']}")
    print(f"Total objects processed: {stats['total_objects']}")
    print()
    print(f"Objects removed (had BOTH fields): {stats['objects_removed']}")
    print(f"Objects kept (missing at least one): {stats['objects_kept']}")
    print()
    print(f"Files modified: {stats['files_modified']}")
    print(f"Files deleted (became empty): {stats['files_deleted']}")
    print("="*60)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <directory_path>")
        print("\nWARNING: This script will modify and delete files!")
        print("Consider backing up your data before running.")
        sys.exit(1)
    
    directory = sys.argv[1]
    
    # Confirmation prompt
    print(f"WARNING: This will modify/delete JSON files in '{directory}'")
    response = input("Are you sure you want to continue? (yes/no): ")
    
    if response.lower() != 'yes':
        print("Operation cancelled.")
        sys.exit(0)
    
    process_directory(directory)