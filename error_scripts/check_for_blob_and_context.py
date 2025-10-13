#!/usr/bin/env python3
import json
import os
import sys
import shutil
from pathlib import Path
from collections import defaultdict

def process_directory(root_dir):
    """
    Process all JSON files in directory and subdirectories.
    Remove objects that have BOTH 'context' and 'afflicted_github_code_blob' fields.
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
            is_array = isinstance(data, list)
            objects = data if is_array else [data]
            
            # Filter objects - keep only those that DON'T have both fields
            filtered_objects = []
            for obj in objects:
                if isinstance(obj, dict):
                    stats['total_objects'] += 1
                    
                    # Check if field exists AND is non-empty
                    has_afflicted = 'afflicted_github_code_blob' in obj and obj['afflicted_github_code_blob']
                    has_context = 'context' in obj and obj['context']
                    
                    # Keep object only if it doesn't have BOTH fields
                    if not (has_afflicted and has_context):
                        filtered_objects.append(obj)
                        stats['objects_kept'] += 1
                    else:
                        stats['objects_removed'] += 1
                        print(f"Removed object with both fields from: {json_file.name}")
            
            # Determine what to do with the file
            if len(filtered_objects) == 0:
                # Delete empty file
                json_file.unlink()
                stats['files_deleted'] += 1
                print(f"Deleted empty file: {json_file}")
            elif len(filtered_objects) < len(objects):
                # File was modified - write back filtered data
                result_data = filtered_objects if is_array else filtered_objects[0]
                with open(json_file, 'w', encoding='utf-8') as f:
                    json.dump(result_data, f, indent=2, ensure_ascii=False)
                stats['files_modified'] += 1
                print(f"Modified file: {json_file}")
        
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
    print(f"Objects REMOVED (had both fields): {stats['objects_removed']}")
    print(f"Objects KEPT: {stats['objects_kept']}")
    print()
    print(f"Files modified: {stats['files_modified']}")
    print(f"Files deleted (empty): {stats['files_deleted']}")
    print("="*60)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <directory_path>")
        sys.exit(1)
    
    directory = sys.argv[1]
    process_directory(directory)