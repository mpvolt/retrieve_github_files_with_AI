import os
import json
import re

# Regex for detecting GitHub URLs
GITHUB_URL_RE = re.compile(r"https?://github\.com/\S+")

def extract_github_url(text):
    """Return first GitHub URL found in text, or None."""
    if not isinstance(text, str):
        return None
    match = GITHUB_URL_RE.search(text)
    return match.group(0) if match else None

def process_object(obj):
    """Check an object and update fields if necessary."""
    if not isinstance(obj, dict):
        return obj

    # files → source_code_url
    if "files" in obj and "source_code_url" not in obj:
        url = extract_github_url(obj["files"])
        if url:
            obj["source_code_url"] = url

    # status → fix_commit_url
    if "status" in obj and "fix_commit_url" not in obj:
        url = extract_github_url(obj["status"])
        if url:
            obj["fix_commit_url"] = url

    return obj

def process_file(path):
    with open(path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Skipping {path}, invalid JSON: {e}")
            return

    # Handle dict or list at root
    if isinstance(data, dict):
        data = process_object(data)
    elif isinstance(data, list):
        data = [process_object(obj) for obj in data]

    # Save back
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def main(directory="."):
    for filename in os.listdir(directory):
        if filename.endswith(".json"):
            path = os.path.join(directory, filename)
            process_file(path)
            print(f"Processed {path}")

if __name__ == "__main__":
    main(".")
