import os
import json
import re

# Regex to match GitHub pull or commit URLs
GITHUB_PULL_OR_COMMIT = re.compile(
    r'https?://github\.com/[^/]+/[^/]+/(pull/\d+|commit/[0-9a-f]{5,40})'
)

def move_github_commits_from_source_urls(obj):
    if not isinstance(obj, dict):
        return
    # Recursively process nested objects/lists
    for v in obj.values():
        if isinstance(v, dict):
            move_github_commits_from_source_urls(v)
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    move_github_commits_from_source_urls(item)

    # Now process this object, if "source_urls" is present
    if "source_urls" in obj:
        src = obj["source_urls"]
        # Accept comma-separated string or list
        if isinstance(src, str):
            urls = [u.strip() for u in src.split(",") if u.strip()]
        elif isinstance(src, list):
            urls = list(src)
        else:
            return # ignore non-list/non-str cases

        matches = []
        nonmatches = []
        for url in urls:
            if GITHUB_PULL_OR_COMMIT.search(url):
                matches.append(url)
            else:
                nonmatches.append(url)

        if matches:
            obj["fixed_commit_url"] = matches if len(matches) > 1 else matches[0]
        if nonmatches:
            obj["source_urls"] = nonmatches if len(nonmatches) > 1 else nonmatches[0]
        else:
            obj.pop("source_urls")
    # done

def process_file(fname):
    with open(fname, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if isinstance(data, dict):
        move_github_commits_from_source_urls(data)
    elif isinstance(data, list):
        for obj in data:
            if isinstance(obj, dict):
                move_github_commits_from_source_urls(obj)
    with open(fname, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def main():
    for fname in os.listdir('.'):
        if fname.lower().endswith('.json') and os.path.isfile(fname):
            print("Processing:", fname)
            try:
                process_file(fname)
            except Exception as e:
                print(f"Error in {fname}: {e}")

if __name__ == "__main__":
    main()