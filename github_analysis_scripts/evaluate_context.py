import os
import re
import json
import base64
import requests
from urllib.parse import urlparse, unquote
from typing import List, Dict, Any, Optional
from openai import OpenAI
from github_analysis_scripts.match_files_to_report_with_AI import VulnerabilityFileMatcher
from github_file_retrieval_scripts.retrieve_all_smart_contract_files import get_smart_contracts


class ContextFunctionValidator:
    """
    A helper class to validate whether vulnerability report contexts actually match
    the vulnerable functions in code using GPT-5 reasoning.
    """

    def __init__(self, openai_api_key: str, github_token: Optional[str] = None):
        self.openai_api_key = OpenAI(api_key=openai_api_key)
        self.github_token = github_token

    # --------------------------------------------------------------------------
    # -------------------------- GITHUB FILE RETRIEVAL -------------------------
    # --------------------------------------------------------------------------
    def fetch_file_content(self, source_url: str) -> Optional[str]:
        """
        Robust retrieval of source code from a GitHub blob or raw URL.

        Strategy:
        1. If the URL already points to raw.githubusercontent.com, fetch it directly.
        2. If the URL is a standard github.com/.../blob/... URL, convert to raw.githubusercontent.com and try.
        3. If raw fails, fall back to the GitHub Contents API and decode base64 content.
        4. If everything fails, return None and print helpful debug info.

        Note: For private repos or large request volumes, provide self.github_token.
        """
        try:
            if not source_url:
                return None

            headers = {}
            if self.github_token:
                headers["Authorization"] = f"token {self.github_token}"

            # 1) Direct raw.githubusercontent URL
            if "raw.githubusercontent.com" in source_url:
                try:
                    resp = requests.get(source_url, headers=headers, timeout=20)
                    if resp.status_code == 200:
                        return resp.text
                    else:
                        print(f"Raw URL fetch failed ({resp.status_code}) for {source_url}: {resp.text[:200]!r}")
                except Exception as e:
                    print(f"Raw URL request exception: {e}")

            # 2) Convert github.com/.../blob/... -> raw.githubusercontent.com/.../.../...
            parsed = urlparse(source_url)
            if "github.com" in parsed.netloc and "/blob/" in parsed.path:
                # path example: /owner/repo/blob/branch/path/to/file.sol
                # We need owner, repo, branch/commit, and file path
                parts = parsed.path.lstrip("/").split("/")

                try:
                    blob_index = parts.index("blob")
                except ValueError:
                    blob_index = -1

                if blob_index >= 0 and blob_index + 2 < len(parts):
                    owner = parts[0]
                    repo = parts[1]
                    # branch can have slashes; everything after 'blob' up to file path is branch+path splitting
                    # we treat the piece immediately after 'blob' as branch/commit and the rest as path
                    branch = parts[blob_index + 1]
                    file_parts = parts[blob_index + 2 :]
                    file_path = "/".join(file_parts)
                    # Construct raw URL: https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}
                    raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"
                    # Try raw fetch first
                    try:
                        resp = requests.get(raw_url, headers=headers, timeout=20)
                        if resp.status_code == 200:
                            return resp.text
                        else:
                            print(f"Converted raw URL fetch failed ({resp.status_code}) for {raw_url}: {resp.text[:200]!r}")
                    except Exception as e:
                        print(f"Converted raw URL request exception: {e}")

                # If conversion didn't work or failed, fall back to the API below.

            # 3) Fallback: GitHub Contents API (works for public/private if token provided)
            # Try to build an API path for github.com blob URLs or attempt to use the original path as a last resort.
            if "github.com" in parsed.netloc and "/blob/" in parsed.path:
                # Rebuild repo and path more robustly (branch may include slashes — but API expects exact branch string, so we attempt)
                segments = parsed.path.lstrip("/").split("/")
                try:
                    blob_idx = segments.index("blob")
                    owner = segments[0]
                    repo = segments[1]
                    # everything after blob is [branch, ...path parts]
                    branch = segments[blob_idx + 1]
                    file_path = "/".join(segments[blob_idx + 2 :])
                except Exception:
                    owner = repo = branch = None
                    file_path = "/".join(segments)

                if owner and repo and file_path:
                    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}"
                    params = {}
                    if branch:
                        params["ref"] = branch
                    api_headers = {"Accept": "application/vnd.github.v3+json"}
                    if self.github_token:
                        api_headers["Authorization"] = f"token {self.github_token}"

                    try:
                        resp = requests.get(api_url, headers=api_headers, params=params, timeout=20)
                        if resp.status_code == 200:
                            j = resp.json()
                            # If raw was requested by Accept header, resp.text may already be raw, but standard API returns JSON with content
                            if isinstance(j, dict) and "content" in j and "encoding" in j:
                                if j["encoding"] == "base64":
                                    decoded = base64.b64decode(j["content"]).decode("utf-8", errors="ignore")
                                    return decoded
                                else:
                                    # unexpected encoding
                                    return j.get("content")
                            else:
                                # fallback: return text
                                return resp.text
                        else:
                            # Helpful debug message
                            msg = ""
                            try:
                                msg = resp.json().get("message", "")
                            except Exception:
                                msg = resp.text[:200]
                            print(f"GitHub API fetch failed ({resp.status_code}) for {api_url} ref={branch}: {msg!r}")
                    except Exception as e:
                        print(f"GitHub API request exception: {e}")

            # 4) Last-ditch: try the original URL directly (some raw URLs / CDNs)
            try:
                resp = requests.get(source_url, headers=headers, timeout=20)
                if resp.status_code == 200:
                    return resp.text
                else:
                    print(f"Direct fetch failed ({resp.status_code}) for {source_url}: {resp.text[:200]!r}")
            except Exception as e:
                print(f"Direct fetch exception for {source_url}: {e}")

            return None

        except Exception as e:
            print(f"Error in fetch_file_content: {e}")
            return None

    # --------------------------------------------------------------------------
    # ---------------------------- FUNCTION EXTRACTION -------------------------
    # --------------------------------------------------------------------------
    def extract_function_code(self, file_content: str, function_name: str, line_number: Optional[int] = None) -> str:
        """
        Extract a specific function or modifier from source code.
        Supports Solidity, JS, Python, Rust, Move, Cairo, and Go.
        """
        if not file_content or not function_name:
            return ""

        # Patterns for multiple languages
        patterns = [
            # Solidity functions and modifiers
            rf"\bfunction\s+{re.escape(function_name)}\b[^\{{;]*\{{",
            rf"\bmodifier\s+{re.escape(function_name)}\b[^\{{;]*\{{",
            # JS / TypeScript
            rf"\bfunction\s+{re.escape(function_name)}\b[^\{{;]*\{{",
            # Rust
            rf"\bfn\s+{re.escape(function_name)}\b[^\{{;]*\{{",
            # Move
            rf"\b(public\s+)?fun\s+{re.escape(function_name)}\b[^\{{;]*\{{",
            # Go
            rf"\bfunc\s+\(*[A-Za-z0-9_\*\s]*\)*\s*{re.escape(function_name)}\b[^\{{;]*\{{",
            # Cairo
            rf"\bfunc\s+{re.escape(function_name)}\b[^\{{;]*\{{",
            # Python
            rf"def\s+{re.escape(function_name)}\b[^\:]*\:",
        ]

        match = None
        for pat in patterns:
            m = re.search(pat, file_content)
            if m:
                match = m
                break

        if not match:
            if line_number:
                lines = file_content.splitlines()
                start = max(line_number - 10, 0)
                end = min(line_number + 40, len(lines))
                return "\n".join(lines[start:end])
            return ""

        start_idx = match.start()
        block_start = match.end() - 1

        # Block-based (curly braces) languages
        if match.group().strip().endswith("{"):
            brace_count = 0
            end_idx = None
            for i, ch in enumerate(file_content[block_start:], start=block_start):
                if ch == "{":
                    brace_count += 1
                elif ch == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        end_idx = i + 1
                        break
            return file_content[start_idx:end_idx].strip() if end_idx else file_content[start_idx:start_idx + 1000].strip()
        else:
            # Python-style indentation
            lines = file_content.splitlines()
            line_index = file_content[:match.start()].count("\n")
            indent_match = re.match(r"(\s*)", lines[line_index])
            base_indent = len(indent_match.group(1)) if indent_match else 0

            block_lines = [lines[line_index]]
            for next_line in lines[line_index + 1:]:
                if not next_line.strip():
                    block_lines.append(next_line)
                    continue
                indent = len(re.match(r"(\s*)", next_line).group(1))
                if indent <= base_indent:
                    break
                block_lines.append(next_line)
            return "\n".join(block_lines).strip()


    def extract_all_functions(self, file_content: str) -> Dict[str, str]:
        """
        Extract all function and modifier names and their full code from a source file.
        Returns a dictionary: {function_name: function_code}
        """
        if not file_content:
            return {}

        # Matches functions and modifiers (Solidity, JS, Rust, Move, Go, Cairo, Python)
        patterns = [
            r"\bfunction\s+([A-Za-z0-9_]+)\b[^\{;]*\{",
            r"\bmodifier\s+([A-Za-z0-9_]+)\b[^\{;]*\{",
            r"\bconstructor\s+([A-Za-z0-9_]+)\b[^\{;]*\{",
            r"\bfn\s+([A-Za-z0-9_]+)\b[^\{;]*\{",
            r"\b(public\s+)?fun\s+([A-Za-z0-9_]+)\b[^\{;]*\{",
            r"\bfunc\s+\(*[A-Za-z0-9_\*\s]*\)*\s*([A-Za-z0-9_]+)\b[^\{;]*\{",
            r"def\s+([A-Za-z0-9_]+)\b[^\:]*\:",
        ]

        functions = {}
        for pat in patterns:
            for m in re.finditer(pat, file_content):
                name = m.group(1)
                if name not in functions:
                    code = self.extract_function_code(file_content, name)
                    functions[name] = code

        return functions



    # --------------------------------------------------------------------------
    # ------------------------ GPT-5 FUNCTION VALIDATION -----------------------
    # --------------------------------------------------------------------------
    
    #Return true or false if a function is relevant to the vulnerability report
    
    def _validate_function_relevance_gpt(self, report: Dict, function_code: str, function_name: Dict, source_url: str) -> bool:
        """
        Use GPT-5 to decide if a specific function or modifier is relevant to the vulnerability.
        Updated to use 'max_completion_tokens' (required by this model) and robust parsing.
        Returns True if GPT says the function is relevant, False otherwise.
        """
        report_summary = "\n".join(
            f"{k}: {v}" for k, v in report.items() if k != "context"
        )

        prompt = f"""
            You are a professional Web3 security auditor.

            Determine if the following function is the one that the vulnerability described.

            VULNERABILITY REPORT:
            {report_summary}

            FUNCTION SOURCE:
            {function_code}

            QUESTION:
            Is this function relevant to the vulnerability described?

            Respond strictly in JSON with exactly these keys:
            {{
            "relevant": true|false, (true if yes, false if no)
            "reasoning": "<short explanation>"
            }}
        """

        try:
            #print(prompt)
            # NOTE: use max_completion_tokens instead of max_tokens for this model
            resp = self.openai_api_key.chat.completions.create(
                model="gpt-5",
                messages=[{"role": "user", "content": prompt}],
                max_completion_tokens=800,
                response_format={"type": "json_object"},
            )

            # The SDK may return a JSON object directly or a string. Handle both.
            choice = resp.choices[0]
            content = None

            # If the SDK produced a parsed object, it might be in choice.message.content as dict-like
            try:
                # Some SDKs put the parsed JSON under .message.content if response_format was used
                content = choice.message.content
            except Exception:
                # Fallback to text
                try:
                    content = choice.message.content
                except Exception:
                    content = None

            # If content is already a dict-like object, use it directly
            if isinstance(content, dict):
                result = content
            else:
                # content may be a JSON string, or may contain stray text. Try several parse strategies.
                text = (content or "").strip()
                result = None

                # Strategy 1: direct json load
                try:
                    result = json.loads(text)
                except Exception:
                    # Strategy 2: extract JSON object from text
                    try:
                        start = text.index("{")
                        end = text.rindex("}") + 1
                        candidate = text[start:end]
                        result = json.loads(candidate)
                    except Exception:
                        result = None

                # Strategy 3: last resort, ask for "relevant" token with simple heuristics
                if result is None:
                    # Try to find a "true" or "false" token in the text
                    if re.search(r'\btrue\b', text, re.IGNORECASE):
                        result = {"relevant": True, "reasoning": text[:400]}
                    elif re.search(r'\bfalse\b', text, re.IGNORECASE):
                        result = {"relevant": False, "reasoning": text[:400]}
                    else:
                        # Unknown - treat as not relevant but log content
                        print("Warning: Could not parse GPT response as JSON. Response snippet:")
                        print(text[:800])
                        return False

            # At this point, result should be a dict
            relevant = bool(result.get("relevant", False))

            return relevant

        except Exception as e:
            # Try to surface raw API error details if available
            try:
                # If the SDK returned a structured error object, show it
                err_txt = getattr(e, "args", [str(e)])[0]
                print(f"GPT-5 validation failed for {function_name}@({source_url}): {err_txt}")
            except Exception:
                print(f"GPT-5 validation failed for {function_name}@({source_url}): {e}")
            return False
    
    # --------------------------------------------------------------------------
    # --------------------------- MAIN VALIDATION LOOP -------------------------
    # --------------------------------------------------------------------------
    def validate_context_functions(self, reports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Main entrypoint:
        For each vulnerability report:
          - Validate all context functions
          - Return a cleaned list of validated reports
        """
        cleaned_reports = []  # List to hold the cleaned/validated reports

        # Iterate over each report (each report is one vulnerability finding)
        for report in reports:
            print(f"\nValidating report: {report.get('title')}")

            # Validate the "context" sections of this report (each context is usually a file + functions)
            validated_contexts = self._validate_report_contexts(report)

            if validated_contexts:
                # Replace old contexts with only the validated ones
                report["context"] = validated_contexts
            
            

            # Append the cleaned report to the result list
            cleaned_reports.append(report)

        # Return all validated reports
        return cleaned_reports

    # -------------------------------------------------------------------------
    # 1️⃣ Validate all contexts in a report
    # -------------------------------------------------------------------------
    def _validate_report_contexts(self, report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Iterate through each code context in the report, fetch the corresponding source file,
        and validate the functions listed under that context.
        """
        valid_contexts = []

        contexts = report.get("context")
        if contexts:
            # Normal flow — iterate through provided contexts
            for ctx in contexts:
                source_url = ctx.get("source")

                file_content = self.fetch_file_content(source_url)
                if not file_content:
                    print(f"  Skipping {source_url}: unable to fetch content")
                    continue

                valid_funcs = self._validate_context_functions(report, ctx, file_content)

                if valid_funcs:
                    new_ctx = dict(ctx)
                    new_ctx["functions"] = valid_funcs
                    valid_contexts.append(new_ctx)
                else:
                    new_ctx = self.check_other_files(report)
                    valid_contexts.append(new_ctx)

        else:
            # Fallback: no "context", but possibly afflicted_github_code_blob
            afflicted_blobs = report.get("afflicted_github_code_blob", [])
            if afflicted_blobs:
                source_url = afflicted_blobs[0]
                file_content = self.fetch_file_content(source_url)
                if file_content:
                    # Build a minimal fake context to reuse the same validation logic
                    fake_ctx = {"source": source_url, "functions": []}

                    valid_funcs = self._validate_context_functions(report, fake_ctx, file_content)

                    if valid_funcs:
                        new_ctx = dict(fake_ctx)
                        new_ctx["functions"] = valid_funcs
                        valid_contexts.append(new_ctx)
                    else:
                        new_ctx = self.check_other_files(report)
                        valid_contexts.append(new_ctx)
                else:
                    print(f"  Skipping {source_url}: unable to fetch content")
            else:
                print("  Skipping: no context or afflicted_github_code_blob found")

        # Return only the contexts that contained valid/relevant functions
        return valid_contexts

    # -------------------------------------------------------------------------
    # 2️⃣ Validate functions within a single context
    # -------------------------------------------------------------------------
    def _validate_context_functions(
        self, report: Dict[str, Any], ctx: Dict[str, Any], file_content: str
    ) -> List[Dict[str, Any]]:
        """
        Validate each function referenced in the given context:
          - Extract the function code from the source file
          - Ask GPT (or another model) whether it's relevant to the vulnerability
          - If not, search the file for other potentially relevant functions
        """
        valid_funcs = []

        # Loop over each function entry in this context
        for func in ctx.get("functions", []):
            # Extract the actual function code from the file based on name and line number
            fn_code = self.extract_function_code(
                file_content, func.get("name"), func.get("line_number")
            )

            # Skip if the function couldn’t be extracted (e.g., name mismatch, parser issue)
            if not fn_code:
                print(f"  Could not extract code for function: {func.get('name')}")
                continue

            # Check whether this function is relevant to the vulnerability
            if self._is_function_relevant(report, fn_code, func.get("name"), ctx.get("source")):
                # If relevant, keep it in the validated list
                valid_funcs.append(func)
            else:
                # If not relevant, search for other potentially related functions in the same file
                valid_funcs += self._search_related_functions(report, file_content, ctx.get("source"))

        # Return only functions that were validated or found to be relevant
        return valid_funcs

    # -------------------------------------------------------------------------
    # 3️⃣ Wrapper for GPT-based relevance check
    # -------------------------------------------------------------------------
    def _is_function_relevant(
        self, report: Dict[str, Any], fn_code: str, func: str, source_url: str
    ) -> bool:
        """
        Uses an AI model (GPT) to determine whether a given function
        is actually related to the described vulnerability.
        """
        # Ask GPT to assess relevance given the report metadata and function code
        relevant = self._validate_function_relevance_gpt(report, fn_code, func, source_url)

        # Print the result for debugging/logging
        print(f"  Function {func} relevance: {relevant}")
        return relevant

    # -------------------------------------------------------------------------
    # 4️⃣ Explore related functions in same file
    # -------------------------------------------------------------------------
    def _search_related_functions(
        self, report: Dict[str, Any], file_content: str, source_url: str
    ) -> List[Dict[str, Any]]:
        """
        If the initially listed function isn't relevant,
        search through all other functions in the same file to find related ones.
        """
        related_funcs = []

        # Extract all functions from the file as (name, code) pairs
        all_functions = self.extract_all_functions(file_content)
        #print(all_functions)

        # Analyze each extracted function using a custom heuristic or GPT call
        for function_name, function_code in all_functions.items():
            relevant = self. _validate_function_relevance_gpt(report, function_code, function_name, source_url)
            if relevant:
                relevant_func = {
                    "name": function_name,
                }
                related_funcs.extend(relevant_func)

        # Return all newly found relevant functions
        return related_funcs


    # -------------------------------------------------------------------------
    # Explore other files for relevant functions
    # -------------------------------------------------------------------------
    def check_other_files(self, report: Dict[str, Any]):
        context = report.get("context", [])
        first_source = context[0].get("source")

        all_smart_contract_files = get_smart_contracts(first_source, self.github_token)
        matcher = VulnerabilityFileMatcher(self.openai_api_key, self.github_token)
        matches = matcher.process_files(report, all_smart_contract_files['files'])
        medium_confidence_matches = [match for match in matches if match.total_score >= 60]
        valid_ctxs = []
        for file in medium_confidence_matches['files']:
            file_content = self.fetch_file_content(file.blob_url)
            relevant_funcs = self._search_related_functions(report, file_content, file)
            valid_ctxs.extend({
                "source": file.blob_url,
                "functions": relevant_funcs
            })

        return valid_ctxs



# ------------------------------------------------------------------------------
# ----------------------------- Example Usage ----------------------------------
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    # Load reports from a JSON file
    with open("/Users/matt/vulnaut/retrieve_github_files_with_AI/github_analysis_scripts/filtered_sommelier-4_findings.json") as f:
        reports = json.load(f)

    matcher = ContextFunctionValidator(
        openai_api_key=os.getenv("OPENAI_API_KEY"),
        github_token=os.getenv("GITHUB_API_KEY")
    )

    cleaned = matcher.validate_context_functions(reports)

    with open("validated_reports.json", "w") as f:
        json.dump(cleaned, f, indent=2)

    print("\n✅ Validation complete. Cleaned data written to validated_reports.json")
