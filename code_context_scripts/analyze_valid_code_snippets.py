#!/usr/bin/env python3
"""
Script to analyze broken and fixed code snippets from JSON vulnerability reports
using GPT-4o-mini to determine if they contain sufficient context.
Removes snippets marked as "INSUFFICIENT" and preserves all other JSON fields.
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import List, Dict, Any, Union
import openai
from openai import OpenAI

# Configuration
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')  # Set your OpenAI API key as environment variable
MODEL_NAME = "gpt-4.1-mini"
DELAY_BETWEEN_REQUESTS = 1  # seconds to avoid rate limiting

class VulnerabilityAnalyzer:
    def __init__(self, api_key: str = None):
        """Initialize the analyzer with OpenAI client."""
        if api_key:
            self.client = OpenAI(api_key=api_key)
        elif OPENAI_API_KEY:
            self.client = OpenAI(api_key=OPENAI_API_KEY)
        else:
            raise ValueError("OpenAI API key must be provided either as parameter or OPENAI_API_KEY environment variable")
    
    def find_json_files(self, directory: str) -> List[Path]:
        """Find all JSON files in the specified directory."""
        directory_path = Path(directory)
        if not directory_path.exists():
            raise FileNotFoundError(f"Directory {directory} does not exist")
        
        json_files = list(directory_path.rglob("*.json"))
        print(f"Found {len(json_files)} JSON files in {directory}")
        return json_files
    
    def read_json_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Read and parse JSON file. Handle both single objects and arrays."""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
                
            # Ensure we return a list of objects
            if isinstance(data, dict):
                return [data]
            elif isinstance(data, list):
                return data
            else:
                print(f"Warning: Unexpected data type in {file_path}")
                return []
                
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON file {file_path}: {e}")
            return []
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return []
    
    def extract_code_snippets(self, json_obj: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract both broken_code_snippets and fixed_code_snippets from a JSON object."""
        result = {
            "broken": [],
            "fixed": []
        }
        
        # Extract broken_code_snippets
        broken_snippets = json_obj.get("broken_code_snippets", [])
        if isinstance(broken_snippets, str):
            result["broken"] = [broken_snippets]
        elif isinstance(broken_snippets, list):
            result["broken"] = [snippet for snippet in broken_snippets if isinstance(snippet, str)]
        
        # Extract fixed_code_snippets
        fixed_snippets = json_obj.get("fixed_code_snippets", [])
        if isinstance(fixed_snippets, str):
            result["fixed"] = [fixed_snippets]
        elif isinstance(fixed_snippets, list):
            result["fixed"] = [snippet for snippet in fixed_snippets if isinstance(snippet, str)]
        
        return result
    
    def create_analysis_prompt(self, snippet: str, snippet_type: str, title: str, description: str, recommendation: str) -> str:
        """Create the prompt for GPT-4o-mini analysis based on snippet type."""
        
        if snippet_type == "broken":
            context_questions = """
1. Understand what the vulnerability is
2. Identify the specific problematic pattern in the code
3. Comprehend why this code is vulnerable
4. Understand how the vulnerability could be exploited"""
            snippet_label = "Vulnerable Code Snippet"
        else:  # fixed
            context_questions = """
1. Understand what the original vulnerability was
2. Identify how the fix addresses the problematic pattern
3. Comprehend why this fix resolves the vulnerability
4. Understand the security improvement implemented"""
            snippet_label = "Fixed Code Snippet"

        prompt = f"""You are a security expert analyzing code vulnerabilities. Please evaluate whether the following {snippet_type} code snippet contains enough context to understand the vulnerability pattern when combined with the provided information.

**Title:** {title}

**Description:** {description[:1000]}

**Recommendation:** {recommendation[:1000]}

**{snippet_label}:**
```
{snippet}
```

Please analyze whether this {snippet_type} code snippet, combined with the title, description, and recommendation, provides sufficient context to:
{context_questions}

Respond with:
- "SUFFICIENT": If the snippet provides enough context to understand the vulnerability pattern
- "INSUFFICIENT": If the snippet lacks important context needed to understand the vulnerability
- Include a brief explanation (1-2 sentences) of your reasoning

Format your response as:
ASSESSMENT: [SUFFICIENT/INSUFFICIENT]
REASONING: [Your explanation]
"""
        return prompt
    
    def analyze_snippet_with_gpt(self, snippet: str, snippet_type: str, title: str, description: str, recommendation: str) -> Dict[str, str]:
        """Send code snippet to GPT-4o-mini for analysis."""
        try:
            prompt = self.create_analysis_prompt(snippet, snippet_type, title, description, recommendation)
            
            response = self.client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                max_tokens=500,
                temperature=0.1
            )
            
            content = response.choices[0].message.content.strip()
            
            # Parse the response
            lines = content.split('\n')
            assessment = "UNKNOWN"
            reasoning = "No reasoning provided"
            
            for line in lines:
                line = line.strip()
                if line.startswith("ASSESSMENT:"):
                    assessment = line.replace("ASSESSMENT:", "").strip()
                elif line.startswith("REASONING:"):
                    reasoning = line.replace("REASONING:", "").strip()
            
            return {
                "assessment": assessment,
                "reasoning": reasoning,
                "full_response": content
            }
            
        except Exception as e:
            print(f"Error calling OpenAI API: {e}")
            return {
                "assessment": "ERROR",
                "reasoning": f"API call failed: {str(e)}",
                "full_response": ""
            }
    
    def filter_snippets_by_assessment(self, snippets: List[str], assessments: List[str]) -> List[str]:
        """Filter snippets to keep only those marked as SUFFICIENT."""
        filtered_snippets = []
        for snippet, assessment in zip(snippets, assessments):
            if assessment == "SUFFICIENT":
                filtered_snippets.append(snippet)
        return filtered_snippets
    
    def process_json_object(self, json_obj: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single JSON object, analyzing and filtering code snippets."""
        # Create a deep copy to avoid modifying the original
        processed_obj = json_obj.copy()
        
        # Extract required fields for analysis
        title = json_obj.get("title", "No title provided")
        description = json_obj.get("description", "No description provided")
        recommendation = json_obj.get("recommendation", "No recommendation provided")
        
        # Extract code snippets
        snippets = self.extract_code_snippets(json_obj)
        
        analysis_results = {
            "broken": {"assessments": [], "removed_count": 0},
            "fixed": {"assessments": [], "removed_count": 0}
        }
        
        # Process broken code snippets
        if snippets["broken"]:
            print(f"    Analyzing {len(snippets['broken'])} broken snippet(s)")
            for i, snippet in enumerate(snippets["broken"]):
                analysis = self.analyze_snippet_with_gpt(snippet, "broken", title, description, recommendation)
                analysis_results["broken"]["assessments"].append(analysis["assessment"])
                
                status_icon = "✓" if analysis["assessment"] == "SUFFICIENT" else "✗" if analysis["assessment"] == "INSUFFICIENT" else "⚠"
                print(f"      [{i+1}] {status_icon} {analysis['assessment']}: {analysis['reasoning']}")
                
                time.sleep(DELAY_BETWEEN_REQUESTS)
            
            # Filter broken snippets
            original_count = len(snippets["broken"])
            filtered_broken = self.filter_snippets_by_assessment(snippets["broken"], analysis_results["broken"]["assessments"])
            analysis_results["broken"]["removed_count"] = original_count - len(filtered_broken)
            
            # Update the object with filtered snippets
            if "broken_code_snippets" in processed_obj:
                if len(filtered_broken) == 0:
                    # Remove the field entirely if no snippets remain
                    del processed_obj["broken_code_snippets"]
                elif isinstance(json_obj["broken_code_snippets"], str):
                    # Original was a string, keep as string if exactly one remains
                    processed_obj["broken_code_snippets"] = filtered_broken
                else:
                    # Original was a list, keep as list
                    processed_obj["broken_code_snippets"] = filtered_broken
        
        # Process fixed code snippets
        if snippets["fixed"]:
            print(f"    Analyzing {len(snippets['fixed'])} fixed snippet(s)")
            for i, snippet in enumerate(snippets["fixed"]):
                analysis = self.analyze_snippet_with_gpt(snippet, "fixed", title, description, recommendation)
                analysis_results["fixed"]["assessments"].append(analysis["assessment"])
                
                status_icon = "✓" if analysis["assessment"] == "SUFFICIENT" else "✗" if analysis["assessment"] == "INSUFFICIENT" else "⚠"
                print(f"      [{i+1}] {status_icon} {analysis['assessment']}: {analysis['reasoning']}")
                
                time.sleep(DELAY_BETWEEN_REQUESTS)
            
            # Filter fixed snippets
            original_count = len(snippets["fixed"])
            filtered_fixed = self.filter_snippets_by_assessment(snippets["fixed"], analysis_results["fixed"]["assessments"])
            analysis_results["fixed"]["removed_count"] = original_count - len(filtered_fixed)
            
            # Update the object with filtered snippets
            if "fixed_code_snippets" in processed_obj:
                if len(filtered_fixed) == 0:
                    # Remove the field entirely if no snippets remain
                    del processed_obj["fixed_code_snippets"]
                elif isinstance(json_obj["fixed_code_snippets"], str):
                    # Original was a string, keep as string if exactly one remains
                    processed_obj["fixed_code_snippets"] = filtered_fixed
                else:
                    # Original was a list, keep as list
                    processed_obj["fixed_code_snippets"] = filtered_fixed
        
        return processed_obj, analysis_results
    
    def process_directory(self, directory: str, output_dir: str = None) -> Dict[str, Any]:
        """Process all JSON files in directory and subdirectories, filtering code snippets."""
        json_files = self.find_json_files(directory)
        
        if output_dir:
            output_path = Path(output_dir)
            output_path.mkdir(exist_ok=True)
        else:
            output_path = Path(directory) / "filtered"
            output_path.mkdir(exist_ok=True)
        
        summary_stats = {
            "files_processed": 0,
            "objects_processed": 0,
            "broken_snippets": {"total": 0, "removed": 0, "kept": 0},
            "fixed_snippets": {"total": 0, "removed": 0, "kept": 0},
            "analysis_results": []
        }
        
        for file_path in json_files:
            print(f"\nProcessing file: {file_path}")
            json_objects = self.read_json_file(file_path)
            
            if not json_objects:
                continue
            
            processed_objects = []
            
            for obj_index, json_obj in enumerate(json_objects):
                print(f"  Object {obj_index + 1}:")
                
                # Extract snippets for counting
                snippets = self.extract_code_snippets(json_obj)
                total_broken = len(snippets["broken"])
                total_fixed = len(snippets["fixed"])
                
                if total_broken == 0 and total_fixed == 0:
                    print(f"    No code snippets found, keeping object unchanged")
                    processed_objects.append(json_obj)
                    continue
                
                # Process the object
                processed_obj, analysis_results = self.process_json_object(json_obj)
                processed_objects.append(processed_obj)
                
                # Update statistics
                summary_stats["broken_snippets"]["total"] += total_broken
                summary_stats["broken_snippets"]["removed"] += analysis_results["broken"]["removed_count"]
                summary_stats["broken_snippets"]["kept"] += total_broken - analysis_results["broken"]["removed_count"]
                
                summary_stats["fixed_snippets"]["total"] += total_fixed
                summary_stats["fixed_snippets"]["removed"] += analysis_results["fixed"]["removed_count"]
                summary_stats["fixed_snippets"]["kept"] += total_fixed - analysis_results["fixed"]["removed_count"]
                
                # Print object summary
                removed_broken = analysis_results["broken"]["removed_count"]
                removed_fixed = analysis_results["fixed"]["removed_count"]
                if removed_broken > 0 or removed_fixed > 0:
                    print(f"    Removed: {removed_broken} broken, {removed_fixed} fixed snippet(s)")
                else:
                    print(f"    All snippets kept (sufficient context)")
            
            # Save processed file
            # Calculate relative path to maintain directory structure
            base_path = Path(directory)
            relative_path = file_path.relative_to(base_path)
            output_file = output_path / relative_path

            # Create subdirectories if they don't exist
            output_file.parent.mkdir(parents=True, exist_ok=True)

            # Save processed file
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    if len(processed_objects) == 1 and len(json_objects) == 1:
                        # Single object file - maintain original structure
                        json.dump(processed_objects[0], f, indent=2, ensure_ascii=False)
                    else:
                        # Array file - maintain array structure
                        json.dump(processed_objects, f, indent=2, ensure_ascii=False)
                
                print(f"  Saved filtered file: {output_file}")
                summary_stats["files_processed"] += 1
                summary_stats["objects_processed"] += len(processed_objects)
                
            except Exception as e:
                print(f"  Error saving file {output_file}: {e}")
        
        return summary_stats
    
    def print_summary(self, stats: Dict[str, Any], output_path: Path):
        """Print a comprehensive summary of the filtering results."""
        print(f"\n{'='*70}")
        print("VULNERABILITY FILTERING SUMMARY")
        print(f"{'='*70}")
        
        print(f"Files processed: {stats['files_processed']}")
        print(f"Objects processed: {stats['objects_processed']}")
        print(f"Output directory: {output_path}")
        print()
        
        # Broken snippets stats
        broken = stats["broken_snippets"]
        if broken["total"] > 0:
            kept_pct = (broken["kept"] / broken["total"]) * 100
            print(f"BROKEN CODE SNIPPETS:")
            print(f"  Total analyzed: {broken['total']}")
            print(f"  ✓ Kept (sufficient): {broken['kept']} ({kept_pct:.1f}%)")
            print(f"  ✗ Removed (insufficient): {broken['removed']} ({100-kept_pct:.1f}%)")
            print()
        
        # Fixed snippets stats
        fixed = stats["fixed_snippets"]
        if fixed["total"] > 0:
            kept_pct = (fixed["kept"] / fixed["total"]) * 100
            print(f"FIXED CODE SNIPPETS:")
            print(f"  Total analyzed: {fixed['total']}")
            print(f"  ✓ Kept (sufficient): {fixed['kept']} ({kept_pct:.1f}%)")
            print(f"  ✗ Removed (insufficient): {fixed['removed']} ({100-kept_pct:.1f}%)")
            print()
        
        # Overall quality
        total_snippets = broken["total"] + fixed["total"]
        total_kept = broken["kept"] + fixed["kept"]
        
        if total_snippets > 0:
            overall_quality = (total_kept / total_snippets) * 100
            print(f"OVERALL QUALITY:")
            print(f"  Total snippets: {total_snippets}")
            print(f"  Quality score: {overall_quality:.1f}% (snippets with sufficient context)")
            
            if overall_quality >= 80:
                print(f"  Assessment: Excellent snippet quality! 🎉")
            elif overall_quality >= 60:
                print(f"  Assessment: Good snippet quality ✓")
            elif overall_quality >= 40:
                print(f"  Assessment: Moderate snippet quality ⚠")
            else:
                print(f"  Assessment: Low snippet quality - consider improving documentation ⚠")
        
        print(f"{'='*70}")

def main():
    """Main function to run the analyzer."""
    if len(sys.argv) < 2:
        print("Usage: python vulnerability_filter.py <input_directory> [output_directory]")
        print("Example: python vulnerability_filter.py ./vulnerability_reports ./filtered_reports")
        print("\nThis script will:")
        print("- Analyze broken_code_snippets and fixed_code_snippets in JSON files")
        print("- Remove snippets that lack sufficient context (marked as INSUFFICIENT)")
        print("- Preserve all other JSON fields unchanged")
        print("- Save filtered files to output directory")
        print("\nMake sure to set your OpenAI API key:")
        print("export OPENAI_API_KEY='your-api-key-here'")
        sys.exit(1)
    
    input_directory = sys.argv[1]
    output_directory = sys.argv[2] if len(sys.argv) > 2 else None
    
    try:
        print("Initializing Vulnerability Analyzer...")
        analyzer = VulnerabilityAnalyzer()
        
        print(f"Processing directory: {input_directory}")
        if output_directory:
            print(f"Output directory: {output_directory}")
        else:
            print(f"Output directory: {input_directory}/filtered")
        
        stats = analyzer.process_directory(input_directory, output_directory)
        
        output_path = Path(output_directory) if output_directory else Path(input_directory) / "filtered"
        analyzer.print_summary(stats, output_path)
        
        print(f"\n✓ Processing complete! Check the output directory for filtered files.")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()