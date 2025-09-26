#!/usr/bin/env python3
"""
Smart Contract Function Extractor - Enhanced Version

This script reads Solidity (.sol) and Vyper (.vy) smart contract files
and extracts all function definitions with comprehensive parsing.

Usage:
    python contract_parser.py <input_file_or_url> [output_file.json]
"""

import re
import json
import sys
import os
import requests
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional, Tuple


class SolidityTokenizer:
    """Advanced tokenizer for Solidity code"""
    
    def __init__(self, content: str):
        self.content = content
        self.tokens = []
        self.position = 0
        self.tokenize()
    
    def tokenize(self):
        i = 0
        while i < len(self.content):
            # Skip whitespace but preserve newlines for context
            if self.content[i] in ' \t\r':
                i += 1
                continue
            elif self.content[i] == '\n':
                self.tokens.append(('NEWLINE', '\n', i))
                i += 1
                continue
            
            # Handle single-line comments
            if i < len(self.content) - 1 and self.content[i:i+2] == '//':
                start = i
                while i < len(self.content) and self.content[i] != '\n':
                    i += 1
                self.tokens.append(('COMMENT', self.content[start:i], start))
                continue
            
            # Handle multi-line comments
            if i < len(self.content) - 1 and self.content[i:i+2] == '/*':
                start = i
                i += 2
                while i < len(self.content) - 1:
                    if self.content[i:i+2] == '*/':
                        i += 2
                        break
                    i += 1
                self.tokens.append(('COMMENT', self.content[start:i], start))
                continue
            
            # Handle strings
            if self.content[i] in ['"', "'"]:
                quote = self.content[i]
                start = i
                i += 1
                while i < len(self.content):
                    if self.content[i] == quote:
                        i += 1
                        break
                    elif self.content[i] == '\\' and i < len(self.content) - 1:
                        i += 2  # Skip escaped character
                    else:
                        i += 1
                self.tokens.append(('STRING', self.content[start:i], start))
                continue
            
            # Handle assembly blocks
            if i < len(self.content) - 8 and self.content[i:i+8] == 'assembly':
                # Look ahead to see if this is an assembly block
                j = i + 8
                while j < len(self.content) and self.content[j] in ' \t\n\r':
                    j += 1
                if j < len(self.content) and self.content[j] == '{':
                    # This is an assembly block, find the matching brace
                    brace_count = 0
                    start = i
                    while j < len(self.content):
                        if self.content[j] == '{':
                            brace_count += 1
                        elif self.content[j] == '}':
                            brace_count -= 1
                            if brace_count == 0:
                                j += 1
                                break
                        j += 1
                    self.tokens.append(('ASSEMBLY', self.content[start:j], start))
                    i = j
                    continue
            
            # Handle braces and other important characters
            if self.content[i] in '{}();,':
                self.tokens.append((self.content[i], self.content[i], i))
                i += 1
                continue
            
            # Handle other tokens (identifiers, keywords, operators, etc.)
            start = i
            while (i < len(self.content) and 
                   not self.content[i].isspace() and 
                   self.content[i] not in '{}();"\',' and
                   (i >= len(self.content) - 1 or self.content[i:i+2] not in ['//', '/*'])):
                i += 1
            if start < i:
                token_text = self.content[start:i]
                self.tokens.append(('TOKEN', token_text, start))
    
    def find_matching_brace(self, start_token_idx: int) -> Optional[int]:
        """Find the matching closing brace for an opening brace"""
        if start_token_idx >= len(self.tokens) or self.tokens[start_token_idx][0] != '{':
            return None
        
        brace_count = 0
        for i in range(start_token_idx, len(self.tokens)):
            token_type, token_value, pos = self.tokens[i]
            if token_type == '{':
                brace_count += 1
            elif token_type == '}':
                brace_count -= 1
                if brace_count == 0:
                    return i
            # Assembly blocks are treated as single tokens
            elif token_type == 'ASSEMBLY':
                continue
        return None


class ContractParser:
    def __init__(self):
        self.debug = False

    def set_debug(self, debug: bool):
        self.debug = debug

    def debug_print(self, msg: str):
        if self.debug:
            print(f"DEBUG: {msg}")

    def download_github_file(self, url: str) -> str:
        """Download file content from GitHub blob URL"""
        try:
            if 'github.com' in url and '/blob/' in url:
                raw_url = url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
            else:
                raw_url = url
            
            response = requests.get(raw_url, timeout=30)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            raise Exception(f"Failed to download file from {url}: {e}")

    def read_file_content(self, file_path: str) -> str:
        """Read content from local file or GitHub URL"""
        if file_path.startswith(('http://', 'https://')):
            return self.download_github_file(file_path)
        else:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            
            with open(file_path, 'r', encoding='utf-8') as file:
                return file.read()

    def get_file_type(self, file_path: str) -> str:
        """Determine if file is Solidity or Vyper based on extension"""
        if file_path.startswith(('http://', 'https://')):
            parsed_url = urlparse(file_path)
            path = parsed_url.path
            if path.endswith('.sol'):
                return 'solidity'
            elif path.endswith('.vy'):
                return 'vyper'
            else:
                raise ValueError("Unable to determine file type from URL. Supported: .sol, .vy")
        else:
            _, ext = os.path.splitext(file_path)
            if ext == '.sol':
                return 'solidity'
            elif ext == '.vy':
                return 'vyper'
            else:
                raise ValueError(f"Unsupported file type: {ext}. Supported: .sol, .vy")

    def extract_function_signature_and_body(self, content: str, func_start: int, func_end: int) -> Tuple[str, str, str]:
        """Extract function signature and body using tokenization"""
        tokenizer = SolidityTokenizer(content[func_start:])
        
        # Find the opening brace
        brace_idx = None
        for i, (token_type, token_value, pos) in enumerate(tokenizer.tokens):
            if token_type == '{':
                brace_idx = i
                break
        
        if brace_idx is None:
            return "", "", ""
        
        # Find matching closing brace
        closing_brace_idx = tokenizer.find_matching_brace(brace_idx)
        if closing_brace_idx is None:
            return "", "", ""
        
        # Extract signature (everything before the opening brace)
        sig_end = tokenizer.tokens[brace_idx][2]
        signature = content[func_start:func_start + sig_end].strip()
        
        # Extract body (everything between braces)
        body_start = tokenizer.tokens[brace_idx][2] + 1
        body_end = tokenizer.tokens[closing_brace_idx][2]
        body = content[func_start + body_start:func_start + body_end].strip()
        
        # Handle empty bodies - if body is empty or just whitespace, mark it as empty
        if not body:
            body = ""  # Explicitly empty function body
        
        return signature, body, content[func_start:func_start + tokenizer.tokens[closing_brace_idx][2] + 1]

    def parse_function_signature(self, signature: str) -> Dict[str, str]:
        """Parse function signature to extract name, parameters, and modifiers"""
        # Clean up the signature
        signature = re.sub(r'\s+', ' ', signature.strip())
        
        # Handle different function types
        if signature.startswith('function '):
            # Regular function
            match = re.match(r'function\s+(\w+)\s*\(([^)]*)\)\s*(.*)', signature)
            if match:
                name = match.group(1)
                params = match.group(2).strip()
                modifiers = match.group(3).strip()
                return {'name': name, 'params': params, 'modifiers': modifiers, 'type': 'function'}
        elif signature.startswith('constructor'):
            # Constructor
            match = re.match(r'constructor\s*\(([^)]*)\)\s*(.*)', signature)
            if match:
                params = match.group(1).strip()
                modifiers = match.group(2).strip()
                return {'name': 'constructor', 'params': params, 'modifiers': modifiers, 'type': 'constructor'}
        elif signature.startswith('modifier '):
            # Modifier
            match = re.match(r'modifier\s+(\w+)\s*\(([^)]*)\)\s*(.*)', signature)
            if match:
                name = match.group(1)
                params = match.group(2).strip()
                modifiers = match.group(3).strip()
                return {'name': name, 'params': params, 'modifiers': modifiers, 'type': 'modifier'}
        elif signature.startswith('receive'):
            # Receive function
            match = re.match(r'receive\s*\(\s*\)\s*(.*)', signature)
            if match:
                modifiers = match.group(1).strip()
                return {'name': 'receive', 'params': '', 'modifiers': modifiers, 'type': 'receive'}
        elif signature.startswith('fallback'):
            # Fallback function
            match = re.match(r'fallback\s*\(\s*\)\s*(.*)', signature)
            if match:
                modifiers = match.group(1).strip()
                return {'name': 'fallback', 'params': '', 'modifiers': modifiers, 'type': 'fallback'}
        
        return {'name': 'unknown', 'params': '', 'modifiers': '', 'type': 'unknown'}

    def find_all_function_positions(self, content: str) -> List[Tuple[int, int, str]]:
        """Find all function positions using multiple strategies"""
        positions = []
        
        # Strategy 1: Standard regex patterns (including empty body functions)
        patterns = [
            (r'(?:^|\n)(\s*function\s+\w+[^{]*?)\s*\{', 'function'),
            (r'(?:^|\n)(\s*constructor[^{]*?)\s*\{', 'constructor'),
            (r'(?:^|\n)(\s*modifier\s+\w+[^{]*?)\s*\{', 'modifier'),
            (r'(?:^|\n)(\s*receive\s*\([^)]*\)[^{]*?)\s*\{', 'receive'),
            (r'(?:^|\n)(\s*fallback\s*\([^)]*\)[^{]*?)\s*\{', 'fallback'),
        ]
        
        for pattern, func_type in patterns:
            for match in re.finditer(pattern, content, re.MULTILINE | re.DOTALL):
                start_pos = match.start()
                # Find the character position of the opening brace
                brace_pos = content.find('{', match.end() - 1)
                if brace_pos != -1:
                    positions.append((start_pos, brace_pos + 1, func_type))
        
        # Strategy 2: Specifically look for functions with empty bodies like "{}"
        empty_body_patterns = [
            (r'(?:^|\n)(\s*function\s+\w+[^{]*?)\s*\{\s*\}', 'function'),
            (r'(?:^|\n)(\s*constructor[^{]*?)\s*\{\s*\}', 'constructor'),
            (r'(?:^|\n)(\s*modifier\s+\w+[^{]*?)\s*\{\s*\}', 'modifier'),
        ]
        
        for pattern, func_type in empty_body_patterns:
            for match in re.finditer(pattern, content, re.MULTILINE | re.DOTALL):
                start_pos = match.start()
                # For empty body functions, the brace is right after the signature
                brace_pos = content.find('{', match.end() - 2)  # Look backwards a bit
                if brace_pos != -1:
                    # Check if this position is already found
                    already_found = any(abs(pos - start_pos) < 10 for pos, _, _ in positions)
                    if not already_found:
                        positions.append((start_pos, brace_pos + 1, func_type))
                        self.debug_print(f"Found empty body function: {func_type}")
        
        # Strategy 3: Line-by-line scan for missed functions
        lines = content.split('\n')
        current_pos = 0
        
        for i, line in enumerate(lines):
            line_stripped = line.strip()
            
            # Check for function declarations that might have been missed
            if (line_stripped.startswith('function ') or 
                line_stripped.startswith('constructor') or
                line_stripped.startswith('modifier ') or
                line_stripped.startswith('receive ') or
                line_stripped.startswith('fallback ')):
                
                # Check if this position is already captured
                already_found = any(abs(pos - current_pos) < 50 for pos, _, _ in positions)
                
                if not already_found:
                    # Look for the opening brace
                    search_start = current_pos
                    search_end = min(len(content), current_pos + 500)  # Look within 500 chars
                    brace_pos = content.find('{', search_start, search_end)
                    
                    if brace_pos != -1:
                        if line_stripped.startswith('function '):
                            func_type = 'function'
                        elif line_stripped.startswith('constructor'):
                            func_type = 'constructor'
                        elif line_stripped.startswith('modifier '):
                            func_type = 'modifier'
                        elif line_stripped.startswith('receive '):
                            func_type = 'receive'
                        else:
                            func_type = 'fallback'
                        
                        positions.append((current_pos, brace_pos + 1, func_type))
                        self.debug_print(f"Found missed function at line {i+1}: {line_stripped[:50]}...")
            
            current_pos += len(line) + 1  # +1 for newline
        
        # Remove duplicates and sort
        unique_positions = []
        for pos in positions:
            if not any(abs(pos[0] - existing[0]) < 20 for existing in unique_positions):
                unique_positions.append(pos)
        
        unique_positions.sort(key=lambda x: x[0])
        return unique_positions

    def is_inside_assembly_block(self, content: str, position: int) -> bool:
        """Check if a position is inside an assembly block"""
        # Look backwards for 'assembly' keyword
        search_start = max(0, position - 1000)  # Search back up to 1000 chars
        preceding_text = content[search_start:position]
        
        # Find all assembly blocks in the preceding text
        assembly_matches = list(re.finditer(r'assembly\s*\{', preceding_text))
        
        for match in assembly_matches:
            assembly_start = search_start + match.end() - 1  # Position of opening brace
            
            # Find the matching closing brace
            brace_count = 0
            i = assembly_start
            while i < len(content):
                if content[i] == '{':
                    brace_count += 1
                elif content[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        assembly_end = i
                        break
                i += 1
            else:
                continue  # No matching brace found
            
            # Check if our position is within this assembly block
            if assembly_start <= position <= assembly_end:
                return True
        
        return False

    def find_solidity_functions(self, content: str) -> List[Dict[str, Any]]:
        """Find all function definitions in Solidity code"""
        functions = []
        
        # Find all potential function positions
        positions = self.find_all_function_positions(content)
        self.debug_print(f"Found {len(positions)} potential function positions")
        
        for start_pos, brace_pos, func_type in positions:
            try:
                # Check if this is inside an assembly block
                if self.is_inside_assembly_block(content, start_pos):
                    self.debug_print(f"Skipping function at {start_pos} - inside assembly block")
                    continue
                
                # Extract the full function including body
                signature, body, full_func = self.extract_function_signature_and_body(
                    content, start_pos, brace_pos
                )
                
                # Allow empty bodies - signature is required, body can be empty
                if not signature:
                    self.debug_print(f"Failed to extract signature at {start_pos}")
                    continue
                
                # Parse the signature
                sig_info = self.parse_function_signature(signature)
                
                if sig_info['name'] == 'unknown':
                    self.debug_print(f"Unknown function type at {start_pos}: {signature[:50]}...")
                    continue
                
                self.debug_print(f"Successfully parsed function: {sig_info['name']} ({sig_info['type']})")
                
                functions.append({
                    'name': sig_info['name'],
                    'type': sig_info['type'],
                    'signature': signature,
                    'parameters': sig_info['params'],
                    'modifiers': sig_info['modifiers'],
                    'body': body,
                    'start_pos': start_pos
                })
                
            except Exception as e:
                self.debug_print(f"Error parsing function at {start_pos}: {e}")
                continue
        
        # Sort by position and remove duplicates
        functions.sort(key=lambda x: x['start_pos'])
        
        # Remove exact duplicates (same name and position)
        unique_functions = []
        seen = set()
        
        for func in functions:
            key = (func['name'], func['type'], func['start_pos'])
            if key not in seen:
                unique_functions.append(func)
                seen.add(key)
        
        # Remove start_pos from final output
        for func in unique_functions:
            del func['start_pos']
        
        return unique_functions

    def parse_vyper(self, content: str) -> List[Dict[str, Any]]:
        """Parse Vyper contract and extract functions"""
        functions = []
        lines = content.split('\n')
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            if line.startswith('def '):
                if line.startswith('def __init__'):
                    init_match = re.match(r'def\s+__init__\s*\(([^)]*)\)\s*:', line)
                    if init_match:
                        name = '__init__'
                        params = init_match.group(1).strip()
                        func_type = 'constructor'
                        modifiers = ""
                        return_type = ""
                else:
                    func_match = re.match(r'def\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*([^:]+))?\s*:', line)
                    if func_match:
                        name = func_match.group(1)
                        params = func_match.group(2).strip()
                        return_type = func_match.group(3).strip() if func_match.group(3) else ""
                        func_type = 'function'
                        
                        # Look for decorators
                        decorators = []
                        j = i - 1
                        while j >= 0 and lines[j].strip().startswith('@'):
                            decorators.insert(0, lines[j].strip())
                            j -= 1
                        
                        modifiers = ' '.join(decorators)
                
                # Create signature
                signature = f"def {name}({params})"
                if return_type:
                    signature += f" -> {return_type}"
                if modifiers:
                    signature = f"{modifiers}\n{signature}"
                
                # Extract function body
                body_start = i + 1
                body_lines = []
                base_indent = len(lines[i]) - len(lines[i].lstrip())
                
                for j in range(body_start, len(lines)):
                    if lines[j].strip() == "":
                        body_lines.append(lines[j])
                        continue
                    
                    current_indent = len(lines[j]) - len(lines[j].lstrip())
                    if lines[j].strip() and current_indent <= base_indent:
                        break
                    
                    body_lines.append(lines[j])
                
                body = '\n'.join(body_lines).strip()
                
                functions.append({
                    'name': name,
                    'type': func_type,
                    'signature': signature,
                    'parameters': params,
                    'modifiers': modifiers,
                    'return_type': return_type,
                    'body': body
                })
            
            i += 1
        
        return functions

    def parse_contract(self, file_path: str, debug: bool = False) -> Dict[str, Any]:
        """Main parsing function"""
        self.set_debug(debug)
        
        try:
            content = self.read_file_content(file_path)
            file_type = self.get_file_type(file_path)
            
            if file_type == 'solidity':
                functions = self.find_solidity_functions(content)
            elif file_type == 'vyper':
                functions = self.parse_vyper(content)
            else:
                raise ValueError(f"Unsupported file type: {file_type}")
            
            return {
                'file_path': file_path,
                'file_type': file_type,
                'functions_count': len(functions),
                'functions': functions
            }
        
        except Exception as e:
            return {
                'file_path': file_path,
                'error': str(e),
                'functions_count': 0,
                'functions': []
            }


def main():
    if len(sys.argv) < 2:
        print("Usage: python contract_parser.py <input_file_or_url> [output_file.json] [--debug]")
        print("\nExamples:")
        print("  python contract_parser.py contract.sol")
        print("  python contract_parser.py https://github.com/user/repo/blob/main/contract.sol")
        print("  python contract_parser.py contract.vy output.json")
        print("  python contract_parser.py contract.sol output.json --debug")
        sys.exit(1)
    
    input_path = sys.argv[1]
    output_path = "contract_functions.json"
    debug = False
    
    # Parse arguments
    for i, arg in enumerate(sys.argv[2:], 2):
        if arg == '--debug':
            debug = True
        elif not arg.startswith('--'):
            output_path = arg
    
    parser = ContractParser()
    
    print(f"Parsing contract: {input_path}")
    if debug:
        print("Debug mode enabled")
    
    result = parser.parse_contract(input_path, debug=debug)
    
    if 'error' in result:
        print(f"Error: {result['error']}")
        sys.exit(1)
    
    print(f"Found {result['functions_count']} functions")
    
    # Save to JSON file
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    
    print(f"Results saved to: {output_path}")
    
    # Print summary
    print(f"\nSummary:")
    print(f"File type: {result['file_type']}")
    print(f"Functions found: {result['functions_count']}")
    
    if result['functions']:
        print(f"\nFunction names:")
        for func in result['functions']:
            print(f"  - {func['name']} ({func['type']})")


if __name__ == "__main__":
    main()