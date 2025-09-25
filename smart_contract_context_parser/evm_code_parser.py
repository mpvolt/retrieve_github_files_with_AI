#!/usr/bin/env python3
"""
Smart Contract Parser for Solidity and Vyper

This script parses Solidity (.sol) and Vyper (.vy) smart contract source code
and extracts imports, state variables, functions, and modifiers into a JSON format.
"""

import re
import json
import argparse
import os
import urllib.request
import urllib.parse
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class FunctionInfo:
    name: str
    signature: str
    visibility: str
    mutability: str
    modifiers: List[str]
    parameters: List[Dict[str, str]]
    return_types: List[Dict[str, str]]
    code: str


@dataclass
class ModifierInfo:
    name: str
    signature: str
    parameters: List[Dict[str, str]]
    code: str


@dataclass
class StateVariableInfo:
    name: str
    type: str
    visibility: str
    mutability: str
    initial_value: Optional[str] = None


@dataclass
class ImportInfo:
    path: str
    alias: Optional[str] = None
    specific_imports: List[str] = None


class SolidityParser:
    def __init__(self, source_code: str):
        self.source_code = source_code
        self.lines = source_code.split('\n')
    
    def parse(self) -> Dict[str, Any]:
        return {
            "language": "solidity",
            "imports": self._parse_imports(),
            "state_variables": self._parse_state_variables(),
            "functions": self._parse_functions(),
            "modifiers": self._parse_modifiers()
        }
    
    def _parse_imports(self) -> List[Dict[str, Any]]:
        imports = []
        import_pattern = r'import\s+(?:"([^"]+)"|\'([^\']+)\'|\{([^}]+)\}\s+from\s+(?:"([^"]+)"|\'([^\']+)\')|\*\s+as\s+(\w+)\s+from\s+(?:"([^"]+)"|\'([^\']+)\')|([^;]+))\s*;'
        
        for match in re.finditer(import_pattern, self.source_code):
            groups = match.groups()
            
            if groups[0] or groups[1]:  # Simple import
                path = groups[0] or groups[1]
                imports.append(asdict(ImportInfo(path=path)))
            elif groups[2] and (groups[3] or groups[4]):  # Named imports
                specific = [item.strip() for item in groups[2].split(',')]
                path = groups[3] or groups[4]
                imports.append(asdict(ImportInfo(path=path, specific_imports=specific)))
            elif groups[5] and (groups[6] or groups[7]):  # Import as alias
                alias = groups[5]
                path = groups[6] or groups[7]
                imports.append(asdict(ImportInfo(path=path, alias=alias)))
        
        return imports
    
    def _parse_state_variables(self) -> List[Dict[str, Any]]:
        variables = []
        # Match state variables (not in functions or modifiers)
        contract_body = self._extract_contract_body()
        
        # Pattern to match state variable declarations
        var_pattern = r'(?:^|\n)\s*((?:public|private|internal|constant|immutable)\s+)*([a-zA-Z_$][\w$]*(?:\[\d*\])*)\s+(?:(public|private|internal)\s+)?(constant|immutable\s+)?([a-zA-Z_$][\w$]*)\s*(?:=\s*([^;]+))?\s*;'
        
        for match in re.finditer(var_pattern, contract_body, re.MULTILINE):
            modifiers = (match.group(1) or '').strip().split()
            type_name = match.group(2).strip()
            visibility = match.group(3) or 'internal'
            mutability = match.group(4) or 'mutable'
            var_name = match.group(5)
            initial_value = match.group(6)
            
            if mutability:
                mutability = mutability.strip()
            
            variables.append(asdict(StateVariableInfo(
                name=var_name,
                type=type_name,
                visibility=visibility,
                mutability=mutability,
                initial_value=initial_value.strip() if initial_value else None
            )))
        
        return variables
    
    def _parse_functions(self) -> List[Dict[str, Any]]:
        functions = []
        
        # Enhanced function pattern to capture complete function definitions
        function_pattern = r'function\s+([a-zA-Z_$][\w$]*)\s*\(([^)]*)\)\s*((?:public|private|internal|external)?)?\s*((?:pure|view|payable|nonpayable)?)?\s*((?:override\s*(?:\([^)]*\))?\s*)*)((?:\w+(?:\([^)]*\))?\s*)*)\s*(?:returns\s*\(([^)]*)\))?\s*\{'
        
        for match in re.finditer(function_pattern, self.source_code, re.DOTALL):
            func_name = match.group(1)
            params_str = match.group(2)
            visibility = match.group(3) or 'internal'
            mutability = match.group(4) or 'nonpayable'
            override_info = match.group(5) or ''
            modifiers_str = match.group(6) or ''
            returns_str = match.group(7) or ''
            
            # Extract function body
            start_pos = match.end() - 1
            func_body = self._extract_function_body(start_pos)
            
            # Parse parameters
            parameters = self._parse_parameters(params_str)
            
            # Parse return types
            return_types = self._parse_parameters(returns_str)
            
            # Parse modifiers
            modifiers = [m.strip() for m in modifiers_str.split() if m.strip() and m.strip() != 'override']
            
            # Create signature
            signature = f"function {func_name}({params_str})"
            if visibility and visibility != 'internal':
                signature += f" {visibility}"
            if mutability and mutability != 'nonpayable':
                signature += f" {mutability}"
            if modifiers:
                signature += f" {' '.join(modifiers)}"
            if returns_str:
                signature += f" returns ({returns_str})"
            
            functions.append(asdict(FunctionInfo(
                name=func_name,
                signature=signature,
                visibility=visibility,
                mutability=mutability,
                modifiers=modifiers,
                parameters=parameters,
                return_types=return_types,
                code=func_body
            )))
        
        return functions
    
    def _parse_modifiers(self) -> List[Dict[str, Any]]:
        modifiers = []
        
        modifier_pattern = r'modifier\s+([a-zA-Z_$][\w$]*)\s*\(([^)]*)\)\s*\{'
        
        for match in re.finditer(modifier_pattern, self.source_code):
            mod_name = match.group(1)
            params_str = match.group(2)
            
            # Extract modifier body
            start_pos = match.end() - 1
            mod_body = self._extract_function_body(start_pos)
            
            # Parse parameters
            parameters = self._parse_parameters(params_str)
            
            signature = f"modifier {mod_name}({params_str})"
            
            modifiers.append(asdict(ModifierInfo(
                name=mod_name,
                signature=signature,
                parameters=parameters,
                code=mod_body
            )))
        
        return modifiers
    
    def _extract_contract_body(self) -> str:
        # Find contract declaration and extract its body
        contract_pattern = r'contract\s+\w+[^{]*\{(.*)\}(?:\s*$|\s*//|\s*/\*)'
        match = re.search(contract_pattern, self.source_code, re.DOTALL)
        if match:
            return match.group(1)
        return self.source_code
    
    def _extract_function_body(self, start_pos: int) -> str:
        """Extract function/modifier body by matching braces"""
        brace_count = 0
        i = start_pos
        start = start_pos
        
        while i < len(self.source_code):
            if self.source_code[i] == '{':
                brace_count += 1
            elif self.source_code[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    return self.source_code[start:i+1]
            i += 1
        
        return self.source_code[start:]
    
    def _parse_parameters(self, params_str: str) -> List[Dict[str, str]]:
        """Parse function parameters string into list of type-name pairs"""
        if not params_str.strip():
            return []
        
        params = []
        for param in params_str.split(','):
            param = param.strip()
            if param:
                parts = param.split()
                if len(parts) >= 2:
                    param_type = ' '.join(parts[:-1])
                    param_name = parts[-1]
                    params.append({"type": param_type, "name": param_name})
                elif len(parts) == 1:
                    params.append({"type": parts[0], "name": ""})
        
        return params


class VyperParser:
    def __init__(self, source_code: str):
        self.source_code = source_code
        self.lines = source_code.split('\n')
    
    def parse(self) -> Dict[str, Any]:
        return {
            "language": "vyper",
            "imports": self._parse_imports(),
            "state_variables": self._parse_state_variables(),
            "functions": self._parse_functions(),
            "modifiers": []  # Vyper doesn't have traditional modifiers
        }
    
    def _parse_imports(self) -> List[Dict[str, Any]]:
        imports = []
        
        for line in self.lines:
            line = line.strip()
            
            # from ... import ... pattern
            from_import_match = re.match(r'from\s+([^\s]+)\s+import\s+(.+)', line)
            if from_import_match:
                path = from_import_match.group(1)
                imports_str = from_import_match.group(2)
                specific_imports = [item.strip() for item in imports_str.split(',')]
                imports.append(asdict(ImportInfo(path=path, specific_imports=specific_imports)))
                continue
            
            # import ... pattern
            import_match = re.match(r'import\s+([^\s]+)(?:\s+as\s+(\w+))?', line)
            if import_match:
                path = import_match.group(1)
                alias = import_match.group(2)
                imports.append(asdict(ImportInfo(path=path, alias=alias)))
        
        return imports
    
    def _parse_state_variables(self) -> List[Dict[str, Any]]:
        variables = []
        
        # Vyper state variables are typically declared at module level
        for line in self.lines:
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Skip function definitions, decorators, etc.
            if line.startswith(('@', 'def ', 'class ', 'if ', 'for ', 'while ', 'import', 'from')):
                continue
            
            # Match variable declarations (type: name = value or name: type = value)
            var_match = re.match(r'(\w+)\s*:\s*([\w\[\](),\s]+)(?:\s*=\s*(.+))?$', line)
            if var_match:
                var_name = var_match.group(1)
                var_type = var_match.group(2).strip()
                initial_value = var_match.group(3)
                
                # Determine visibility (Vyper variables are internal by default, public if explicitly marked)
                visibility = 'public' if 'public' in var_type else 'internal'
                var_type = var_type.replace('public(', '').replace(')', '') if 'public' in var_type else var_type
                
                variables.append(asdict(StateVariableInfo(
                    name=var_name,
                    type=var_type,
                    visibility=visibility,
                    mutability='mutable',
                    initial_value=initial_value.strip() if initial_value else None
                )))
        
        return variables
    
    def _parse_functions(self) -> List[Dict[str, Any]]:
        functions = []
        
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()
            
            # Look for function definitions
            func_match = re.match(r'def\s+(\w+)\s*\(([^)]*)\)(?:\s*->\s*([\w\[\],\s]+))?\s*:', line)
            if func_match:
                func_name = func_match.group(1)
                params_str = func_match.group(2)
                return_type_str = func_match.group(3) or ''
                
                # Look for decorators above the function
                decorators = []
                j = i - 1
                while j >= 0 and self.lines[j].strip().startswith('@'):
                    decorators.insert(0, self.lines[j].strip())
                    j -= 1
                
                # Extract function body
                func_body, next_i = self._extract_function_body(i)
                
                # Parse parameters
                parameters = self._parse_vyper_parameters(params_str)
                
                # Parse return types
                return_types = []
                if return_type_str:
                    return_types = [{"type": return_type_str.strip(), "name": ""}]
                
                # Determine visibility and mutability from decorators
                visibility = 'internal'
                mutability = 'nonpayable'
                
                for decorator in decorators:
                    if '@external' in decorator:
                        visibility = 'external'
                    elif '@internal' in decorator:
                        visibility = 'internal'
                    elif '@view' in decorator:
                        mutability = 'view'
                    elif '@pure' in decorator:
                        mutability = 'pure'
                    elif '@payable' in decorator:
                        mutability = 'payable'
                
                # Create signature
                signature = f"def {func_name}({params_str})"
                if return_type_str:
                    signature += f" -> {return_type_str}"
                
                functions.append(asdict(FunctionInfo(
                    name=func_name,
                    signature=signature,
                    visibility=visibility,
                    mutability=mutability,
                    modifiers=decorators,
                    parameters=parameters,
                    return_types=return_types,
                    code=func_body
                )))
                
                i = next_i
            else:
                i += 1
        
        return functions
    
    def _extract_function_body(self, start_line: int) -> tuple:
        """Extract Vyper function body based on indentation"""
        lines = []
        i = start_line
        
        # Add the function definition line
        lines.append(self.lines[i])
        i += 1
        
        if i >= len(self.lines):
            return '\n'.join(lines), i
        
        # Get the base indentation level
        base_indent = len(self.lines[start_line]) - len(self.lines[start_line].lstrip())
        
        # Collect all lines that are part of this function
        while i < len(self.lines):
            line = self.lines[i]
            
            # Empty lines or comments are included
            if not line.strip() or line.strip().startswith('#'):
                lines.append(line)
                i += 1
                continue
            
            # Calculate indentation
            line_indent = len(line) - len(line.lstrip())
            
            # If indentation is greater than base, it's part of the function
            if line_indent > base_indent:
                lines.append(line)
                i += 1
            else:
                # We've reached the end of the function
                break
        
        return '\n'.join(lines), i
    
    def _parse_vyper_parameters(self, params_str: str) -> List[Dict[str, str]]:
        """Parse Vyper function parameters"""
        if not params_str.strip():
            return []
        
        params = []
        for param in params_str.split(','):
            param = param.strip()
            if param:
                # Vyper parameters are in format: name: type
                if ':' in param:
                    name, param_type = param.split(':', 1)
                    params.append({"type": param_type.strip(), "name": name.strip()})
                else:
                    params.append({"type": "unknown", "name": param})
        
        return params


def fetch_github_raw_content(url: str) -> str:
    """
    Fetch raw content from a GitHub blob URL
    
    Args:
        url: GitHub blob URL (e.g., https://github.com/user/repo/blob/main/contract.sol)
    
    Returns:
        Raw file content as string
    """
    # Convert GitHub blob URL to raw content URL
    if 'github.com' in url and '/blob/' in url:
        # Replace github.com with raw.githubusercontent.com and remove /blob/
        raw_url = url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
    elif 'raw.githubusercontent.com' in url:
        # Already a raw URL
        raw_url = url
    else:
        raise ValueError("URL must be a GitHub blob URL (e.g., https://github.com/user/repo/blob/main/file.sol)")
    
    try:
        # Add User-Agent header to avoid GitHub blocking
        req = urllib.request.Request(raw_url, headers={
            'User-Agent': 'Smart-Contract-Parser/1.0 (https://github.com/smart-contract-parser)'
        })
        
        with urllib.request.urlopen(req) as response:
            if response.status == 200:
                content = response.read().decode('utf-8')
                return content
            else:
                raise ValueError(f"Failed to fetch file: HTTP {response.status}")
                
    except urllib.error.HTTPError as e:
        raise ValueError(f"HTTP error fetching file: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        raise ValueError(f"URL error fetching file: {e.reason}")
    except Exception as e:
        raise ValueError(f"Error fetching file: {str(e)}")


def is_github_url(input_str: str) -> bool:
    """Check if the input string is a GitHub URL"""
    return (input_str.startswith('http://') or input_str.startswith('https://')) and 'github' in input_str.lower()


def extract_filename_from_github_url(url: str) -> str:
    """Extract filename from GitHub URL"""
    # Parse the URL to get the path
    parsed = urllib.parse.urlparse(url)
    path_parts = parsed.path.split('/')
    
    # GitHub blob URLs have format: /user/repo/blob/branch/path/to/file
    # We want the last part (filename)
    if len(path_parts) > 0:
        filename = path_parts[-1]
        # If no extension, try to detect from URL structure
        if '.' not in filename:
            # Look for .sol or .vy in the path
            for part in reversed(path_parts):
                if part.endswith(('.sol', '.vy')):
                    filename = part
                    break
        return filename
    
    return 'contract.sol'  # Default fallback


def determine_language_from_content(content: str, filename: str = '') -> str:
    """
    Determine contract language from content and filename
    
    Args:
        content: Source code content
        filename: Optional filename for extension checking
    
    Returns:
        'solidity' or 'vyper'
    """
    # First try filename extension
    if filename:
        ext = os.path.splitext(filename)[1].lower()
        if ext == '.sol':
            return 'solidity'
        elif ext == '.vy':
            return 'vyper'
    
    # Analyze content for language indicators
    content_lower = content.lower()
    
    # Solidity indicators
    solidity_indicators = [
        'pragma solidity',
        'contract ',
        'function ',
        'modifier ',
        'event ',
        'struct ',
        'enum ',
        'mapping(',
        'uint256',
        'address',
        'msg.sender'
    ]
    
    # Vyper indicators  
    vyper_indicators = [
        '@external',
        '@internal', 
        '@view',
        '@pure',
        '@payable',
        'def ',
        ': uint256',
        ': address',
        ': bool',
        'self.',
        'msg.sender'  # Also in Vyper but syntax is different
    ]
    
    solidity_score = sum(1 for indicator in solidity_indicators if indicator in content_lower)
    vyper_score = sum(1 for indicator in vyper_indicators if indicator in content_lower)
    
    # Additional specific checks
    if 'pragma solidity' in content_lower:
        solidity_score += 5
    if '@version' in content_lower or 'def __init__' in content_lower:
        vyper_score += 5
    
    return 'solidity' if solidity_score >= vyper_score else 'vyper'


def parse_smart_contract(input_source: str, output_path: str = None) -> Dict[str, Any]:
    """
    Parse a smart contract from file path or GitHub URL
    
    Args:
        input_source: File path or GitHub blob URL to the smart contract
        output_path: Optional path to save the JSON output
    
    Returns:
        Dict containing the parsed contract structure
    """
    
    # Determine if input is a URL or file path
    if is_github_url(input_source):
        # Fetch from GitHub
        print(f"Fetching contract from GitHub: {input_source}")
        source_code = fetch_github_raw_content(input_source)
        filename = extract_filename_from_github_url(input_source)
        source_identifier = input_source
        
        # Determine language from content and filename
        language = determine_language_from_content(source_code, filename)
        print(f"Detected language: {language}")
        
    else:
        # Read from local file
        if not os.path.exists(input_source):
            raise FileNotFoundError(f"File not found: {input_source}")
            
        with open(input_source, 'r', encoding='utf-8') as f:
            source_code = f.read()
        
        filename = os.path.basename(input_source)
        source_identifier = input_source
        
        # Determine language based on file extension
        file_ext = os.path.splitext(input_source)[1].lower()
        
        if file_ext == '.sol':
            language = 'solidity'
        elif file_ext == '.vy':
            language = 'vyper'
        else:
            # Try to detect from content
            language = determine_language_from_content(source_code, filename)
            print(f"Unknown extension {file_ext}, detected language: {language}")
    
    # Create appropriate parser
    if language == 'solidity':
        parser = SolidityParser(source_code)
    elif language == 'vyper':
        parser = VyperParser(source_code)
    else:
        raise ValueError(f"Unsupported language: {language}")
    
    # Parse the contract
    result = parser.parse()
    result['source_file'] = source_identifier
    result['filename'] = filename
    
    # Save to output file if specified
    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"Parsed contract saved to: {output_path}")
    
    return result


def main():
    parser = argparse.ArgumentParser(
        description='Parse Solidity and Vyper smart contracts from local files or GitHub URLs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Parse local file
  python contract_parser.py contract.sol
  
  # Parse from GitHub blob URL
  python contract_parser.py https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/ERC20.sol
  
  # Save output and pretty print
  python contract_parser.py https://github.com/user/repo/blob/main/Contract.sol -o output.json --pretty
        '''
    )
    parser.add_argument('input_source', 
                       help='Path to smart contract file (.sol or .vy) OR GitHub blob URL')
    parser.add_argument('-o', '--output', 
                       help='Output JSON file path (optional)')
    parser.add_argument('--pretty', action='store_true', 
                       help='Pretty print JSON to console')
    
    args = parser.parse_args()
    
    try:
        # Parse the contract
        result = parse_smart_contract(args.input_source, args.output)
        
        # Determine if we should show JSON output
        show_json = args.pretty or is_github_url(args.input_source)
        
        # Pretty print JSON if requested or if it's a GitHub URL
        if show_json:
            print("\n" + "="*50)
            print("PARSED CONTRACT STRUCTURE")
            print("="*50)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        
        # Print summary
        print(f"\nSuccessfully parsed {result['language']} contract: {result['filename']}")
        print(f"Source: {result['source_file']}")
        print(f"Found:")
        print(f"  • {len(result['imports'])} imports")
        print(f"  • {len(result['state_variables'])} state variables") 
        print(f"  • {len(result['functions'])} functions")
        print(f"  • {len(result['modifiers'])} modifiers")
        
        # Show function names for local files or if not showing JSON
        if result['functions'] and not show_json:
            print(f"\nFunctions:")
            for func in result['functions']:
                print(f"  • {func['name']} ({func['visibility']}, {func['mutability']})")
        
        if not args.output and is_github_url(args.input_source):
            print(f"\nTip: Use -o filename.json to save the parsed output to a file")
        elif not args.output and not is_github_url(args.input_source):
            print(f"\nTip: Use -o filename.json to save the parsed output to a file, or --pretty to see JSON structure")
        
    except Exception as e:
        print(f"Error parsing contract: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())