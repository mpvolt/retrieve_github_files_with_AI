#!/usr/bin/env python3
"""
Extracts function names from smart contract files with supported extensions.

This script processes files with extensions .sol, .vy, .rs, .move, .cairo, .fc, .func
and returns a list of function names found in each file. It uses regular expressions
tailored to each language's function syntax.

Usage:
    from extract_function_names import extract_function_names
    
    function_names = extract_function_names("path/to/contract.sol")
    print(function_names)
"""

import re
from pathlib import Path
from typing import List, Optional

# Supported smart contract file extensions
SMART_CONTRACT_EXTENSIONS = ('.sol', '.vy', '.rs', '.move', '.cairo', '.fc', '.func')

def extract_function_names(file_path: str) -> List[str]:
    """
    Extract function names from a smart contract file based on its extension.
    
    Args:
        file_path (str): Path to the smart contract file
        
    Returns:
        List[str]: List of function names found in the file
        
    Example:
        function_names = extract_function_names("contract.sol")
        print(function_names)  # ['transfer', 'balanceOf', 'approve']
    """
    file_path = Path(file_path)
    if not file_path.is_file():
        print(f"Error: {file_path} is not a valid file")
        return []
    
    if not file_path.suffix.lower() in SMART_CONTRACT_EXTENSIONS:
        print(f"Error: {file_path} has unsupported extension. Supported: {SMART_CONTRACT_EXTENSIONS}")
        return []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return []
    
    function_names = []
    extension = file_path.suffix.lower()
    
    if extension == '.sol':  # Solidity
        # Matches: function name(...), function name (...), or function name()
        pattern = r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*(?:public|private|internal|external)?'
        matches = re.findall(pattern, content)
        function_names.extend(matches)
    
    elif extension == '.vy':  # Vyper
        # Matches: @external def name(...): or def name(...):
        pattern = r'(?:@external\s+)?def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*:'
        matches = re.findall(pattern, content)
        function_names.extend(matches)
    
    elif extension == '.rs':  # Rust (used in Solana smart contracts)
        # Matches: fn name(...) or pub fn name(...)
        pattern = r'(?:pub\s+)?fn\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)'
        matches = re.findall(pattern, content)
        function_names.extend(matches)
    
    elif extension == '.move':  # Move (used in Aptos/Sui)
        # Matches: fun name(...) or public fun name(...)
        pattern = r'(?:public\s+)?fun\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)'
        matches = re.findall(pattern, content)
        function_names.extend(matches)
    
    elif extension == '.cairo':  # Cairo (used in StarkNet)
        # Matches: func name{...}(...): or func name(...)
        pattern = r'func\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\{[^}]*\})?\s*\([^)]*\)\s*:'
        matches = re.findall(pattern, content)
        function_names.extend(matches)
    
    elif extension in ('.fc', '.func'):  # FunC (used in TON blockchain)
        # Matches: () name(...) or name(...)
        pattern = r'(?:\([^\)]*\)\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)'
        matches = re.findall(pattern, content)
        function_names.extend(matches)
    
    # Remove duplicates while preserving order
    seen = set()
    function_names = [name for name in function_names if not (name in seen or seen.add(name))]
    
    return function_names


if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python extract_function_names.py <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    functions = extract_function_names(file_path)
    
    if functions:
        print(f"Function names found in {file_path}:")
        for func in functions:
            print(f"- {func}")
    else:
        print(f"No functions found in {file_path}")