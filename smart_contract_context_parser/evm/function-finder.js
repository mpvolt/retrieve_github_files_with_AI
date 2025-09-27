/**
 * Function Finder
 * Utilities for finding and matching functions
 */
class FunctionFinder {
  constructor(options = {}) {
    this.debug = options.debug || false;
  }

  // Find function by name (handles overloads)
  findFunction(functions, targetName) {
    if (this.debug) {
      console.log(`\n=== DEBUG: Searching for function "${targetName}" ===`);
      console.log(`Available functions: ${functions.filter(f => f.type !== 'event').length}`);
    }

    // First try exact name match
    let matches = functions.filter(f => f.name === targetName && f.type !== 'event');
    
    if (matches.length === 1) {
      if (this.debug) {
        console.log(`Found exact match: ${matches[0].signature}`);
      }
      return matches[0];
    }
    
    if (matches.length > 1) {
      console.log(`Multiple functions found with name "${targetName}":`);
      matches.forEach((f, i) => {
        console.log(`  ${i + 1}. ${f.signature}`);
      });
      return matches[0]; // Return first match
    }
    
    // Try partial match on signature
    matches = functions.filter(f => 
      f.signature && f.signature.includes(targetName) && f.type !== 'event'
    );
    
    if (matches.length > 0) {
      console.log(`Found function by signature match: ${matches[0].signature}`);
      return matches[0];
    }
    
    if (this.debug) {
      console.log(`No matches found for "${targetName}"`);
      console.log(`Available function names: ${this.listAvailableFunctions(functions)}`);
    }
    
    return null;
  }

  // List available functions for error messages
  listAvailableFunctions(functions) {
    return functions
      .filter(f => f.type !== 'event')
      .map(f => f.name)
      .filter(name => name && name !== '<constructor>')
      .join(', ');
  }

  // Extract all functions referenced in call tree
  extractFunctionsFromTree(allFunctions, callTree, options) {
    const extracted = new Map();
    
    const traverse = (node) => {
      if (node.external && !node.definition) return;
      
      // Find the actual function object
      const func = allFunctions.find(f => f.name === node.name || 
        (node.methodName && f.name === node.methodName));
      
      if (func && func.type !== 'event') {
        extracted.set(func.name, func);
      }
      
      // If it's an interface call with definition, include that too
      if (node.definition) {
        extracted.set(node.definition.name, node.definition);
      }
      
      // Process called functions
      if (node.calls) {
        node.calls.forEach(traverse);
      }
    };

    traverse(callTree);

    // Add modifiers if requested
    if (options.includeModifiers) {
      for (const func of extracted.values()) {
        if (func.modifiers) {
          func.modifiers.forEach(modifierName => {
            const modifier = allFunctions.find(f => f.name === modifierName);
            if (modifier) {
              extracted.set(`modifier_${modifierName}`, modifier);
            }
          });
        }
      }
    }

    return extracted;
  }

  // Group functions by file
  groupByFile(functions) {
    const grouped = {};
    functions.forEach(func => {
      const file = func.file || 'unknown';
      if (!grouped[file]) {
        grouped[file] = [];
      }
      grouped[file].push(func.name);
    });
    return grouped;
  }
}

module.exports = FunctionFinder;