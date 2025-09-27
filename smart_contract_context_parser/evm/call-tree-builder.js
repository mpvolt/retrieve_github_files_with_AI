const InterfaceDetector = require('./interface-detector.js');

/**
 * Call Tree Builder
 * Builds function call trees with interface detection
 */
class CallTreeBuilder {
  constructor(options = {}) {
    this.debug = options.debug || false;
    this.interfaceDetector = new InterfaceDetector({ debug: this.debug });
  }

  // Build call tree recursively
  buildCallTree(allFunctions, currentFunction, maxDepth, currentDepth = 0, visited = new Set(), baseRepoInfo = null) {
    if (currentDepth >= maxDepth || visited.has(currentFunction.name)) {
      return { name: currentFunction.name, calls: [], depth: currentDepth };
    }

    visited.add(currentFunction.name);
    
    const tree = {
      name: currentFunction.name,
      signature: currentFunction.signature,
      file: currentFunction.file,
      calls: [],
      depth: currentDepth
    };

    // Find called functions from AST analysis
    if (currentFunction.resolvedCalls) {
      for (const call of currentFunction.resolvedCalls) {
        if (!call.isExternal && call.definition) {
          const calledFunction = call.definition;
          const subTree = this.buildCallTree(
            allFunctions, 
            calledFunction, 
            maxDepth, 
            currentDepth + 1, 
            new Set(visited),
            baseRepoInfo
          );
          tree.calls.push(subTree);
        } else {
          // External call - just record the name
          tree.calls.push({
            name: call.name,
            external: true,
            arguments: call.arguments,
            depth: currentDepth + 1
          });
        }
      }
    }

    // Find interface calls by parsing source code
    if (currentFunction.sourceCode && currentDepth < maxDepth - 1) {
      const interfaceCalls = this.interfaceDetector.extractInterfaceCalls(
        currentFunction.sourceCode, 
        allFunctions,
        baseRepoInfo
      );
      
      if (this.debug && interfaceCalls.length > 0) {
        console.log(`\n=== DEBUG: Interface calls found in ${currentFunction.name} ===`);
        interfaceCalls.forEach(call => {
          console.log(`  - ${call.name} (pattern: ${call.pattern}, has definition: ${!!call.definition})`);
          if (call.implementation) {
            console.log(`    -> Implementation: ${call.implementation.contractName} (${(call.implementation.matchRatio * 100).toFixed(1)}% match)`);
          }
        });
      }
      
      for (const interfaceCall of interfaceCalls) {
        // Check if this call is already captured
        const alreadyCaptured = tree.calls.some(call => call.name === interfaceCall.name);
        if (!alreadyCaptured) {
          tree.calls.push({
            name: interfaceCall.name,
            type: 'interface',
            interface: interfaceCall.interface,
            external: !interfaceCall.definition,
            definition: interfaceCall.definition,
            pattern: interfaceCall.pattern,
            implementation: interfaceCall.implementation,
            depth: currentDepth + 1
          });
        }
      }
    }

    return tree;
  }

  // Print call tree visualization
  printCallTree(tree, indent = 0) {
    const prefix = '  '.repeat(indent);
    const arrow = indent > 0 ? '└─ ' : '';
    
    if (tree.external && !tree.definition) {
      let description = '';
      if (tree.type === 'interface') {
        description = ` (interface: ${tree.interface})`;
        if (tree.pattern) {
          description += ` [${tree.pattern}]`;
        }
        if (tree.implementation) {
          description += ` -> ${tree.implementation.contractName}`;
        }
      } else {
        description = ` (external, ${tree.arguments || 0} args)`;
      }
      console.log(`${prefix}${arrow}${tree.name}${description}`);
      return;
    }
    
    if (tree.type === 'interface' && tree.definition) {
      let description = ` (interface: ${tree.interface})`;
      if (tree.pattern) {
        description += ` [${tree.pattern}]`;
      }
      if (tree.implementation) {
        description += ` -> ${tree.implementation.contractName}`;
      }
      description += ` - ${tree.definition.signature || tree.definition.name}`;
      console.log(`${prefix}${arrow}${tree.name}${description}`);
    } else {
      const signature = tree.signature ? ` - ${tree.signature}` : '';
      console.log(`${prefix}${arrow}${tree.name}${signature}`);
    }
    
    if (tree.calls && tree.calls.length > 0) {
      tree.calls.forEach(call => this.printCallTree(call, indent + 1));
    }
  }

  // Calculate maximum depth in call tree
  getMaxDepth(tree) {
    if (!tree.calls || tree.calls.length === 0) {
      return tree.depth;
    }
    return Math.max(tree.depth, ...tree.calls.map(call => this.getMaxDepth(call)));
  }

  // Analyze call depth distribution
  analyzeCallDepth(tree) {
    const depths = {};
    
    const traverse = (node) => {
      const depth = node.depth || 0;
      depths[depth] = (depths[depth] || 0) + 1;
      
      if (node.calls) {
        node.calls.forEach(traverse);
      }
    };

    traverse(tree);
    return depths;
  }
}

module.exports = CallTreeBuilder;