const ImplementationResolver = require('./implementation-resolver.js');

/**
 * Interface Call Detector
 * Analyzes Solidity source code to find interface method calls and their implementations
 */
class InterfaceDetector {
  constructor(options = {}) {
    this.debug = options.debug || false;
    this.resolveImplementations = options.resolveImplementations !== false; // Default true
    this.implementationResolver = new ImplementationResolver({ debug: this.debug });
  }

  // Extract interface calls from source code with implementation resolution
  extractInterfaceCalls(sourceCode, allFunctions, baseRepoInfo = null) {
    const interfaceCalls = [];
    
    if (this.debug) {
      console.log(`\n=== DEBUG: Analyzing source code (${sourceCode.length} chars) ===`);
    }
    
    // Pattern 1: InterfaceName(address).methodName()
    this.findDirectInterfaceCalls(sourceCode, allFunctions, interfaceCalls);
    
    // Pattern 2: Variable declarations with interface casting
    this.findVariableInterfaceCalls(sourceCode, allFunctions, interfaceCalls);
    
    // Pattern 3: Method calls on variables
    this.findMethodCalls(sourceCode, allFunctions, interfaceCalls);
    
    // Pattern 4: Search by function name in interface files
    this.findByFunctionName(sourceCode, allFunctions, interfaceCalls);
    
    if (this.debug) {
      console.log(`Found ${interfaceCalls.length} interface calls total`);
    }
    
    // Resolve implementations if enabled
    if (this.resolveImplementations && baseRepoInfo) {
      const implementations = this.implementationResolver.resolveImplementations(
        interfaceCalls, 
        allFunctions, 
        baseRepoInfo
      );
      
      if (implementations.size > 0) {
        const enhancedCalls = this.implementationResolver.enhanceInterfaceCallsWithImplementations(
          interfaceCalls, 
          implementations
        );
        
        if (this.debug) {
          console.log(`\n=== DEBUG: Enhanced ${enhancedCalls.filter(c => c.implementation).length} calls with implementations ===`);
          enhancedCalls.forEach(call => {
            if (call.implementation) {
              console.log(`  ${call.name} -> ${call.implementation.contractName} (${(call.implementation.matchRatio * 100).toFixed(1)}% match)`);
            }
          });
        }
        
        return enhancedCalls;
      }
    }
    
    return interfaceCalls;
  }

  // Pattern 1: InterfaceName(address).methodName()
  findDirectInterfaceCalls(sourceCode, allFunctions, interfaceCalls) {
    const interfaceCallPattern = /(\w+)\([^)]+\)\.(\w+)\s*\(/g;
    
    let match;
    while ((match = interfaceCallPattern.exec(sourceCode)) !== null) {
      const interfaceName = match[1];
      const methodName = match[2];
      
      const interfaceFunction = allFunctions.find(f => 
        f.file && f.file.includes(interfaceName) && f.name === methodName
      );
      
      interfaceCalls.push({
        interface: interfaceName,
        name: `${interfaceName}.${methodName}`,
        methodName: methodName,
        definition: interfaceFunction,
        pattern: 'direct'
      });
      
      if (this.debug) {
        console.log(`  Direct call: ${interfaceName}.${methodName} (found def: ${!!interfaceFunction})`);
      }
    }
  }

  // Pattern 2: Variable declarations with interface casting
  findVariableInterfaceCalls(sourceCode, allFunctions, interfaceCalls) {
    const interfaceVarPattern = /(\w+)\s+(\w+)\s*=\s*(\w+)\([^)]+\);/g;
    const interfaceVariables = new Map(); // varName -> interfaceName
    
    let match;
    while ((match = interfaceVarPattern.exec(sourceCode)) !== null) {
      const interfaceName = match[1];
      const varName = match[2];
      interfaceVariables.set(varName, interfaceName);
      
      if (this.debug) {
        console.log(`  Variable declaration: ${varName} = ${interfaceName}(...)`);
      }
    }

    // Now find calls on these variables
    const methodCallPattern = /(\w+)\.(\w+)\s*\(/g;
    
    while ((match = methodCallPattern.exec(sourceCode)) !== null) {
      const variableName = match[1];
      const methodName = match[2];
      
      // Skip common patterns that aren't interface calls
      if (['msg', 'block', 'tx', 'this', 'super', '$'].includes(variableName)) {
        continue;
      }
      
      const interfaceName = interfaceVariables.get(variableName);
      if (interfaceName) {
        const interfaceFunction = allFunctions.find(f => 
          f.name === methodName && f.file && f.file.includes(interfaceName)
        );
        
        const callName = `${interfaceName}.${methodName}`;
        if (!interfaceCalls.some(call => call.name === callName)) {
          interfaceCalls.push({
            interface: interfaceName,
            name: callName,
            methodName: methodName,
            definition: interfaceFunction,
            pattern: 'variable'
          });
          
          if (this.debug) {
            console.log(`  Variable call: ${variableName}.${methodName} -> ${interfaceName}.${methodName} (found def: ${!!interfaceFunction})`);
          }
        }
      }
    }
  }

  // Pattern 3: Method calls on variables (fallback)
  findMethodCalls(sourceCode, allFunctions, interfaceCalls) {
    const methodCallPattern = /(\w+)\.(\w+)\s*\(/g;
    
    let match;
    while ((match = methodCallPattern.exec(sourceCode)) !== null) {
      const variableName = match[1];
      const methodName = match[2];
      
      // Skip common patterns and already processed calls
      if (['msg', 'block', 'tx', 'this', 'super', '$'].includes(variableName)) {
        continue;
      }
      
      // Look for interface function definitions
      const interfaceFunction = allFunctions.find(f => 
        f.name === methodName && f.file && (
          f.file.toLowerCase().includes('interface') || 
          f.file.startsWith('I') || 
          f.signature?.includes('external')
        )
      );
      
      if (interfaceFunction) {
        const callName = `${variableName}.${methodName}`;
        if (!interfaceCalls.some(call => call.name === callName)) {
          interfaceCalls.push({
            interface: variableName,
            name: callName,
            methodName: methodName,
            definition: interfaceFunction,
            pattern: 'method'
          });
          
          if (this.debug) {
            console.log(`  Method call: ${callName} (found def: ${!!interfaceFunction})`);
          }
        }
      }
    }
  }

  // Pattern 4: Search by function name in interface files
  findByFunctionName(sourceCode, allFunctions, interfaceCalls) {
    const potentialInterfaceFunctions = allFunctions.filter(f => 
      f.file && (
        f.file.toLowerCase().includes('interface') ||
        f.file.startsWith('I') ||
        f.file.includes('IDrand') ||
        f.file.includes('IGas')
      )
    );

    for (const interfaceFunc of potentialInterfaceFunctions) {
      const funcCallPattern = new RegExp(`\\b${interfaceFunc.name}\\s*\\(`, 'g');
      if (funcCallPattern.test(sourceCode)) {
        const alreadyAdded = interfaceCalls.some(call => 
          call.methodName === interfaceFunc.name
        );
        if (!alreadyAdded) {
          const interfaceName = interfaceFunc.file.replace('.sol', '');
          interfaceCalls.push({
            interface: interfaceName,
            name: `${interfaceName}.${interfaceFunc.name}`,
            methodName: interfaceFunc.name,
            definition: interfaceFunc,
            pattern: 'byname'
          });
          
          if (this.debug) {
            console.log(`  By name: ${interfaceFunc.name} in ${interfaceFunc.file}`);
          }
        }
      }
    }
  }
}

module.exports = InterfaceDetector;