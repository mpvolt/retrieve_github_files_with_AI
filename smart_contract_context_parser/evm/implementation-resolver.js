const DependencyResolver = require('./dependency-resolver.js');

/**
 * Implementation Resolver
 * Finds concrete implementations of interfaces in the analyzed contracts
 * and fetches them if not already available
 */
class ImplementationResolver {
  constructor(options = {}) {
    this.debug = options.debug || false;
    this.dependencyResolver = new DependencyResolver();
  }

  // Find implementations for detected interface calls
  async resolveImplementations(interfaceCalls, allFunctions, baseRepoInfo) {
    const implementationMap = new Map(); // interface -> implementation info
    const newlyFetchedFunctions = []; // Track newly fetched implementation functions
    
    for (const interfaceCall of interfaceCalls) {
      if (!interfaceCall.definition) continue;
      
      const interfaceName = this.extractInterfaceName(interfaceCall.interface);
      
      if (this.debug) {
        console.log(`\n=== DEBUG: Looking for implementation of ${interfaceName} ===`);
      }
      
      // First try to find implementation in existing functions
      let implementation = this.findImplementation(interfaceName, allFunctions, baseRepoInfo);
      
      // If not found, try to fetch implementation contract
      if (!implementation && baseRepoInfo) {
        implementation = await this.fetchImplementationContract(interfaceName, allFunctions, baseRepoInfo);
        if (implementation && implementation.newFunctions) {
          newlyFetchedFunctions.push(...implementation.newFunctions);
        }
      }
      
      if (implementation) {
        implementationMap.set(interfaceName, implementation);
        
        if (this.debug) {
          console.log(`Found implementation: ${implementation.contractName} with ${implementation.functions.length} functions`);
        }
      } else if (this.debug) {
        console.log(`No implementation found for ${interfaceName}`);
      }
    }
    
    return {
      implementations: implementationMap,
      newFunctions: newlyFetchedFunctions
    };
  }

  // Try to fetch implementation contract from repository
  async fetchImplementationContract(interfaceName, allFunctions, baseRepoInfo) {
    const candidateNames = this.generateImplementationNames(interfaceName);
    
    if (this.debug) {
      console.log(`Trying to fetch implementation contracts: ${candidateNames.join(', ')}`);
    }
    
    for (const candidateName of candidateNames) {
      try {
        const implementationFiles = await this.tryFetchImplementationFile(candidateName, baseRepoInfo);
        
        if (implementationFiles.length > 0) {
          if (this.debug) {
            console.log(`Found implementation file(s) for ${candidateName}`);
          }
          
          // Parse the implementation files
          const newFunctions = await this.parseImplementationFiles(implementationFiles);
          
          // Check if this actually implements the interface
          const interfaceFunctions = this.getInterfaceFunctions(interfaceName, allFunctions);
          const matchingFunctions = this.matchFunctions(interfaceFunctions, newFunctions);
          
          if (matchingFunctions.length > 0) {
            return {
              contractName: candidateName,
              file: implementationFiles[0].filename,
              functions: newFunctions,
              implementedFunctions: matchingFunctions,
              matchRatio: matchingFunctions.length / Math.max(interfaceFunctions.length, 1),
              newFunctions: newFunctions // Track these for addition to main function list
            };
          }
        }
      } catch (error) {
        if (this.debug) {
          console.log(`Failed to fetch ${candidateName}: ${error.message}`);
        }
      }
    }
    
    return null;
  }

  // Generate possible implementation contract names
  generateImplementationNames(interfaceName) {
    const baseName = interfaceName.replace(/^I/, '');
    
    return [
      baseName,                    // IDrandBeacon -> DrandBeacon
      `${baseName}Impl`,          // IDrandBeacon -> DrandBeaconImpl  
      `${baseName}Contract`,      // IDrandBeacon -> DrandBeaconContract
      `${baseName}Implementation`, // IDrandBeacon -> DrandBeaconImplementation
      `Concrete${baseName}`,      // IDrandBeacon -> ConcreteDrandBeacon
      `${interfaceName}Impl`,     // IDrandBeacon -> IDrandBeaconImpl
      `${baseName.toLowerCase()}`, // IDrandBeacon -> drandbeacon (lowercase)
      baseName.charAt(0).toLowerCase() + baseName.slice(1) // IDrandBeacon -> drandBeacon (camelCase)
    ];
  }

  // Try to fetch implementation file from repository
  async tryFetchImplementationFile(contractName, baseRepoInfo) {
    const potentialPaths = this.generateImplementationPaths(contractName, baseRepoInfo);
    const foundFiles = [];
    
    for (const path of potentialPaths) {
      try {
        const fileData = await this.dependencyResolver.fetchSourceCode(path);
        if (fileData && this.dependencyResolver.isSolidityFile(fileData.filename)) {
          foundFiles.push(fileData);
          if (this.debug) {
            console.log(`  ✅ Found implementation: ${fileData.filename}`);
          }
        }
      } catch (error) {
        // Continue trying other paths
        continue;
      }
    }
    
    return foundFiles;
  }

  // Generate potential paths for implementation files
  generateImplementationPaths(contractName, baseRepoInfo) {
    const { owner, repo, branch } = baseRepoInfo;
    const paths = [];
    
    // Common directory structures
    const directories = [
      'contracts',
      'src',
      'contracts/implementations',
      'contracts/impl', 
      'src/implementations',
      'contracts/core',
      'src/core',
      'lib',
      '', // root
    ];
    
    for (const dir of directories) {
      const basePath = dir ? `${dir}/` : '';
      
      // Try various filename patterns
      const filenames = [
        `${contractName}.sol`,
        `${contractName.toLowerCase()}.sol`,
        `${contractName}Contract.sol`,
        `${contractName}Impl.sol`
      ];
      
      for (const filename of filenames) {
        paths.push(`https://github.com/${owner}/${repo}/blob/${branch}/${basePath}${filename}`);
      }
    }
    
    return paths;
  }

  // Parse implementation files to extract functions
  async parseImplementationFiles(implementationFiles) {
    const Parser = require('@solidity-parser/parser');
    const allFunctions = [];
    
    for (const file of implementationFiles) {
      try {
        const ast = Parser.parse(file.content, {
          loc: true,
          range: true,
          tolerant: false
        });
        
        // Extract functions, state variables, and modifiers
        const fileFunctions = this.extractFromAST(ast, file.filename, file.content);
        allFunctions.push(...fileFunctions);
        
        if (this.debug) {
          console.log(`  Extracted ${fileFunctions.length} elements from ${file.filename}`);
        }
        
      } catch (error) {
        if (this.debug) {
          console.log(`  Failed to parse ${file.filename}: ${error.message}`);
        }
      }
    }
    
    return allFunctions;
  }

  // Extract functions, state variables, and modifiers from AST
  extractFromAST(ast, filename, sourceCode) {
    const elements = [];
    const Parser = require('@solidity-parser/parser');
    
    Parser.visit(ast, {
      StateVariableDeclaration: (node) => {
        node.variables.forEach(variable => {
          elements.push({
            type: 'stateVariable',
            name: variable.name,
            variableType: this.getTypeString(variable.typeName),
            visibility: variable.visibility || 'internal',
            isConstant: variable.isConstant || false,
            isImmutable: variable.isImmutable || false,
            file: filename,
            location: node.loc,
            sourceCode: this.extractSourceCode(node, sourceCode)
          });
        });
      },

      ModifierDefinition: (node) => {
        elements.push({
          type: 'modifier',
          name: node.name,
          parameters: this.extractParameters(node.parameters),
          file: filename,
          location: node.loc,
          sourceCode: this.extractSourceCode(node, sourceCode)
        });
      },

      FunctionDefinition: (node) => {
        elements.push({
          type: 'function',
          name: node.name || '<constructor>',
          signature: this.buildFunctionSignature(node),
          visibility: node.visibility || 'internal',
          stateMutability: node.stateMutability || 'nonpayable',
          modifiers: node.modifiers?.map(m => m.name) || [],
          parameters: this.extractParameters(node.parameters),
          returnParameters: this.extractParameters(node.returnParameters),
          isConstructor: node.isConstructor || false,
          isReceive: node.isReceive || false,
          isFallback: node.isFallback || false,
          file: filename,
          location: node.loc,
          sourceCode: this.extractSourceCode(node, sourceCode)
        });
      },

      EventDefinition: (node) => {
        elements.push({
          type: 'event',
          name: node.name,
          parameters: this.extractParameters(node.parameters),
          file: filename,
          location: node.loc,
          sourceCode: this.extractSourceCode(node, sourceCode)
        });
      }
    });
    
    return elements;
  }

  // Extract source code for a node
  extractSourceCode(node, sourceCode) {
    if (!node.loc) return null;
    
    try {
      const lines = sourceCode.split('\n');
      const startLine = node.loc.start.line - 1;
      const endLine = node.loc.end.line - 1;
      const startColumn = node.loc.start.column;
      const endColumn = node.loc.end.column;

      if (startLine === endLine) {
        return lines[startLine].substring(startColumn, endColumn);
      } else {
        const functionLines = [];
        functionLines.push(lines[startLine].substring(startColumn));
        for (let i = startLine + 1; i < endLine; i++) {
          functionLines.push(lines[i]);
        }
        if (endLine < lines.length) {
          functionLines.push(lines[endLine].substring(0, endColumn));
        }
        return functionLines.join('\n');
      }
    } catch (error) {
      return null;
    }
  }

  // Extract clean interface name from various formats
  extractInterfaceName(interfaceIdentifier) {
    // Handle cases like "IDrandBeacon.sol" -> "IDrandBeacon"
    let cleanName = interfaceIdentifier.replace('.sol', '');
    
    // Handle file paths
    if (cleanName.includes('/')) {
      cleanName = cleanName.split('/').pop();
    }
    
    return cleanName;
  }

  // Find implementation contract for an interface
  findImplementation(interfaceName, allFunctions, baseRepoInfo) {
    // Strategy 1: Look for contract with name without 'I' prefix
    // IDrandBeacon -> DrandBeacon
    const implName1 = interfaceName.startsWith('I') ? interfaceName.substring(1) : null;
    
    // Strategy 2: Look for contract with 'Impl' suffix
    // IDrandBeacon -> DrandBeaconImpl
    const implName2 = `${interfaceName.replace(/^I/, '')}Impl`;
    
    // Strategy 3: Look for contract with same name (concrete implementation)
    const implName3 = interfaceName.replace(/^I/, '');
    
    // Strategy 4: Common implementation patterns
    const implName4 = `${interfaceName}Implementation`;
    const implName5 = `${interfaceName.replace(/^I/, '')}Contract`;
    
    const candidateNames = [implName1, implName2, implName3, implName4, implName5].filter(Boolean);
    
    if (this.debug) {
      console.log(`Searching for implementations: ${candidateNames.join(', ')}`);
    }
    
    // Get interface functions to match against
    const interfaceFunctions = this.getInterfaceFunctions(interfaceName, allFunctions);
    
    for (const candidateName of candidateNames) {
      const implementation = this.findContractByName(candidateName, allFunctions, interfaceFunctions);
      if (implementation) {
        return implementation;
      }
    }
    
    // Strategy 5: Find by function signature matching
    return this.findByFunctionMatching(interfaceFunctions, allFunctions);
  }

  // Get all functions defined in an interface
  getInterfaceFunctions(interfaceName, allFunctions) {
    return allFunctions.filter(f => 
      f.file && (
        f.file.includes(interfaceName) ||
        f.file === `${interfaceName}.sol` ||
        f.file.endsWith(`/${interfaceName}.sol`)
      )
    );
  }

  // Find contract by name
  findContractByName(contractName, allFunctions, interfaceFunctions) {
    // Look for functions from a contract with this name
    const contractFunctions = allFunctions.filter(f => 
      f.file && (
        f.file.includes(contractName) ||
        f.file === `${contractName}.sol` ||
        f.file.endsWith(`/${contractName}.sol`)
      ) && f.type !== 'event'
    );
    
    if (contractFunctions.length === 0) {
      return null;
    }
    
    // Check if this contract implements the interface functions
    const matchingFunctions = this.matchFunctions(interfaceFunctions, contractFunctions);
    
    if (matchingFunctions.length > 0) {
      return {
        contractName: contractName,
        file: contractFunctions[0].file,
        functions: contractFunctions,
        implementedFunctions: matchingFunctions,
        matchRatio: matchingFunctions.length / Math.max(interfaceFunctions.length, 1)
      };
    }
    
    return null;
  }

  // Find implementation by function signature matching
  findByFunctionMatching(interfaceFunctions, allFunctions) {
    if (interfaceFunctions.length === 0) {
      return null;
    }
    
    // Group functions by file
    const functionsByFile = new Map();
    
    allFunctions.forEach(func => {
      if (func.file && func.type !== 'event') {
        if (!functionsByFile.has(func.file)) {
          functionsByFile.set(func.file, []);
        }
        functionsByFile.get(func.file).push(func);
      }
    });
    
    let bestMatch = null;
    let bestMatchRatio = 0;
    
    // Check each file for implementation
    for (const [fileName, fileFunctions] of functionsByFile) {
      // Skip interface files themselves
      if (fileName.toLowerCase().includes('interface') || fileName.startsWith('I')) {
        continue;
      }
      
      const matchingFunctions = this.matchFunctions(interfaceFunctions, fileFunctions);
      const matchRatio = matchingFunctions.length / interfaceFunctions.length;
      
      if (matchRatio > bestMatchRatio && matchRatio > 0.5) { // At least 50% match
        bestMatch = {
          contractName: fileName.replace('.sol', ''),
          file: fileName,
          functions: fileFunctions,
          implementedFunctions: matchingFunctions,
          matchRatio: matchRatio
        };
        bestMatchRatio = matchRatio;
      }
    }
    
    return bestMatch;
  }

  // Match interface functions with implementation functions
  matchFunctions(interfaceFunctions, implementationFunctions) {
    const matches = [];
    
    for (const interfaceFunc of interfaceFunctions) {
      // Look for function with same name and compatible signature
      const implFunc = implementationFunctions.find(impl => 
        impl.name === interfaceFunc.name &&
        this.isCompatibleSignature(interfaceFunc, impl)
      );
      
      if (implFunc) {
        matches.push({
          interface: interfaceFunc,
          implementation: implFunc
        });
      }
    }
    
    return matches;
  }

  // Check if implementation signature is compatible with interface
  isCompatibleSignature(interfaceFunc, implFunc) {
    // Basic compatibility check - same name and parameter count
    if (interfaceFunc.name !== implFunc.name) {
      return false;
    }
    
    const interfaceParams = interfaceFunc.parameters || [];
    const implParams = implFunc.parameters || [];
    
    // Parameter count should match
    if (interfaceParams.length !== implParams.length) {
      return false;
    }
    
    // Check parameter types (basic check)
    for (let i = 0; i < interfaceParams.length; i++) {
      if (interfaceParams[i].type !== implParams[i].type) {
        return false;
      }
    }
    
    return true;
  }

  // Enhance interface calls with implementation information
  enhanceInterfaceCallsWithImplementations(interfaceCalls, implementations) {
    return interfaceCalls.map(call => {
      const interfaceName = this.extractInterfaceName(call.interface);
      const implementation = implementations.get(interfaceName);
      
      if (implementation) {
        // Find the specific implemented function
        const matchedFunction = implementation.implementedFunctions.find(match => 
          match.interface.name === call.methodName
        );
        
        return {
          ...call,
          implementation: {
            contractName: implementation.contractName,
            file: implementation.file,
            matchRatio: implementation.matchRatio,
            implementedFunction: matchedFunction ? matchedFunction.implementation : null
          }
        };
      }
      
      return call;
    });
  }
}

module.exports = ImplementationResolver;