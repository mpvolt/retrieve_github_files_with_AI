#!/usr/bin/env node

const axios = require('axios');
const Parser = require('@solidity-parser/parser');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const DependencyResolver = require('./dependency_resolver.js');

class GitHubSolidityAnalyzer {
  constructor() {
    this.contracts = new Map(); // filename -> AST
    this.dependencies = new Set();
    this.stateVariables = [];
    this.modifiers = [];
    this.functions = [];
    this.sourceFiles = new Map(); // filename -> source code
    this.processedFiles = new Set(); // Track processed files to avoid duplicates
    this.baseRepoInfo = null; // Store repository information for dependency resolution
    this.dependencyResolver = new DependencyResolver();
  }

  // Convert GitHub blob URL to raw URL
  convertToRawUrl(githubUrl) {
    return this.dependencyResolver.convertToRawUrl(githubUrl);
  }

  // Fetch source code from GitHub
  async fetchSourceCode(githubUrl) {
    try {
      const rawUrl = this.convertToRawUrl(githubUrl);
      console.log(`Fetching: ${rawUrl}`);
      
      const response = await axios.get(rawUrl, {
        timeout: 10000,
        headers: {
          'User-Agent': 'Solidity-Analyzer/1.0'
        }
      });
      
      return {
        content: response.data,
        filename: this.extractFilename(githubUrl)
      };
    } catch (error) {
      if (error.response) {
        throw new Error(`HTTP ${error.response.status}: ${error.response.statusText}`);
      } else if (error.request) {
        throw new Error('Network error: Unable to reach GitHub');
      } else {
        throw new Error(`Error fetching file: ${error.message}`);
      }
    }
  }

  // Extract filename from URL
  extractFilename(url) {
    return this.dependencyResolver.extractFilename(url);
  }

  // Check if file is a Solidity file
  isSolidityFile(filename) {
    return this.dependencyResolver.isSolidityFile(filename);
  }

  // Analyze single file with dependency resolution
  async analyzeSingleFile(githubUrl, resolveDependencies = true, maxDepth = 3) {
    // Parse repository information for dependency resolution
    this.baseRepoInfo = this.dependencyResolver.parseRepoInfo(githubUrl);
    
    const fileData = await this.fetchSourceCode(githubUrl);
    
    if (!this.isSolidityFile(fileData.filename)) {
      throw new Error(`File ${fileData.filename} is not a Solidity file (.sol)`);
    }

    this.sourceFiles.set(fileData.filename, fileData.content);
    this.processedFiles.add(path.basename(fileData.filename));
    
    // Initial parsing and analysis
    this.parseAndAnalyze([{
      filename: fileData.filename,
      content: fileData.content
    }]);
    
    // Resolve dependencies if requested
    if (resolveDependencies && this.baseRepoInfo) {
      console.log('\n=== Starting Dependency Resolution ===');
      await this.resolveDependenciesRecursively(maxDepth);
    }
    
    return this.generateReport();
  }

  // Analyze multiple files with dependency resolution
  async analyzeMultipleFiles(githubUrls, resolveDependencies = true, maxDepth = 3) {
    const files = [];
    
    // Set base repo info from the first URL
    if (githubUrls.length > 0) {
      this.baseRepoInfo = this.dependencyResolver.parseRepoInfo(githubUrls[0]);
    }
    
    for (const url of githubUrls) {
      try {
        const fileData = await this.fetchSourceCode(url);
        if (this.isSolidityFile(fileData.filename)) {
          files.push(fileData);
          this.sourceFiles.set(fileData.filename, fileData.content);
          this.processedFiles.add(path.basename(fileData.filename));
        } else {
          console.warn(`Skipping non-Solidity file: ${fileData.filename}`);
        }
      } catch (error) {
        console.error(`Failed to fetch ${url}: ${error.message}`);
      }
    }

    if (files.length === 0) {
      throw new Error('No valid Solidity files found');
    }

    // Initial parsing and analysis
    this.parseAndAnalyze(files);
    
    // Resolve dependencies if requested
    if (resolveDependencies && this.baseRepoInfo) {
      console.log('\n=== Starting Dependency Resolution ===');
      await this.resolveDependenciesRecursively(maxDepth);
    }
    
    return this.generateReport();
  }

  // Recursively resolve and analyze dependencies
  async resolveDependenciesRecursively(maxDepth = 3, currentDepth = 0) {
    if (currentDepth >= maxDepth) {
      console.log(`Maximum recursion depth (${maxDepth}) reached`);
      return;
    }
    
    const currentDependencies = Array.from(this.dependencies);
    
    if (currentDependencies.length === 0) {
      console.log('No dependencies found to resolve');
      return;
    }
    
    console.log(`\n🔍 Depth ${currentDepth + 1}/${maxDepth}: Found ${currentDependencies.length} dependencies`);
    
    // Use dependency resolver to fetch files
    const result = await this.dependencyResolver.resolveDependencies(
      currentDependencies, 
      this.baseRepoInfo, 
      true // verbose
    );
    
    if (result.resolved.length === 0) {
      console.log('No dependencies could be resolved');
      return;
    }
    
    // Parse and analyze resolved dependencies
    const newFiles = [];
    const previousDependencyCount = this.dependencies.size;
    
    for (const fileData of result.resolved) {
      // Avoid processing the same file twice
      const normalizedName = path.basename(fileData.filename);
      if (!this.processedFiles.has(normalizedName)) {
        newFiles.push(fileData);
        this.sourceFiles.set(fileData.filename, fileData.content);
        this.processedFiles.add(normalizedName);
      }
    }
    
    if (newFiles.length > 0) {
      console.log(`\n📝 Parsing ${newFiles.length} resolved dependencies...`);
      
      // Parse new files
      for (const file of newFiles) {
        try {
          const ast = Parser.parse(file.content, {
            loc: true,
            range: true,
            tolerant: false
          });
          this.contracts.set(file.filename, ast);
          console.log(`  ✅ Parsed: ${file.filename}`);
        } catch (error) {
          console.error(`  ❌ Failed to parse ${file.filename}: ${error.message}`);
        }
      }
      
      // Analyze new files to extract their dependencies
      for (const file of newFiles) {
        if (this.contracts.has(file.filename)) {
          this.analyzeContract(this.contracts.get(file.filename), file.filename);
        }
      }
      
      // Check if we found new dependencies
      const newDependencyCount = this.dependencies.size;
      if (newDependencyCount > previousDependencyCount) {
        const newDepsFound = newDependencyCount - previousDependencyCount;
        console.log(`🔗 Found ${newDepsFound} new dependencies in resolved files`);
        
        // Recursively resolve new dependencies
        await this.resolveDependenciesRecursively(maxDepth, currentDepth + 1);
      } else {
        console.log('No new dependencies found in resolved files');
      }
    }
  }

  // Parse and analyze Solidity files
  parseAndAnalyze(files) {
    // Reset state
    this.contracts.clear();
    this.dependencies.clear();
    this.stateVariables = [];
    this.modifiers = [];
    this.functions = [];

    // Parse all files first
    for (const file of files) {
      try {
        const ast = Parser.parse(file.content, {
          loc: true,
          range: true,
          tolerant: false
        });
        this.contracts.set(file.filename, ast);
        console.log(`Successfully parsed: ${file.filename}`);
      } catch (error) {
        console.error(`Failed to parse ${file.filename}: ${error.message}`);
        throw new Error(`Parse error in ${file.filename}: ${error.message}`);
      }
    }

    // Analyze each file
    for (const [filename, ast] of this.contracts) {
      this.analyzeContract(ast, filename);
    }

    return this.generateReport();
  }

  // Analyze individual contract
  analyzeContract(ast, filename) {
    Parser.visit(ast, {
      ImportDirective: (node) => {
        this.dependencies.add(node.path);
      },
      
      StateVariableDeclaration: (node) => {
        node.variables.forEach(variable => {
          this.stateVariables.push({
            name: variable.name,
            type: this.getTypeString(variable.typeName),
            visibility: variable.visibility || 'internal',
            isConstant: variable.isConstant || false,
            isImmutable: variable.isImmutable || false,
            file: filename,
            location: node.loc
          });
        });
      },

      ModifierDefinition: (node) => {
        this.modifiers.push({
          name: node.name,
          parameters: this.extractParameters(node.parameters),
          file: filename,
          location: node.loc
        });
      },

      FunctionDefinition: (node) => {
        const functionInfo = {
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
          calls: []
        };

        // Find function calls within this function
        if (node.body) {
          this.findFunctionCalls(node.body, functionInfo.calls);
        }

        this.functions.push(functionInfo);
      },

      EventDefinition: (node) => {
        // Track events as well
        const eventInfo = {
          type: 'event',
          name: node.name,
          parameters: this.extractParameters(node.parameters),
          file: filename,
          location: node.loc
        };
        
        // Add to functions array for simplicity (could create separate events array)
        this.functions.push(eventInfo);
      }
    });
  }

  // Extract parameters from AST node
  extractParameters(parametersNode) {
    if (!parametersNode || !parametersNode.parameters) {
      return [];
    }
    
    return parametersNode.parameters.map(param => ({
      name: param.name || '',
      type: this.getTypeString(param.typeName),
      indexed: param.indexed || false
    }));
  }

  // Find function calls within a code block
  findFunctionCalls(node, calls) {
    Parser.visit(node, {
      FunctionCall: (callNode) => {
        if (callNode.expression) {
          const functionName = this.extractFunctionName(callNode.expression);
          if (functionName) {
            calls.push({
              name: functionName,
              arguments: callNode.arguments?.length || 0,
              location: callNode.loc
            });
          }
        }
      }
    });
  }

  // Extract function name from expression
  extractFunctionName(expression) {
    if (!expression) return null;
    
    switch (expression.type) {
      case 'Identifier':
        return expression.name;
      case 'MemberAccess':
        const base = this.extractFunctionName(expression.expression);
        return base ? `${base}.${expression.memberName}` : expression.memberName;
      default:
        return null;
    }
  }

  // Build function signature
  buildFunctionSignature(node) {
    const name = node.name || (node.isConstructor ? 'constructor' : 
                             node.isReceive ? 'receive' : 
                             node.isFallback ? 'fallback' : 'unknown');
    
    const params = this.extractParameters(node.parameters)
      .map(p => `${p.type} ${p.name}`.trim())
      .join(', ');
    
    const returns = this.extractParameters(node.returnParameters)
      .map(p => p.type)
      .join(', ');
    
    let signature = `${name}(${params})`;
    
    if (node.visibility && node.visibility !== 'internal') {
      signature += ` ${node.visibility}`;
    }
    
    if (node.stateMutability && node.stateMutability !== 'nonpayable') {
      signature += ` ${node.stateMutability}`;
    }
    
    if (returns) {
      signature += ` returns (${returns})`;
    }
    
    return signature;
  }

  // Get type string from type AST node
  getTypeString(typeName) {
    if (!typeName) return 'unknown';
    
    switch (typeName.type) {
      case 'ElementaryTypeName':
        return typeName.name;
      case 'UserDefinedTypeName':
        return typeName.namePath;
      case 'ArrayTypeName':
        const baseType = this.getTypeString(typeName.baseTypeName);
        const length = typeName.length ? `[${typeName.length}]` : '[]';
        return `${baseType}${length}`;
      case 'Mapping':
        const keyType = this.getTypeString(typeName.keyType);
        const valueType = this.getTypeString(typeName.valueType);
        return `mapping(${keyType} => ${valueType})`;
      case 'FunctionTypeName':
        return 'function';
      default:
        return typeName.type || 'unknown';
    }
  }

  // Find where a called function is defined
  findFunctionDefinition(functionName) {
    return this.functions.find(f => 
      f.name === functionName || 
      (f.signature && f.signature.startsWith(functionName + '('))
    );
  }

  // Generate final report
  generateReport() {
    // Create cross-references for function calls
    const functionsWithResolvedCalls = this.functions.map(func => {
      if (!func.calls) return func;
      
      return {
        ...func,
        resolvedCalls: func.calls.map(call => ({
          ...call,
          definition: this.findFunctionDefinition(call.name),
          isExternal: !this.findFunctionDefinition(call.name)
        }))
      };
    });

    // Get dependency resolver stats
    const resolverStats = this.dependencyResolver.getStats();

    return {
      metadata: {
        analyzedAt: new Date().toISOString(),
        totalFiles: this.contracts.size,
        fileNames: Array.from(this.contracts.keys()),
        repositoryInfo: this.baseRepoInfo,
        processedFiles: Array.from(this.processedFiles)
      },
      dependencies: {
        found: Array.from(this.dependencies).sort(),
        resolved: resolverStats.processedDependencies,
        failed: resolverStats.failedDependencies,
        external: resolverStats.failedDependencies.filter(dep => 
          this.dependencyResolver.isExternalDependency(dep)
        ),
        unreachable: resolverStats.failedDependencies.filter(dep => 
          !this.dependencyResolver.isExternalDependency(dep)
        )
      },
      stateVariables: this.stateVariables.sort((a, b) => a.name.localeCompare(b.name)),
      modifiers: this.modifiers.sort((a, b) => a.name.localeCompare(b.name)),
      functions: functionsWithResolvedCalls.sort((a, b) => a.name.localeCompare(b.name)),
      summary: {
        totalDependencies: this.dependencies.size,
        resolvedDependencies: resolverStats.totalProcessed,
        failedDependencies: resolverStats.totalFailed,
        externalDependencies: resolverStats.failedDependencies.filter(dep => 
          this.dependencyResolver.isExternalDependency(dep)
        ).length,
        dependencySuccessRate: resolverStats.successRate,
        totalStateVariables: this.stateVariables.length,
        totalModifiers: this.modifiers.length,
        totalFunctions: this.functions.filter(f => f.type !== 'event').length,
        totalEvents: this.functions.filter(f => f.type === 'event').length,
        externalFunctionCalls: functionsWithResolvedCalls
          .flatMap(f => f.resolvedCalls || [])
          .filter(call => call.isExternal).length,
        internalFunctionCalls: functionsWithResolvedCalls
          .flatMap(f => f.resolvedCalls || [])
          .filter(call => !call.isExternal).length
      }
    };
  }

  // Save report to file
  async saveReport(report, outputPath) {
    const jsonOutput = JSON.stringify(report, null, 2);
    await fs.promises.writeFile(outputPath, jsonOutput, 'utf8');
    console.log(`Report saved to: ${outputPath}`);
  }
}

// CLI interface
async function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    console.log(`
Usage: node solidity-analyzer.js <github-blob-url> [output-file] [options]

Options:
  --no-deps          Disable dependency resolution
  --max-depth=N      Maximum recursion depth for dependencies (default: 3)

Examples:
  # Analyze single file with dependency resolution
  node solidity-analyzer.js https://github.com/owner/repo/blob/main/Contract.sol

  # Analyze without resolving dependencies
  node solidity-analyzer.js https://github.com/owner/repo/blob/main/Contract.sol --no-deps

  # Analyze with custom depth and output
  node solidity-analyzer.js https://github.com/owner/repo/blob/main/Contract.sol output.json --max-depth=2

  # Analyze multiple files
  node solidity-analyzer.js "url1,url2,url3" analysis.json
`);
    process.exit(1);
  }

  const urlInput = args[0];
  let outputFile = 'solidity-analysis.json';
  let resolveDependencies = true;
  let maxDepth = 3;
  
  // Parse arguments
  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--no-deps') {
      resolveDependencies = false;
    } else if (arg.startsWith('--max-depth=')) {
      maxDepth = parseInt(arg.split('=')[1]) || 3;
    } else if (!arg.startsWith('--')) {
      outputFile = arg;
    }
  }
  
  try {
    const analyzer = new GitHubSolidityAnalyzer();
    let report;

    // Check if multiple URLs (comma-separated)
    if (urlInput.includes(',')) {
      const urls = urlInput.split(',').map(url => url.trim());
      console.log(`Analyzing ${urls.length} files...`);
      report = await analyzer.analyzeMultipleFiles(urls, resolveDependencies, maxDepth);
    } else {
      console.log('Analyzing single file...');
      report = await analyzer.analyzeSingleFile(urlInput, resolveDependencies, maxDepth);
    }

    await analyzer.saveReport(report, outputFile);
    
    console.log('\n=== Analysis Summary ===');
    console.log(`Files analyzed: ${report.metadata.totalFiles}`);
    console.log(`Dependencies found: ${report.summary.totalDependencies}`);
    console.log(`Dependencies resolved: ${report.summary.resolvedDependencies}`);
    console.log(`Dependencies failed: ${report.summary.failedDependencies}`);
    console.log(`External dependencies: ${report.summary.externalDependencies}`);
    console.log(`Dependency success rate: ${(report.summary.dependencySuccessRate * 100).toFixed(1)}%`);
    console.log(`State variables: ${report.summary.totalStateVariables}`);
    console.log(`Modifiers: ${report.summary.totalModifiers}`);
    console.log(`Functions: ${report.summary.totalFunctions}`);
    console.log(`Events: ${report.summary.totalEvents}`);
    console.log(`Internal function calls: ${report.summary.internalFunctionCalls}`);
    console.log(`External function calls: ${report.summary.externalFunctionCalls}`);
    
    if (report.dependencies.failed.length > 0) {
      console.log('\n=== Failed Dependencies ===');
      console.log('External (expected to fail):');
      report.dependencies.external.forEach(dep => console.log(`  🌐 ${dep}`));
      console.log('Unreachable (unexpected failures):');
      report.dependencies.unreachable.forEach(dep => console.log(`  ❌ ${dep}`));
    }
    
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

// Export for use as module
module.exports = GitHubSolidityAnalyzer;

// Run as CLI if called directly
if (require.main === module) {
  main();
}