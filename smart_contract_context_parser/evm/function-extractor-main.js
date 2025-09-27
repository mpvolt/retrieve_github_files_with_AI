#!/usr/bin/env node

const GitHubSolidityAnalyzer = require('./solidity-analyzer.js');
const CallTreeBuilder = require('./call-tree-builder.js');
const FunctionFinder = require('./function-finder.js');
const fs = require('fs');

class FunctionExtractor {
  constructor() {
    this.analyzer = new GitHubSolidityAnalyzer({
      includeSourceCode: true
    });
  }

  // Extract a specific function and its call tree
  async extractFunction(githubUrl, targetFunctionName, options = {}) {
    const {
      maxDepth = 10,
      includeModifiers = true,
      includeEvents = false,
      resolveDependencies = true,
      debug = false
    } = options;

    console.log(`Extracting function: ${targetFunctionName}`);
    console.log(`Max call depth: ${maxDepth}`);
    
    // Analyze the contract
    const report = await this.analyzer.analyzeSingleFile(githubUrl, resolveDependencies, 3);
    
    if (debug) {
      this.printDebugInfo(report);
    }
    
    // Find the target function
    const finder = new FunctionFinder({ debug });
    const targetFunction = finder.findFunction(report.functions, targetFunctionName);
    if (!targetFunction) {
      throw new Error(`Function "${targetFunctionName}" not found. Available functions: ${finder.listAvailableFunctions(report.functions)}`);
    }

    console.log(`Found target function: ${targetFunction.signature}`);
    
    if (debug && targetFunction.sourceCode) {
      console.log('\n=== DEBUG: Target function source ===');
      console.log(targetFunction.sourceCode.substring(0, 500) + '...');
    }
    
    // Build call tree
    const treeBuilder = new CallTreeBuilder({ debug });
    const callTree = treeBuilder.buildCallTree(report.functions, targetFunction, maxDepth);
    
    // Extract all functions in the call tree
    const extractedFunctions = finder.extractFunctionsFromTree(report.functions, callTree, {
      includeModifiers,
      includeEvents
    });

    // Generate focused report
    return this.generateFocusedReport(report, extractedFunctions, targetFunction, callTree, treeBuilder);
  }

  // Print debug information
  printDebugInfo(report) {
    console.log('\n=== DEBUG: Available interface files ===');
    const interfaceFiles = report.functions
      .filter(f => f.file && (f.file.includes('Interface') || f.file.startsWith('I')))
      .map(f => f.file);
    const uniqueFiles = [...new Set(interfaceFiles)];
    uniqueFiles.forEach(file => console.log(`  - ${file}`));
    
    console.log('\n=== DEBUG: Functions in interface files ===');
    report.functions
      .filter(f => f.file && (f.file.includes('Interface') || f.file.startsWith('I') || f.file.includes('Drand')))
      .forEach(f => console.log(`  - ${f.name} (${f.file})`));
  }

  // Generate focused report with only extracted functions
  generateFocusedReport(originalReport, extractedFunctions, targetFunction, callTree, treeBuilder) {
    const functionsArray = Array.from(extractedFunctions.values());
    const finder = new FunctionFinder();
    
    return {
      metadata: {
        extractedAt: new Date().toISOString(),
        targetFunction: targetFunction.name,
        targetSignature: targetFunction.signature,
        originalAnalysis: {
          totalFiles: originalReport.metadata.totalFiles,
          totalFunctions: originalReport.summary.totalFunctions,
          analyzedAt: originalReport.metadata.analyzedAt
        },
        extraction: {
          functionsExtracted: functionsArray.length,
          maxCallDepth: treeBuilder.getMaxDepth(callTree),
          filesInvolved: [...new Set(functionsArray.map(f => f.file))]
        }
      },
      callTree: callTree,
      functions: functionsArray.sort((a, b) => a.name.localeCompare(b.name)),
      summary: {
        targetFunction: targetFunction,
        totalExtractedFunctions: functionsArray.length,
        functionsByFile: finder.groupByFile(functionsArray),
        callDepthAnalysis: treeBuilder.analyzeCallDepth(callTree)
      }
    };
  }

  // Save extraction report
  async saveReport(report, outputPath) {
    const jsonOutput = JSON.stringify(report, null, 2);
    await fs.promises.writeFile(outputPath, jsonOutput, 'utf8');
    console.log(`Function extraction report saved to: ${outputPath}`);
  }
}

// CLI interface
async function main() {
  const args = process.argv.slice(2);
  
  if (args.length < 2) {
    console.log(`
Usage: node function-extractor-main.js <github-blob-url> <function-name> [options]

Arguments:
  github-blob-url    GitHub URL to the Solidity contract
  function-name      Name of the function to extract

Options:
  --output=FILE      Output file for JSON report (default: function-extraction.json)
  --max-depth=N      Maximum call tree depth (default: 10)
  --no-deps          Skip dependency resolution (faster)
  --no-modifiers     Exclude modifiers from extraction
  --include-events   Include events in extraction
  --tree-only        Only print call tree, don't save report
  --debug            Enable debug output to diagnose interface detection

Examples:
  # Extract requestRandomness function and its call tree
  node function-extractor-main.js https://github.com/owner/repo/blob/main/Contract.sol requestRandomness

  # Extract with debug output to see interface detection
  node function-extractor-main.js https://github.com/owner/repo/blob/main/Contract.sol requestRandomness --debug
`);
    process.exit(1);
  }

  const githubUrl = args[0];
  const functionName = args[1];
  let outputFile = 'function-extraction.json';
  let maxDepth = 10;
  let resolveDependencies = true;
  let includeModifiers = true;
  let includeEvents = false;
  let treeOnly = false;
  let debug = false;

  // Parse options
  for (let i = 2; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--output=')) {
      outputFile = arg.split('=')[1];
    } else if (arg.startsWith('--max-depth=')) {
      maxDepth = parseInt(arg.split('=')[1]) || 10;
    } else if (arg === '--no-deps') {
      resolveDependencies = false;
    } else if (arg === '--no-modifiers') {
      includeModifiers = false;
    } else if (arg === '--include-events') {
      includeEvents = true;
    } else if (arg === '--tree-only') {
      treeOnly = true;
    } else if (arg === '--debug') {
      debug = true;
    }
  }

  try {
    const extractor = new FunctionExtractor();
    
    const report = await extractor.extractFunction(githubUrl, functionName, {
      maxDepth,
      includeModifiers,
      includeEvents,
      resolveDependencies,
      debug
    });

    console.log('\n=== Call Tree ===');
    const treeBuilder = new CallTreeBuilder();
    treeBuilder.printCallTree(report.callTree);

    console.log('\n=== Extraction Summary ===');
    console.log(`Target function: ${report.summary.targetFunction.name}`);
    console.log(`Functions extracted: ${report.summary.totalExtractedFunctions}`);
    console.log(`Maximum call depth: ${report.metadata.extraction.maxCallDepth}`);
    console.log(`Files involved: ${report.metadata.extraction.filesInvolved.length}`);
    
    console.log('\nFunctions by file:');
    Object.entries(report.summary.functionsByFile).forEach(([file, functions]) => {
      console.log(`  ${file}: ${functions.join(', ')}`);
    });

    if (!treeOnly) {
      await extractor.saveReport(report, outputFile);
      
      console.log('\n=== Extracted Functions ===');
      report.functions.forEach(func => {
        if (func.type !== 'event') {
          console.log(`${func.name}: ${func.signature}`);
          if (func.sourceCode) {
            console.log(`  Source: ${func.sourceCode.split('\n')[0]}...`);
          }
        }
      });
    }

  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

// Export for use as module
module.exports = FunctionExtractor;

// Run as CLI if called directly
if (require.main === module) {
  main();
}