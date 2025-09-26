const axios = require('axios');
const path = require('path');
const { URL } = require('url');

class DependencyResolver {
  constructor() {
    this.processedDependencies = new Set(); // Track processed dependencies to avoid duplicates
    this.failedDependencies = new Set(); // Track dependencies that couldn't be resolved
    this.resolvedFiles = new Map(); // dependency path -> file data
  }

  // Parse repository information from GitHub URL
  parseRepoInfo(githubUrl) {
    try {
      const url = new URL(githubUrl);
      if (url.hostname === 'github.com') {
        const pathParts = url.pathname.split('/');
        if (pathParts.length >= 5) {
          return {
            owner: pathParts[1],
            repo: pathParts[2],
            branch: pathParts[4],
            basePath: pathParts.slice(5, -1).join('/') // Path without filename
          };
        }
      }
      return null;
    } catch {
      return null;
    }
  }

  // Convert GitHub blob URL to raw URL
  convertToRawUrl(githubUrl) {
    try {
      const url = new URL(githubUrl);
      
      // Handle github.com URLs
      if (url.hostname === 'github.com') {
        const pathParts = url.pathname.split('/');
        if (pathParts.length >= 5 && pathParts[3] === 'blob') {
          // Format: /owner/repo/blob/branch/path/to/file
          const owner = pathParts[1];
          const repo = pathParts[2];
          const branch = pathParts[4];
          const filePath = pathParts.slice(5).join('/');
          return `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${filePath}`;
        }
      }
      
      // If it's already a raw URL, return as is
      if (url.hostname === 'raw.githubusercontent.com') {
        return githubUrl;
      }
      
      throw new Error('Invalid GitHub URL format');
    } catch (error) {
      throw new Error(`Failed to parse GitHub URL: ${error.message}`);
    }
  }

  // Extract filename from URL
  extractFilename(url) {
    try {
      const urlObj = new URL(url);
      const pathParts = urlObj.pathname.split('/');
      return pathParts[pathParts.length - 1];
    } catch {
      return 'unknown.sol';
    }
  }

  // Fetch source code from GitHub
  async fetchSourceCode(githubUrl) {
    try {
      const rawUrl = this.convertToRawUrl(githubUrl);
      
      const response = await axios.get(rawUrl, {
        timeout: 10000,
        headers: {
          'User-Agent': 'Solidity-Dependency-Resolver/1.0'
        }
      });
      
      return {
        content: response.data,
        filename: this.extractFilename(githubUrl),
        url: githubUrl
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

  // Generate potential file paths for a dependency
  resolveDependencyPaths(dependencyPath, baseRepoInfo) {
    if (!baseRepoInfo) return [];
    
    const { owner, repo, branch } = baseRepoInfo;
    const potentialPaths = [];
    
    // Clean up the dependency path
    const cleanPath = dependencyPath.replace(/^["']|["']$/g, ''); // Remove quotes
    
    // Skip if it's an external package or absolute path that we can't resolve
    if (this.isExternalDependency(cleanPath)) {
      return [];
    }
    
    // Common resolution strategies
    const strategies = [
      // 1. Relative to current file's directory
      baseRepoInfo.basePath ? `${baseRepoInfo.basePath}/${cleanPath}` : cleanPath,
      
      // 2. Relative to repository root
      cleanPath,
      
      // 3. Common contract directories
      `contracts/${cleanPath}`,
      `src/${cleanPath}`,
      `lib/${cleanPath}`,
      
      // 4. Remove leading ./ if present
      cleanPath.startsWith('./') ? cleanPath.substring(2) : null,
      
      // 5. Handle ../ paths relative to base
      cleanPath.startsWith('../') ? this.resolveRelativePath(cleanPath, baseRepoInfo.basePath) : null,
      
      // 6. Try with contracts prefix if not already there
      !cleanPath.startsWith('contracts/') ? `contracts/${cleanPath}` : null,
      
      // 7. Try in interfaces directory
      `contracts/interfaces/${path.basename(cleanPath)}`,
      
      // 8. Try in utils directory
      `contracts/utils/${path.basename(cleanPath)}`
    ].filter(Boolean);
    
    // Generate GitHub URLs for each strategy
    strategies.forEach(pathStrategy => {
      // Normalize path (remove double slashes, etc.)
      const normalizedPath = pathStrategy.replace(/\/+/g, '/').replace(/^\//, '');
      
      // Add .sol extension if not present
      const finalPath = normalizedPath.endsWith('.sol') ? 
        normalizedPath : `${normalizedPath}.sol`;
      
      potentialPaths.push(
        `https://github.com/${owner}/${repo}/blob/${branch}/${finalPath}`
      );
    });
    
    return [...new Set(potentialPaths)]; // Remove duplicates
  }

  // Check if dependency is external (can't be resolved in same repo)
  isExternalDependency(dependencyPath) {
    const externalPatterns = [
      /^@openzeppelin\//, // OpenZeppelin packages
      /^@chainlink\//, // Chainlink packages
      /^hardhat\//, // Hardhat imports
      /^forge-std\//, // Foundry standard library
      /^ds-test\//, // DappTools test library
      /^solmate\//, // Solmate library
      /^node_modules\//, // Node modules
      /^npm:/, // NPM packages
      /^https?:\/\//, // HTTP URLs
      /^ipfs:\/\//, // IPFS URLs
    ];
    
    return externalPatterns.some(pattern => pattern.test(dependencyPath));
  }

  // Resolve relative paths like ../interfaces/IContract.sol
  resolveRelativePath(relativePath, basePath) {
    if (!basePath) return relativePath;
    
    const basePathParts = basePath.split('/');
    const relativePathParts = relativePath.split('/');
    
    const resolvedParts = [...basePathParts];
    
    for (const part of relativePathParts) {
      if (part === '..') {
        resolvedParts.pop();
      } else if (part !== '.') {
        resolvedParts.push(part);
      }
    }
    
    return resolvedParts.join('/');
  }

  // Check if a dependency file exists and fetch it
  async tryFetchDependency(dependencyPath, baseRepoInfo, verbose = true) {
    // Skip if already processed or known to be external
    if (this.processedDependencies.has(dependencyPath) || 
        this.failedDependencies.has(dependencyPath) ||
        this.isExternalDependency(dependencyPath)) {
      return null;
    }
    
    const potentialUrls = this.resolveDependencyPaths(dependencyPath, baseRepoInfo);
    
    if (potentialUrls.length === 0) {
      if (verbose) console.log(`  ⚠️  External dependency (skipped): ${dependencyPath}`);
      this.failedDependencies.add(dependencyPath);
      return null;
    }
    
    if (verbose) console.log(`\n  🔍 Resolving: ${dependencyPath}`);
    
    for (const url of potentialUrls) {
      try {
        if (verbose) console.log(`    Trying: ${this.shortenUrl(url)}`);
        const fileData = await this.fetchSourceCode(url);
        
        if (verbose) console.log(`    ✅ Found: ${fileData.filename}`);
        
        // Mark as processed
        this.processedDependencies.add(dependencyPath);
        this.resolvedFiles.set(dependencyPath, fileData);
        
        return fileData;
      } catch (error) {
        // Continue to next potential URL
        continue;
      }
    }
    
    if (verbose) console.log(`    ❌ Could not resolve: ${dependencyPath}`);
    this.failedDependencies.add(dependencyPath);
    return null;
  }

  // Shorten URL for cleaner logging
  shortenUrl(url) {
    try {
      const urlObj = new URL(url);
      const pathParts = urlObj.pathname.split('/');
      if (pathParts.length > 5) {
        return `.../${pathParts.slice(-2).join('/')}`;
      }
      return url;
    } catch {
      return url;
    }
  }

  // Batch resolve multiple dependencies
  async resolveDependencies(dependencies, baseRepoInfo, verbose = true) {
    const resolvedFiles = [];
    const failedDependencies = [];
    
    if (verbose && dependencies.length > 0) {
      console.log(`\n📦 Resolving ${dependencies.length} dependencies...`);
    }
    
    for (const dependency of dependencies) {
      try {
        const fileData = await this.tryFetchDependency(dependency, baseRepoInfo, verbose);
        if (fileData) {
          resolvedFiles.push(fileData);
        } else {
          failedDependencies.push(dependency);
        }
      } catch (error) {
        if (verbose) console.log(`  ❌ Error resolving ${dependency}: ${error.message}`);
        failedDependencies.push(dependency);
      }
    }
    
    if (verbose) {
      console.log(`\n📊 Resolution Summary:`);
      console.log(`  ✅ Resolved: ${resolvedFiles.length}`);
      console.log(`  ❌ Failed: ${failedDependencies.length}`);
    }
    
    return {
      resolved: resolvedFiles,
      failed: failedDependencies,
      processedCount: this.processedDependencies.size,
      failedCount: this.failedDependencies.size
    };
  }

  // Recursively resolve dependencies with depth control
  async resolveRecursively(initialDependencies, baseRepoInfo, maxDepth = 3, verbose = true) {
    let currentDependencies = [...initialDependencies];
    let allResolvedFiles = [];
    let depth = 0;
    
    while (currentDependencies.length > 0 && depth < maxDepth) {
      depth++;
      
      if (verbose) {
        console.log(`\n🔄 Depth ${depth}/${maxDepth}: Processing ${currentDependencies.length} dependencies`);
      }
      
      const result = await this.resolveDependencies(currentDependencies, baseRepoInfo, verbose);
      allResolvedFiles.push(...result.resolved);
      
      // Extract new dependencies from resolved files (this would need parser integration)
      // For now, we'll break after first iteration - the main analyzer will handle recursion
      break;
    }
    
    return {
      resolved: allResolvedFiles,
      failed: Array.from(this.failedDependencies),
      totalProcessed: this.processedDependencies.size,
      totalFailed: this.failedDependencies.size,
      maxDepthReached: depth >= maxDepth
    };
  }

  // Get resolution statistics
  getStats() {
    return {
      processedDependencies: Array.from(this.processedDependencies),
      failedDependencies: Array.from(this.failedDependencies),
      resolvedFiles: Array.from(this.resolvedFiles.keys()),
      totalProcessed: this.processedDependencies.size,
      totalFailed: this.failedDependencies.size,
      successRate: this.processedDependencies.size / 
        (this.processedDependencies.size + this.failedDependencies.size) || 0
    };
  }

  // Reset state for new analysis
  reset() {
    this.processedDependencies.clear();
    this.failedDependencies.clear();
    this.resolvedFiles.clear();
  }

  // Check if file is a Solidity file
  isSolidityFile(filename) {
    return filename.toLowerCase().endsWith('.sol');
  }
}

module.exports = DependencyResolver;