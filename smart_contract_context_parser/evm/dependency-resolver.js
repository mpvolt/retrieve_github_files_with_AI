const axios = require('axios');
const path = require('path');
const { URL } = require('url');

class DependencyResolver {
  constructor() {
    this.processedDependencies = new Set(); // Track processed dependencies to avoid duplicates
    this.failedDependencies = new Set(); // Track dependencies that couldn't be resolved
    this.resolvedFiles = new Map(); // dependency path -> file data
    
    // Bind methods to ensure proper context
    this.isExternalDependency = this.isExternalDependency.bind(this);
    this.resolveDependencyPaths = this.resolveDependencyPaths.bind(this);
    this.tryFetchDependency = this.tryFetchDependency.bind(this);
    this.resolveDependencies = this.resolveDependencies.bind(this);
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

  // Check if dependency is external (can't be resolved in same repo)
  isExternalDependency(dependencyPath) {
    // Avoid circular reference - check patterns directly first
    const externalPatterns = [
      /^@openzeppelin\//, // OpenZeppelin packages (npm style)
      /^@chainlink\//, // Chainlink packages
      /^hardhat\//, // Hardhat imports
      /^node_modules\//, // Node modules
      /^npm:/, // NPM packages
      /^https?:\/\//, // HTTP URLs
      /^ipfs:\/\//, // IPFS URLs
    ];
    
    // If it matches known external patterns, check if we can resolve it through common libraries
    const isExternalPattern = externalPatterns.some(pattern => pattern.test(dependencyPath));
    if (isExternalPattern) {
      return true; // These are truly external
    }
    
    // For other patterns, check if we can resolve them through common libraries
    const commonLibraryUrls = this.tryResolveCommonLibrariesSafe(dependencyPath);
    if (commonLibraryUrls.length > 0) {
      return false; // We can resolve it, so it's not truly "external"
    }
    
    return false; // Default to treating as local dependency
  }

  // Safe version of tryResolveCommonLibraries that doesn't call isExternalDependency
  tryResolveCommonLibrariesSafe(dependencyPath) {
    const commonLibraries = {
      // Solady library
      'solady/': 'https://github.com/Vectorized/solady/blob/main/',
      
      // OpenZeppelin (if not already handled)
      'openzeppelin-contracts/': 'https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/',
      
      // Solmate library
      'solmate/': 'https://github.com/transmissions11/solmate/blob/main/',
      
      // Foundry standard library
      'forge-std/': 'https://github.com/foundry-rs/forge-std/blob/master/',
      
      // Chainlink contracts
      'chainlink/': 'https://github.com/smartcontractkit/chainlink/blob/develop/',
      
      // Uniswap contracts
      'uniswap/': 'https://github.com/Uniswap/v3-core/blob/main/',
    };
    
    // Check if dependency matches any common library pattern
    for (const [prefix, baseUrl] of Object.entries(commonLibraries)) {
      if (dependencyPath.startsWith(prefix)) {
        if (baseUrl) {
          // Direct mapping to known repository
          const relativePath = dependencyPath.substring(prefix.length);
          const fullUrl = `${baseUrl}${relativePath}`;
          
          // Convert to GitHub blob URL format
          const blobUrl = this.convertRawToGitHubUrl(fullUrl);
          return [blobUrl];
        } else {
          // Try multiple common repositories
          return this.tryMultipleCommonRepos(dependencyPath);
        }
      }
    }
    
    // Check for specific well-known contracts by name
    const wellKnownContracts = this.resolveWellKnownContracts(dependencyPath);
    if (wellKnownContracts.length > 0) {
      return wellKnownContracts;
    }
    
    return [];
  }

  // Try to resolve common Solidity libraries
  tryResolveCommonLibraries(dependencyPath) {
    return this.tryResolveCommonLibrariesSafe(dependencyPath);
  }

  // Convert raw GitHub URL to blob URL
  convertRawToGitHubUrl(rawUrl) {
    try {
      // Convert raw.githubusercontent.com URL back to github.com blob URL
      if (rawUrl.includes('raw.githubusercontent.com')) {
        const url = new URL(rawUrl);
        const pathParts = url.pathname.split('/');
        // Format: /owner/repo/branch/path...
        if (pathParts.length >= 4) {
          const owner = pathParts[1];
          const repo = pathParts[2];
          const branch = pathParts[3];
          const filePath = pathParts.slice(4).join('/');
          return `https://github.com/${owner}/${repo}/blob/${branch}/${filePath}`;
        }
      }
      
      // If it's already a blob URL or other format, return as is
      return rawUrl;
    } catch {
      return rawUrl;
    }
  }

  // Try multiple common repositories for generic paths
  tryMultipleCommonRepos(dependencyPath) {
    const commonRepos = [
      'https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/',
      'https://github.com/Vectorized/solady/blob/main/',
      'https://github.com/transmissions11/solmate/blob/main/',
      'https://github.com/foundry-rs/forge-std/blob/master/'
    ];
    
    return commonRepos.map(baseUrl => {
      // Try both with and without 'src' prefix for libraries like solady
      const urls = [
        `${baseUrl}${dependencyPath}`,
        `${baseUrl}src/${dependencyPath}`,
        `${baseUrl}contracts/${dependencyPath}`
      ];
      
      return urls;
    }).flat();
  }

  // Resolve well-known contract names to their canonical locations
  resolveWellKnownContracts(dependencyPath) {
    const fileName = dependencyPath.split('/').pop();
    
    const wellKnownContracts = {
      'Ownable.sol': [
        'https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable.sol',
        'https://github.com/Vectorized/solady/blob/main/src/auth/Ownable.sol'
      ],
      'ERC20.sol': [
        'https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/ERC20.sol',
        'https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC20.sol'
      ],
      'ERC721.sol': [
        'https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol',
        'https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC721.sol'
      ],
      'ReentrancyGuard.sol': [
        'https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/ReentrancyGuard.sol',
        'https://github.com/transmissions11/solmate/blob/main/src/utils/ReentrancyGuard.sol'
      ],
      'SafeTransferLib.sol': [
        'https://github.com/transmissions11/solmate/blob/main/src/utils/SafeTransferLib.sol',
        'https://github.com/Vectorized/solady/blob/main/src/utils/SafeTransferLib.sol'
      ]
    };
    
    return wellKnownContracts[fileName] || [];
  }

  // Generate potential file paths for a dependency
  resolveDependencyPaths(dependencyPath, baseRepoInfo) {
    if (!baseRepoInfo) return [];
    
    const { owner, repo, branch } = baseRepoInfo;
    const potentialPaths = [];
    
    // Clean up the dependency path
    const cleanPath = dependencyPath.replace(/^["']|["']$/g, ''); // Remove quotes
    
    // Check for common external libraries that we can try to resolve
    const commonLibraryUrls = this.tryResolveCommonLibraries(cleanPath);
    if (commonLibraryUrls.length > 0) {
      return commonLibraryUrls;
    }
    
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
    // Skip if already processed
    if (this.processedDependencies.has(dependencyPath) || 
        this.failedDependencies.has(dependencyPath)) {
      return null;
    }

    // Check if external
    const isExternal = this.isExternalDependency(dependencyPath);
    if (isExternal) {
      if (verbose) console.log(`  ⚠️  External dependency (skipped): ${dependencyPath}`);
      this.failedDependencies.add(dependencyPath);
      return null;
    }
    
    const potentialUrls = this.resolveDependencyPaths(dependencyPath, baseRepoInfo);
    
    if (potentialUrls.length === 0) {
      if (verbose) console.log(`  ⚠️  No resolution paths found: ${dependencyPath}`);
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