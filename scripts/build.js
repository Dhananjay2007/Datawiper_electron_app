#!/usr/bin/env node
/**
 * Build Script for Secure Wipe Dashboard
 * Compiles C++ addon and prepares the application for distribution
 */

const fs = require('fs-extra');
const path = require('path');
const { spawn, exec } = require('child_process');
const os = require('os');

class BuildManager {
  constructor() {
    this.projectRoot = process.cwd();
    this.buildDir = path.join(this.projectRoot, 'build');
    this.srcDir = path.join(this.projectRoot, 'src');
    this.nodeModulesDir = path.join(this.projectRoot, 'node_modules');
    
    this.platform = os.platform();
    this.arch = os.arch();
    
    console.log(`Building for ${this.platform}-${this.arch}`);
  }

  async checkPrerequisites() {
    console.log('Checking build prerequisites...');
    
    // Check Node.js version
    const nodeVersion = process.version;
    console.log(`Node.js version: ${nodeVersion}`);
    
    // Check for Python
    try {
      const pythonVersion = await this.runCommand('python', ['--version'], { timeout: 10000 });
      console.log(`Python version: ${pythonVersion.stdout.trim()}`);
    } catch (error) {
      console.warn('Python not found in PATH, checking python3...');
      try {
        const python3Version = await this.runCommand('python3', ['--version'], { timeout: 10000 });
        console.log(`Python3 version: ${python3Version.stdout.trim()}`);
      } catch (error2) {
        throw new Error('Python is required for building. Please install Python 3.x');
      }
    }
    
    // Check for C++ compiler
    if (this.platform === 'win32') {
      console.log('Checking for Visual Studio Build Tools...');
      try {
        await this.runCommand('where', ['cl']);
        console.log('Visual Studio Build Tools found');
      } catch (error) {
        console.warn('Visual Studio Build Tools not found in PATH');
        console.warn('Please install Visual Studio Build Tools or Visual Studio Community');
      }
    } else {
      console.log('Checking for C++ compiler...');
      try {
        const gccVersion = await this.runCommand('gcc', ['--version']);
        console.log(`GCC found: ${gccVersion.stdout.split('\\n')[0]}`);
      } catch (error) {
        try {
          const clangVersion = await this.runCommand('clang', ['--version']);
          console.log(`Clang found: ${clangVersion.stdout.split('\\n')[0]}`);
        } catch (error2) {
          throw new Error('C++ compiler not found. Please install GCC or Clang');
        }
      }
    }
    
    // Check for node-gyp
    console.log('Checking for node-gyp...');
    try {
      const nodeGypVersion = await this.runCommand('npx', ['node-gyp', '--version']);
      console.log(`node-gyp version: ${nodeGypVersion.stdout.trim()}`);
    } catch (error) {
      console.log('Installing node-gyp...');
      await this.runCommand('npm', ['install', '-g', 'node-gyp']);
    }
  }

  async installDependencies() {
    console.log('Installing Node.js dependencies...');
    
    if (!fs.existsSync(this.nodeModulesDir)) {
      await this.runCommand('npm', ['install'], { cwd: this.projectRoot });
    } else {
      console.log('Node modules already installed');
    }
    
    // Install Python dependencies
    console.log('Installing Python dependencies...');
    const pythonDeps = [
      'cryptography',
      'psutil',
      'py-cpuinfo'
    ];
    
    for (const dep of pythonDeps) {
      try {
        await this.runCommand('pip', ['install', dep]);
      } catch (error) {
        try {
          await this.runCommand('pip3', ['install', dep]);
        } catch (error2) {
          console.warn(`Failed to install Python dependency: ${dep}`);
        }
      }
    }
  }

  async buildCppAddon() {
    console.log('Building C++ addon...');
    
    // Ensure build directory exists
    await fs.ensureDir(this.buildDir);
    
    try {
      // Configure
      console.log('Configuring C++ build...');
      await this.runCommand('npx', ['node-gyp', 'configure'], { cwd: this.projectRoot });
      
      // Build
      console.log('Compiling C++ addon...');
      await this.runCommand('npx', ['node-gyp', 'build'], { cwd: this.projectRoot });
      
      // Verify the addon was built
      const addonPath = path.join(this.buildDir, 'Release', 'secure_wiper.node');
      if (fs.existsSync(addonPath)) {
        console.log('C++ addon built successfully');
        return true;
      } else {
        throw new Error('C++ addon file not found after build');
      }
      
    } catch (error) {
      console.error('C++ addon build failed:', error.message);
      console.warn('Application will run without native acceleration');
      return false;
    }
  }

  async buildCppStandalone() {
    console.log('Building standalone C++ executable...');
    
    const cppSrcDir = path.join(this.srcDir, 'cpp');
    const outputName = this.platform === 'win32' ? 'secure_wiper.exe' : 'secure_wiper';
    const outputPath = path.join(this.buildDir, outputName);
    
    // Source files
    const sourceFiles = [
      path.join(cppSrcDir, 'secure_wiper.cpp')
    ];
    
    // Compiler flags
    const flags = ['-std=c++17', '-O2'];
    if (this.platform !== 'win32') {
      flags.push('-pthread');
    }
    
    // Libraries
    const libs = [];
    if (this.platform === 'win32') {
      libs.push('-ladvapi32', '-lkernel32', '-luser32');
    }
    
    try {
      const compiler = this.platform === 'win32' ? 'cl' : 'g++';
      const args = [...flags, ...sourceFiles, '-o', outputPath, ...libs];
      
      if (this.platform === 'win32') {
        // Visual Studio compiler syntax
        args.splice(0, flags.length, '/std:c++17', '/O2');
        const outputIndex = args.indexOf('-o');
        if (outputIndex >= 0) {
          args[outputIndex] = '/Fe:';
          args[outputIndex + 1] = outputPath;
        }
      }
      
      console.log(`Compiling with ${compiler}...`);
      await this.runCommand(compiler, args, { cwd: cppSrcDir });
      
      if (fs.existsSync(outputPath)) {
        console.log('Standalone C++ executable built successfully');
        return true;
      } else {
        throw new Error('Executable not found after compilation');
      }
      
    } catch (error) {
      console.error('Standalone C++ build failed:', error.message);
      console.warn('Will use Python fallback for wipe operations');
      return false;
    }
  }

  async preparePythonScripts() {
    console.log('Preparing Python scripts...');
    
    const pythonSrcDir = path.join(this.srcDir, 'python');
    const scripts = ['verification.py', 'certificate_gen.py', 'device_fingerprint.py', 'automation.py'];
    
    for (const script of scripts) {
      const srcPath = path.join(pythonSrcDir, script);
      if (fs.existsSync(srcPath)) {
        // Make executable on Unix-like systems
        if (this.platform !== 'win32') {
          await fs.chmod(srcPath, '755');
        }
        console.log(`Prepared ${script}`);
      } else {
        console.warn(`Python script not found: ${script}`);
      }
    }
  }

  async createDirectories() {
    console.log('Creating necessary directories...');
    
    const dirs = [
      path.join(this.srcDir, 'assets', 'logs'),
      path.join(this.srcDir, 'assets', 'reports'),
      path.join(this.srcDir, 'assets', 'certificates'),
      path.join(this.srcDir, 'assets', 'icons'),
      this.buildDir
    ];
    
    for (const dir of dirs) {
      await fs.ensureDir(dir);
      console.log(`Created directory: ${path.relative(this.projectRoot, dir)}`);
    }
  }

  async validateBuild() {
    console.log('Validating build...');
    
    const criticalFiles = [
      'main.js',
      'preload.js',
      'package.json',
      'src/renderer/index.html',
      'src/renderer/styles.css',
      'src/renderer/renderer.js'
    ];
    
    for (const file of criticalFiles) {
      const filePath = path.join(this.projectRoot, file);
      if (!fs.existsSync(filePath)) {
        throw new Error(`Critical file missing: ${file}`);
      }
    }
    
    // Check if C++ addon built successfully
    const addonPath = path.join(this.buildDir, 'Release', 'secure_wiper.node');
    if (fs.existsSync(addonPath)) {
      console.log('✓ C++ addon available');
    } else {
      console.log('⚠ C++ addon not available (will use fallbacks)');
    }
    
    // Check Python scripts
    const pythonSrcDir = path.join(this.srcDir, 'python');
    const pythonScripts = ['verification.py', 'certificate_gen.py', 'automation.py'];
    
    for (const script of pythonScripts) {
      const scriptPath = path.join(pythonSrcDir, script);
      if (fs.existsSync(scriptPath)) {
        console.log(`✓ ${script} available`);
      } else {
        console.log(`⚠ ${script} missing`);
      }
    }
    
    console.log('Build validation completed');
  }

  async runCommand(command, args = [], options = {}) {
    return new Promise((resolve, reject) => {
      const defaultOptions = {
        stdio: 'pipe',
        timeout: 300000, // 5 minutes
        ...options
      };
      
      const child = spawn(command, args, defaultOptions);
      let stdout = '';
      let stderr = '';
      
      if (child.stdout) {
        child.stdout.on('data', (data) => {
          stdout += data.toString();
        });
      }
      
      if (child.stderr) {
        child.stderr.on('data', (data) => {
          stderr += data.toString();
        });
      }
      
      child.on('close', (code) => {
        if (code === 0) {
          resolve({ stdout, stderr, code });
        } else {
          reject(new Error(`Command failed with code ${code}: ${stderr || stdout}`));
        }
      });
      
      child.on('error', (error) => {
        reject(error);
      });
      
      // Handle timeout
      if (defaultOptions.timeout) {
        setTimeout(() => {
          child.kill('SIGTERM');
          reject(new Error(`Command timed out after ${defaultOptions.timeout}ms`));
        }, defaultOptions.timeout);
      }
    });
  }

  async build() {
    try {
      console.log('Starting build process...');
      console.log('='.repeat(50));
      
      // Check prerequisites
      await this.checkPrerequisites();
      
      // Create directories
      await this.createDirectories();
      
      // Install dependencies
      await this.installDependencies();
      
      // Build C++ components
      await this.buildCppAddon();
      await this.buildCppStandalone();
      
      // Prepare Python scripts
      await this.preparePythonScripts();
      
      // Validate build
      await this.validateBuild();
      
      console.log('='.repeat(50));
      console.log('Build completed successfully!');
      console.log('');
      console.log('Next steps:');
      console.log('  npm start          - Start the development server');
      console.log('  npm run dist       - Create distribution package');
      console.log('');
      
      return true;
      
    } catch (error) {
      console.error('Build failed:', error.message);
      console.error('');
      console.error('Please check the error above and retry.');
      console.error('For help, visit: https://github.com/infoinvaders/secure-wipe-dashboard/issues');
      
      process.exit(1);
    }
  }
}

// Run build if called directly
if (require.main === module) {
  const buildManager = new BuildManager();
  buildManager.build().catch(console.error);
}

module.exports = BuildManager;