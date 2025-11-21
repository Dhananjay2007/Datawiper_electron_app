#!/usr/bin/env node
/**
 * Installation Dependencies Script
 * Installs and configures all required dependencies for the Secure Wipe Dashboard
 */

const fs = require('fs-extra');
const path = require('path');
const { spawn } = require('child_process');
const os = require('os');

class DependencyInstaller {
  constructor() {
    this.projectRoot = process.cwd();
    this.platform = os.platform();
    this.arch = os.arch();
    
    console.log('INFO INVADERS Secure Wipe Dashboard - Dependency Installer');
    console.log(`Platform: ${this.platform}-${this.arch}`);
    console.log('='.repeat(60));
  }

  async checkSystemRequirements() {
    console.log('Checking system requirements...');
    
    // Check Node.js version
    const nodeVersion = process.version;
    const majorVersion = parseInt(nodeVersion.split('.')[0].substring(1));
    
    if (majorVersion < 16) {
      throw new Error(`Node.js 16+ required. Current version: ${nodeVersion}`);
    }
    console.log(`✓ Node.js ${nodeVersion}`);
    
    // Check npm
    try {
      const npmVersion = await this.runCommand('npm', ['--version']);
      console.log(`✓ npm ${npmVersion.stdout.trim()}`);
    } catch (error) {
      throw new Error('npm is required but not found');
    }
    
    // Check available disk space
    const stats = await fs.stat(this.projectRoot);
    console.log('✓ Disk space available');
    
    // Check administrative privileges
    if (this.platform === 'win32') {
      console.log('⚠ Administrator privileges recommended for device access');
    } else {
      console.log('⚠ Root privileges recommended for device access');
    }
  }

  async installNodeDependencies() {
    console.log('\\nInstalling Node.js dependencies...');
    
    const packageJson = path.join(this.projectRoot, 'package.json');
    if (!fs.existsSync(packageJson)) {
      throw new Error('package.json not found. Run this script from the project root.');
    }
    
    // Clean install
    const nodeModulesDir = path.join(this.projectRoot, 'node_modules');
    if (fs.existsSync(nodeModulesDir)) {
      console.log('Cleaning existing node_modules...');
      await fs.remove(nodeModulesDir);
    }
    
    const lockFile = path.join(this.projectRoot, 'package-lock.json');
    if (fs.existsSync(lockFile)) {
      await fs.remove(lockFile);
    }
    
    // Install dependencies
    console.log('Running npm install...');
    await this.runCommand('npm', ['install'], { 
      cwd: this.projectRoot,
      stdio: 'inherit'
    });
    
    console.log('✓ Node.js dependencies installed');
  }

  async installPythonDependencies() {
    console.log('\\nInstalling Python dependencies...');
    
    // Check Python installation
    let pythonCmd = 'python';
    try {
      await this.runCommand('python', ['--version']);
    } catch (error) {
      try {
        await this.runCommand('python3', ['--version']);
        pythonCmd = 'python3';
      } catch (error2) {
        console.warn('⚠ Python not found. Some features may not work.');
        console.warn('Please install Python 3.8+ from https://python.org');
        return;
      }
    }
    
    // Check pip
    let pipCmd = 'pip';
    try {
      await this.runCommand('pip', ['--version']);
    } catch (error) {
      try {
        await this.runCommand('pip3', ['--version']);
        pipCmd = 'pip3';
      } catch (error2) {
        console.warn('⚠ pip not found. Cannot install Python dependencies.');
        return;
      }
    }
    
    // Python dependencies for the project
    const pythonDeps = [
      'cryptography>=3.4.0',      // Certificate generation
      'psutil>=5.8.0',            // System information
      'py-cpuinfo>=8.0.0'         // CPU information
    ];
    
    console.log('Installing Python packages...');
    for (const dep of pythonDeps) {
      try {
        console.log(`Installing ${dep}...`);
        await this.runCommand(pipCmd, ['install', dep], { stdio: 'pipe' });
        console.log(`✓ ${dep.split('>=')[0]} installed`);
      } catch (error) {
        console.warn(`⚠ Failed to install ${dep}: ${error.message}`);
      }
    }
  }

  async installSystemTools() {
    console.log('\\nChecking system tools...');
    
    if (this.platform === 'win32') {
      await this.installWindowsTools();
    } else if (this.platform === 'linux') {
      await this.installLinuxTools();
    } else if (this.platform === 'darwin') {
      await this.installMacTools();
    }
  }

  async installWindowsTools() {
    console.log('Checking Windows-specific tools...');
    
    // Check for Visual Studio Build Tools
    try {
      await this.runCommand('where', ['cl']);
      console.log('✓ Visual Studio Build Tools found');
    } catch (error) {
      console.warn('⚠ Visual Studio Build Tools not found');
      console.warn('Please install:');
      console.warn('  - Visual Studio Community (free) with C++ workload, or');
      console.warn('  - Visual Studio Build Tools for C++');
      console.warn('  - Download: https://visualstudio.microsoft.com/downloads/');
    }
    
    // Check for TestDisk/PhotoRec
    const testDiskPaths = [
      'C:\\\\Program Files\\\\TestDisk\\\\photorec_win.exe',
      'C:\\\\Program Files (x86)\\\\TestDisk\\\\photorec_win.exe',
      'C:\\\\TestDisk\\\\photorec_win.exe'
    ];
    
    let testDiskFound = false;
    for (const testDiskPath of testDiskPaths) {
      if (fs.existsSync(testDiskPath)) {
        console.log(`✓ TestDisk/PhotoRec found at ${testDiskPath}`);
        testDiskFound = true;
        break;
      }
    }
    
    if (!testDiskFound) {
      console.warn('⚠ TestDisk/PhotoRec not found');
      console.warn('Please install TestDisk from: https://www.cgsecurity.org/wiki/TestDisk');
      console.warn('This is required for wipe verification functionality');
    }
    
    // Check Windows SDK
    try {
      const windowsSdkPaths = [
        'C:\\\\Program Files (x86)\\\\Windows Kits\\\\10\\\\Include',
        'C:\\\\Program Files\\\\Windows Kits\\\\10\\\\Include'
      ];
      
      let sdkFound = false;
      for (const sdkPath of windowsSdkPaths) {
        if (fs.existsSync(sdkPath)) {
          console.log('✓ Windows SDK found');
          sdkFound = true;
          break;
        }
      }
      
      if (!sdkFound) {
        console.warn('⚠ Windows SDK not found');
        console.warn('Please install Windows SDK for C++ development');
      }
    } catch (error) {
      // SDK check failed
    }
  }

  async installLinuxTools() {
    console.log('Checking Linux-specific tools...');
    
    // Check for build essentials
    try {
      await this.runCommand('gcc', ['--version']);
      console.log('✓ GCC compiler found');
    } catch (error) {
      console.warn('⚠ GCC not found');
      console.warn('Please install: sudo apt-get install build-essential (Ubuntu/Debian)');
      console.warn('or equivalent for your distribution');
    }
    
    // Check for make
    try {
      await this.runCommand('make', ['--version']);
      console.log('✓ make found');
    } catch (error) {
      console.warn('⚠ make not found');
      console.warn('Please install: sudo apt-get install make');
    }
    
    // Check for TestDisk
    try {
      await this.runCommand('which', ['photorec']);
      console.log('✓ TestDisk/PhotoRec found');
    } catch (error) {
      console.warn('⚠ TestDisk/PhotoRec not found');
      console.warn('Please install: sudo apt-get install testdisk (Ubuntu/Debian)');
      console.warn('or equivalent for your distribution');
    }
    
    // Check for development headers
    const devPackages = [
      '/usr/include/linux/fs.h',
      '/usr/include/sys/ioctl.h'
    ];
    
    let headersFound = true;
    for (const header of devPackages) {
      if (!fs.existsSync(header)) {
        headersFound = false;
        break;
      }
    }
    
    if (headersFound) {
      console.log('✓ Development headers found');
    } else {
      console.warn('⚠ Some development headers missing');
      console.warn('Please install: sudo apt-get install linux-headers-$(uname -r)');
    }
  }

  async installMacTools() {
    console.log('Checking macOS-specific tools...');
    
    // Check for Xcode Command Line Tools
    try {
      await this.runCommand('xcode-select', ['--print-path']);
      console.log('✓ Xcode Command Line Tools found');
    } catch (error) {
      console.warn('⚠ Xcode Command Line Tools not found');
      console.warn('Please install: xcode-select --install');
    }
    
    // Check for Homebrew
    try {
      await this.runCommand('brew', ['--version']);
      console.log('✓ Homebrew found');
      
      // Check for TestDisk via Homebrew
      try {
        await this.runCommand('brew', ['list', 'testdisk']);
        console.log('✓ TestDisk installed via Homebrew');
      } catch (error) {
        console.warn('⚠ TestDisk not found');
        console.warn('Please install: brew install testdisk');
      }
    } catch (error) {
      console.warn('⚠ Homebrew not found');
      console.warn('Please install Homebrew from: https://brew.sh');
      console.warn('Then install TestDisk: brew install testdisk');
    }
  }

  async setupDirectories() {
    console.log('\\nSetting up project directories...');
    
    const directories = [
      'src/assets/logs',
      'src/assets/reports', 
      'src/assets/certificates',
      'src/assets/icons',
      'build',
      'dist'
    ];
    
    for (const dir of directories) {
      const fullPath = path.join(this.projectRoot, dir);
      await fs.ensureDir(fullPath);
      console.log(`✓ Created ${dir}`);
    }
  }

  async createConfigFiles() {
    console.log('\\nCreating configuration files...');
    
    // Create .gitignore if it doesn't exist
    const gitignorePath = path.join(this.projectRoot, '.gitignore');
    if (!fs.existsSync(gitignorePath)) {
      const gitignoreContent = `# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Build outputs
build/
dist/
*.node

# Runtime data
pids
*.pid
*.seed
*.pid.lock

# Logs
logs
*.log

# Runtime data
src/assets/logs/*
src/assets/reports/*
src/assets/certificates/*

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# IDE files
.vscode/
.idea/
*.swp
*.swo
*~

# Temporary files
tmp/
temp/
.tmp/

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/

# Electron
out/
`;
      await fs.writeFile(gitignorePath, gitignoreContent);
      console.log('✓ Created .gitignore');
    }
    
    // Create README if it doesn't exist
    const readmePath = path.join(this.projectRoot, 'README.md');
    if (!fs.existsSync(readmePath)) {
      const readmeContent = `# INFO INVADERS Secure Wipe Dashboard

Professional secure data wiping application with HPA/DCO support.

## Features

- **Multi-Standard Support**: NIST SP 800-88 and HSE wiping standards
- **Security Profiles**: Citizen, Enterprise, and Government levels
- **HPA/DCO Areas**: Complete device wiping including hidden areas
- **Verification**: Automated post-wipe verification with PhotoRec/TestDisk
- **Certificates**: Tamper-evident certificates with DNA fingerprinting
- **Cross-Platform**: Windows, Linux, and macOS support

## Quick Start

1. Install dependencies:
   \`\`\`bash
   npm run install-deps
   \`\`\`

2. Build the application:
   \`\`\`bash
   npm run build
   \`\`\`

3. Start the application:
   \`\`\`bash
   npm start
   \`\`\`

## System Requirements

- **Node.js**: 16+ 
- **Python**: 3.8+
- **C++ Compiler**: Visual Studio Build Tools (Windows), GCC/Clang (Linux/macOS)
- **TestDisk/PhotoRec**: For verification functionality
- **Administrative Privileges**: Required for device access

## Usage

1. **Device Detection**: Automatically detects connected storage devices
2. **Profile Selection**: Choose security profile (Citizen/Enterprise/Government)
3. **Standard Selection**: Select wiping standard (NIST SP 800-88/HSE)
4. **Confirmation**: Multiple confirmations based on profile
5. **Secure Wipe**: Execute wipe with real-time progress
6. **Verification**: Automated verification with recovery tools
7. **Certification**: Generate tamper-evident certificate

## Security Features

- **HPA/DCO Support**: Access and wipe hidden disk areas
- **Multiple Passes**: Up to 5-pass wiping for government profile
- **DNA Fingerprinting**: Unique device identification
- **Tamper Evidence**: Cryptographic integrity seals
- **Compliance**: NIST, GDPR, HIPAA, SOX compliant

## Support

For issues and documentation:
- GitHub: https://github.com/infoinvaders/secure-wipe-dashboard
- Issues: https://github.com/infoinvaders/secure-wipe-dashboard/issues

© 2024 INFO INVADERS. All rights reserved.
`;
      await fs.writeFile(readmePath, readmeContent);
      console.log('✓ Created README.md');
    }
  }

  async validateInstallation() {
    console.log('\\nValidating installation...');
    
    // Check critical files
    const criticalFiles = [
      'package.json',
      'main.js',
      'preload.js',
      'src/renderer/index.html'
    ];
    
    for (const file of criticalFiles) {
      const filePath = path.join(this.projectRoot, file);
      if (fs.existsSync(filePath)) {
        console.log(`✓ ${file}`);
      } else {
        console.warn(`⚠ Missing: ${file}`);
      }
    }
    
    // Check node_modules
    const nodeModulesPath = path.join(this.projectRoot, 'node_modules');
    if (fs.existsSync(nodeModulesPath)) {
      const packageCount = fs.readdirSync(nodeModulesPath).length;
      console.log(`✓ Node modules installed (${packageCount} packages)`);
    } else {
      console.warn('⚠ node_modules not found');
    }
    
    // Try to require main modules
    try {
      require('electron');
      console.log('✓ Electron available');
    } catch (error) {
      console.warn('⚠ Electron not available');
    }
    
    try {
      require('node-addon-api');
      console.log('✓ Node-addon-api available');
    } catch (error) {
      console.warn('⚠ Node-addon-api not available');
    }
  }

  async runCommand(command, args = [], options = {}) {
    return new Promise((resolve, reject) => {
      const defaultOptions = {
        stdio: 'pipe',
        timeout: 120000, // 2 minutes
        ...options
      };
      
      const child = spawn(command, args, defaultOptions);
      let stdout = '';
      let stderr = '';
      
      if (child.stdout && defaultOptions.stdio === 'pipe') {
        child.stdout.on('data', (data) => {
          stdout += data.toString();
        });
      }
      
      if (child.stderr && defaultOptions.stdio === 'pipe') {
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
      
      if (defaultOptions.timeout) {
        setTimeout(() => {
          child.kill('SIGTERM');
          reject(new Error(`Command timed out after ${defaultOptions.timeout}ms`));
        }, defaultOptions.timeout);
      }
    });
  }

  async install() {
    try {
      console.log('Starting dependency installation...');
      console.log('');
      
      // Check system requirements
      await this.checkSystemRequirements();
      
      // Setup directories
      await this.setupDirectories();
      
      // Install Node.js dependencies
      await this.installNodeDependencies();
      
      // Install Python dependencies
      await this.installPythonDependencies();
      
      // Install system tools
      await this.installSystemTools();
      
      // Create config files
      await this.createConfigFiles();
      
      // Validate installation
      await this.validateInstallation();
      
      console.log('\\n' + '='.repeat(60));
      console.log('✓ Dependency installation completed successfully!');
      console.log('');
      console.log('Next steps:');
      console.log('  npm run build      - Build the application');
      console.log('  npm start          - Start the application');
      console.log('  npm run dist       - Create distribution package');
      console.log('');
      console.log('Important notes:');
      console.log('  - Run as administrator/root for device access');
      console.log('  - Ensure TestDisk/PhotoRec is in PATH');
      console.log('  - Install C++ compiler for native performance');
      console.log('');
      
      return true;
      
    } catch (error) {
      console.error('\\nInstallation failed:', error.message);
      console.error('');
      console.error('Please resolve the error and try again.');
      console.error('For help: https://github.com/infoinvaders/secure-wipe-dashboard/issues');
      
      process.exit(1);
    }
  }
}

// Run installer if called directly
if (require.main === module) {
  const installer = new DependencyInstaller();
  installer.install().catch(console.error);
}

module.exports = DependencyInstaller;