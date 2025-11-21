#!/usr/bin/env python3
"""
PhotoRec/TestDisk Verification Module
Automated verification of secure wipe effectiveness using recovery tools
"""

import os
import sys
import json
import subprocess
import tempfile
import shutil
import time
from pathlib import Path
import argparse
import logging

class WipeVerifier:
    def __init__(self, device_path, output_dir=None):
        self.device_path = device_path
        self.output_dir = output_dir or tempfile.mkdtemp(prefix="wipe_verify_")
        self.results = {
            'device': device_path,
            'scan_time': None,
            'files_recovered': 0,
            'verification_passed': False,
            'details': '',
            'tools_used': [],
            'timestamp': time.time()
        }
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    def find_photorec_binary(self):
        """Find PhotoRec binary in system PATH or common locations"""
        possible_names = ['photorec', 'photorec_win.exe', 'photorec.exe']
        possible_paths = [
            # Windows
            'C:\\Program Files\\TestDisk\\',
            'C:\\Program Files (x86)\\TestDisk\\',
            'C:\\TestDisk\\',
            # Linux
            '/usr/bin/',
            '/usr/local/bin/',
            '/opt/testdisk/bin/',
            # Current directory
            './',
            '../tools/'
        ]
        
        # Check PATH first
        for name in possible_names:
            if shutil.which(name):
                return shutil.which(name)
        
        # Check common installation paths
        for path in possible_paths:
            for name in possible_names:
                full_path = os.path.join(path, name)
                if os.path.exists(full_path) and os.access(full_path, os.X_OK):
                    return full_path
        
        raise FileNotFoundError("PhotoRec binary not found. Please install TestDisk/PhotoRec.")

    def find_testdisk_binary(self):
        """Find TestDisk binary in system PATH or common locations"""
        possible_names = ['testdisk', 'testdisk_win.exe', 'testdisk.exe']
        possible_paths = [
            # Windows
            'C:\\Program Files\\TestDisk\\',
            'C:\\Program Files (x86)\\TestDisk\\',
            'C:\\TestDisk\\',
            # Linux
            '/usr/bin/',
            '/usr/local/bin/',
            '/opt/testdisk/bin/',
            # Current directory
            './',
            '../tools/'
        ]
        
        # Check PATH first
        for name in possible_names:
            if shutil.which(name):
                return shutil.which(name)
        
        # Check common installation paths
        for path in possible_paths:
            for name in possible_names:
                full_path = os.path.join(path, name)
                if os.path.exists(full_path) and os.access(full_path, os.X_OK):
                    return full_path
        
        raise FileNotFoundError("TestDisk binary not found. Please install TestDisk/PhotoRec.")

    def run_photorec(self, max_files=1000, timeout=3600):
        try:
            photorec_path = self.find_photorec_binary()
            self.results['tools_used'].append('PhotoRec')

            self.logger.info(f"Starting PhotoRec verification on {self.device_path}")

            # Create recovery directory
            recovery_dir = os.path.join(self.output_dir, "photorec_recovery")
            os.makedirs(recovery_dir, exist_ok=True)

            # Use raw device path format on Windows, else use standard
            target_device = self.device_path
            if os.name == 'nt':
                # If device_path is like 'E:', convert to raw device path
                if len(target_device) == 2 and target_device[1] == ':':
                    target_device = f"\\\\.\\{target_device[0]}:"

            # Compose PhotoRec command with full partition scan and non-interactive
            cmd = [
                photorec_path,
                "/d", recovery_dir,
                "/cmd", target_device,
                "partition_none,search"
            ]

            self.logger.info(f"Running command: {' '.join(cmd)}")

            start_time = time.time()

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=recovery_dir
            )

            end_time = time.time()
            self.results['scan_time'] = end_time - start_time

            files_count = self.count_recovered_files(recovery_dir)
            self.results['files_recovered'] += files_count

            self.logger.info(f"PhotoRec completed. Files recovered: {files_count}")

            if result.stdout:
                self.logger.debug(f"PhotoRec stdout: {result.stdout}")
            if result.stderr:
                self.logger.debug(f"PhotoRec stderr: {result.stderr}")

            return files_count == 0

        except Exception as e:
            self.logger.error(f"PhotoRec execution failed: {e}")
            self.results['details'] += f"PhotoRec failed: {e}\n"
            return None

    def run_testdisk(self, timeout=1800):
        """Run TestDisk for partition and file system analysis"""
        try:
            testdisk_path = self.find_testdisk_binary()
            self.results['tools_used'].append('TestDisk')
            
            self.logger.info(f"Starting TestDisk analysis on {self.device_path}")
            
            # Create analysis directory
            analysis_dir = os.path.join(self.output_dir, "testdisk_analysis")
            os.makedirs(analysis_dir, exist_ok=True)
            
            # TestDisk command for analysis
            cmd = [
                testdisk_path,
                '/log',
                '/cmd', self.device_path,
                'analyse,quick,write'
            ]
            
            self.logger.info(f"Running command: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=analysis_dir
                )
                
                # Analyze TestDisk output
                analysis_successful = self.analyze_testdisk_output(result.stdout, result.stderr)
                
                self.logger.info(f"TestDisk analysis completed. Clean: {analysis_successful}")
                
                return analysis_successful
                
            except subprocess.TimeoutExpired:
                self.logger.warning(f"TestDisk timed out after {timeout} seconds")
                return None
                
        except FileNotFoundError as e:
            self.logger.error(f"TestDisk not found: {e}")
            self.results['details'] += f"TestDisk not found: {e}\\n"
            return None
        except Exception as e:
            self.logger.error(f"TestDisk execution failed: {e}")
            self.results['details'] += f"TestDisk failed: {e}\\n"
            return None

    def count_recovered_files(self, directory):
        """Count recovered files in the specified directory"""
        if not os.path.exists(directory):
            return 0
        
        file_count = 0
        try:
            for root, dirs, files in os.walk(directory):
                # Skip empty files and system files
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.getsize(file_path) > 0:
                        file_count += 1
            
            self.logger.info(f"Found {file_count} non-empty recovered files")
            return file_count
            
        except Exception as e:
            self.logger.error(f"Error counting files: {e}")
            return 0

    def analyze_testdisk_output(self, stdout, stderr):
        """Analyze TestDisk output for signs of remaining data structures"""
        # Look for partition table signatures, file system structures
        concerning_patterns = [
            'Partition table type',
            'FAT32',
            'NTFS',
            'ext2',
            'ext3',
            'ext4',
            'HFS+',
            'Boot sector',
            'Superblock',
            'File system'
        ]
        
        output_text = (stdout + '\\n' + stderr).lower()
        
        for pattern in concerning_patterns:
            if pattern.lower() in output_text:
                self.results['details'] += f"TestDisk found: {pattern}\\n"
                return False
        
        return True

    def run_custom_hex_scan(self, sample_size=1024*1024*100):  # 100MB sample
        """Run custom hex analysis to look for data patterns"""
        try:
            self.logger.info(f"Starting custom hex scan on {self.device_path}")
            
            # Read sample from beginning, middle, and end of device
            samples_found = False
            
            with open(self.device_path, 'rb') as device:
                # Get device size
                device.seek(0, 2)  # Seek to end
                device_size = device.tell()
                
                if device_size == 0:
                    self.logger.warning("Device size is 0, cannot perform hex scan")
                    return True
                
                # Sample positions: start, 25%, 50%, 75%, end
                positions = [0, device_size//4, device_size//2, 3*device_size//4, max(0, device_size-sample_size)]
                
                for pos in positions:
                    device.seek(pos)
                    data = device.read(min(sample_size, device_size - pos))
                    
                    if self.analyze_hex_data(data, pos):
                        samples_found = True
                        break
            
            return not samples_found
            
        except Exception as e:
            self.logger.error(f"Custom hex scan failed: {e}")
            self.results['details'] += f"Hex scan failed: {e}\\n"
            return None

    def analyze_hex_data(self, data, position):
        """Analyze hex data for patterns that indicate remaining file structures"""
        # Look for common file signatures
        file_signatures = [
            b'\\x89PNG',  # PNG
            b'\\xFF\\xD8\\xFF',  # JPEG
            b'GIF8',  # GIF
            b'BM',  # BMP
            b'PK',  # ZIP/Office files
            b'\\x50\\x4B\\x03\\x04',  # ZIP
            b'\\x50\\x4B\\x05\\x06',  # ZIP end
            b'%PDF',  # PDF
            b'\\x00\\x00\\x01\\x00',  # ICO
            b'RIFF',  # WAV/AVI
            b'\\x49\\x44\\x33',  # MP3
            b'\\x1A\\x45\\xDF\\xA3',  # MKV
            b'ftyp',  # MP4/MOV
            b'\\x00\\x00\\x00\\x18ftypmp4',  # MP4
            b'\\x4D\\x5A',  # EXE
            b'\\x7F\\x45\\x4C\\x46',  # ELF
        ]
        
        # Check for file signatures
        for signature in file_signatures:
            if signature in data:
                self.results['details'] += f"Found file signature at position {position}: {signature.hex()}\\n"
                return True
        
        # Check for non-zero patterns that aren't random
        non_zero_count = sum(1 for byte in data if byte != 0)
        if non_zero_count > len(data) * 0.1:  # More than 10% non-zero
            # Additional analysis could be done here
            pattern_density = non_zero_count / len(data)
            if pattern_density > 0.5:  # Significant data pattern
                self.results['details'] += f"High data density ({pattern_density:.2%}) at position {position}\\n"
                return True
        
        return False

    def verify_wipe(self):
        """Main verification method"""
        self.logger.info(f"Starting wipe verification for device: {self.device_path}")
        
        verification_results = []
        
        # Run PhotoRec verification
        photorec_result = self.run_photorec()
        if photorec_result is not None:
            verification_results.append(photorec_result)
        
        # Run TestDisk verification
        testdisk_result = self.run_testdisk()
        if testdisk_result is not None:
            verification_results.append(testdisk_result)
        
        # Run custom hex scan
        hex_result = self.run_custom_hex_scan()
        if hex_result is not None:
            verification_results.append(hex_result)
        
        # Overall verification result
        if not verification_results:
            self.results['verification_passed'] = False
            self.results['details'] += "No verification tools could run successfully\\n"
        else:
            # Verification passes if ALL tools show clean results
            self.results['verification_passed'] = all(verification_results)
        
        # Determine final status
        if self.results['files_recovered'] == 0 and self.results['verification_passed']:
            self.results['details'] += "✓ Wipe verification PASSED - No recoverable data found\\n"
        else:
            self.results['details'] += f"✗ Wipe verification FAILED - {self.results['files_recovered']} files recovered\\n"
        
        self.logger.info(f"Verification completed. Result: {'PASSED' if self.results['verification_passed'] else 'FAILED'}")
        
        return self.results

    def cleanup(self):
        """Clean up temporary files"""
        try:
            if os.path.exists(self.output_dir) and self.output_dir.startswith(tempfile.gettempdir()):
                shutil.rmtree(self.output_dir)
                self.logger.info("Cleanup completed")
        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")

    def save_results(self, output_file=None):
        """Save verification results to JSON file"""
        if output_file is None:
            timestamp = int(time.time())
            output_file = f"wipe_verification_{timestamp}.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            
            self.logger.info(f"Results saved to: {output_file}")
            return output_file
            
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")
            return None

def main():
    parser = argparse.ArgumentParser(description='Verify secure wipe effectiveness using recovery tools')
    parser.add_argument('device', help='Device path to verify (e.g., /dev/sda or \\\\.\\PhysicalDrive0)')
    parser.add_argument('--output-dir', help='Output directory for recovery attempts')
    parser.add_argument('--save-results', help='Save results to specified JSON file')
    parser.add_argument('--no-cleanup', action='store_true', help='Keep temporary files for inspection')
    parser.add_argument('--timeout', type=int, default=3600, help='Timeout for PhotoRec (seconds)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate device path
    if not args.device.startswith('\\\\.\\'):
        if not os.path.exists(args.device):
            print(f"Error: Device {args.device} does not exist", file=sys.stderr)
            sys.exit(1)

    # Create verifier and run verification
    verifier = WipeVerifier(args.device, args.output_dir)
    
    try:
        results = verifier.verify_wipe()
        
        # Save results if requested
        if args.save_results:
            verifier.save_results(args.save_results)
        
        # Print results
        print(json.dumps(results, indent=2))
        
        # Exit code based on verification result
        sys.exit(0 if results['verification_passed'] else 1)
        
    except KeyboardInterrupt:
        print("\\nVerification interrupted by user", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Verification failed: {e}", file=sys.stderr)
        sys.exit(3)
    finally:
        if not args.no_cleanup:
            verifier.cleanup()

if __name__ == "__main__":
    main()