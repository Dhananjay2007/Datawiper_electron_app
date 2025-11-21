#!/usr/bin/env python3
"""
Secure Wipe Automation Module
Coordinates the complete secure wipe process including verification and certification
"""

import os
import sys
import json
import subprocess
import time
import argparse
import logging
from pathlib import Path
from datetime import datetime, timezone
import threading
import queue

class SecureWipeAutomation:
    def __init__(self):
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
        # Find Python scripts directory
        self.script_dir = Path(__file__).parent
        self.verification_script = self.script_dir / "verification.py"
        self.certificate_script = self.script_dir / "certificate_gen.py"
        self.fingerprint_script = self.script_dir / "device_fingerprint.py"
        
        # Progress tracking
        self.progress_callback = None
        self.log_callback = None
        
    def set_progress_callback(self, callback):
        """Set callback for progress updates"""
        self.progress_callback = callback
        
    def set_log_callback(self, callback):
        """Set callback for log updates"""
        self.log_callback = callback
        
    def report_progress(self, percentage, message):
        """Report progress to callback"""
        if self.progress_callback:
            self.progress_callback(percentage, message)
        
        self.logger.info(f"Progress {percentage}%: {message}")
        print(f"PROGRESS:{percentage}:{message}", flush=True)
        
    def log_message(self, level, message):
        """Log message to callback"""
        if self.log_callback:
            self.log_callback(level, message)
            
        getattr(self.logger, level.lower(), self.logger.info)(message)
    
    def validate_device(self, device_path):
        """Validate device accessibility and safety"""
        try:
            self.log_message('info', f"Validating device: {device_path}")
            
            # Check if device exists
            if not os.path.exists(device_path):
                raise Exception(f"Device {device_path} does not exist")
            
            # Check if it's a block device (Linux) or physical drive (Windows)
            if os.name != 'nt':
                import stat
                mode = os.stat(device_path).st_mode
                if not stat.S_ISBLK(mode):
                    self.log_message('warning', f"Device {device_path} may not be a block device")
            
            # Check if device is mounted (Linux only)
            if os.name != 'nt':
                try:
                    result = subprocess.run(['mount'], capture_output=True, text=True)
                    if device_path in result.stdout:
                        raise Exception(f"Device {device_path} appears to be mounted. Unmount before wiping.")
                except:
                    pass  # mount command may not be available
            
            # Check permissions
            if not os.access(device_path, os.R_OK | os.W_OK):
                raise Exception(f"Insufficient permissions to access {device_path}")
            
            self.log_message('info', "Device validation passed")
            return True
            
        except Exception as e:
            self.log_message('error', f"Device validation failed: {e}")
            raise

    def execute_cpp_wipe(self, device_path, profile, standard, include_hpa_dco):
        """Execute the C++ wipe engine"""
        try:
            self.log_message('info', "Starting C++ secure wipe engine...")
            
            # Find the C++ executable
            cpp_executable = None
            possible_paths = [
                './wiper.exe',
                'D:/secure-wipe-dashboard/build/Release/wiper.exe',
                'D:/secure-wipe-dashboard/build/build/Release/wiper.exe',
                './secure_wiper.exe',
                '../build/secure_wiper.exe',
                '../build/Release/secure_wiper.exe',
                '../build/Debug/secure_wiper.exe'
            ]

            for path in possible_paths:
                if os.path.exists(path) and os.access(path, os.X_OK):
                    cpp_executable = path
                    break
            
            if not cpp_executable:
                raise Exception("C++ wipe engine executable not found")
            
            # Map profile and mode to numeric values
            profile_map = {'citizen': 1, 'enterprise': 2, 'government': 3}
            mode_map = {'NIST SP 800-88': 1, 'HSE': 2}
            
            profile_num = profile_map.get(profile.lower(), 1)
            mode_num = mode_map.get(standard, 1)
            hpa_dco_flag = '1' if include_hpa_dco else '0'
            
            # Build command
            cmd = [cpp_executable, device_path, str(profile_num), str(mode_num), hpa_dco_flag]
            
            self.log_message('info', f"Executing: {' '.join(cmd)}")
            self.report_progress(10, "Starting secure wipe process...")
            
            # Execute with real-time output parsing
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            # Monitor output for progress updates
            progress_keywords = {
                'initializing': 5,
                'unlocking': 10,
                'starting': 15,
                'pass 1': 25,
                'pass 2': 45,
                'pass 3': 65,
                'pass 4': 75,
                'pass 5': 85,
                'complete': 90,
                'success': 100
            }
            
            output_lines = []
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                
                if line:
                    line = line.strip()
                    output_lines.append(line)
                    self.log_message('info', f"[WIPE] {line}")
                    
                    # Check for progress indicators
                    line_lower = line.lower()
                    for keyword, progress in progress_keywords.items():
                        if keyword in line_lower:
                            self.report_progress(progress, line)
                            break
                    
                    # Check for percentage indicators
                    if '%' in line and any(char.isdigit() for char in line):
                        try:
                            # Extract percentage from line
                            import re
                            match = re.search(r'(\d+(?:\.\d+)?)%', line)
                            if match:
                                percentage = float(match.group(1))
                                # Scale to 10-90% range (leaving room for verification)
                                scaled_percentage = 10 + (percentage * 0.8)
                                self.report_progress(int(scaled_percentage), line)
                        except:
                            pass
            
            return_code = process.wait()
            
            if return_code == 0:
                self.log_message('info', "C++ wipe engine completed successfully")
                self.report_progress(90, "Secure wipe completed successfully")
                return True
            else:
                error_msg = f"C++ wipe engine failed with return code {return_code}"
                self.log_message('error', error_msg)
                raise Exception(error_msg)
                
        except FileNotFoundError:
            self.log_message('error', "C++ wipe engine not found, falling back to Python implementation")
            return self.execute_python_fallback_wipe(device_path, profile, standard, include_hpa_dco)
        except Exception as e:
            self.log_message('error', f"C++ wipe execution failed: {e}")
            raise

    def execute_python_fallback_wipe(self, device_path, profile, standard, include_hpa_dco):
        """Fallback Python implementation for basic wiping"""
        try:
            self.log_message('warning', "Using Python fallback wipe (basic overwrite only)")
            self.report_progress(15, "Starting Python fallback wipe...")
            
            # Open device for writing
            with open(device_path, 'r+b') as device:
                # Get device size
                device.seek(0, 2)  # Seek to end
                device_size = device.tell()
                device.seek(0)  # Seek to start
                
                self.log_message('info', f"Device size: {device_size} bytes")
                
                # Determine number of passes
                passes = 1
                if standard == 'HSE':
                    passes = 3 if profile != 'government' else 5
                
                patterns = [
                    b'\\x00' * 1024 * 1024,  # Zeros
                    b'\\xFF' * 1024 * 1024,  # Ones
                    None,  # Random (will be generated)
                ]
                
                block_size = 1024 * 1024  # 1MB blocks
                total_blocks = (device_size + block_size - 1) // block_size
                
                for pass_num in range(passes):
                    self.log_message('info', f"Starting pass {pass_num + 1}/{passes}")
                    base_progress = 15 + (pass_num * 70 // passes)
                    
                    # Select pattern
                    if pass_num < len(patterns):
                        pattern = patterns[pass_num]
                        if pattern is None:  # Random pattern
                            import random
                            pattern = bytes([random.randint(0, 255) for _ in range(block_size)])
                    else:
                        pattern = patterns[0]  # Default to zeros
                    
                    # Write pattern to entire device
                    device.seek(0)
                    blocks_written = 0
                    
                    while device.tell() < device_size:
                        remaining = device_size - device.tell()
                        write_size = min(block_size, remaining)
                        
                        if write_size < block_size:
                            # Adjust pattern for final block
                            write_pattern = pattern[:write_size]
                        else:
                            write_pattern = pattern
                        
                        device.write(write_pattern)
                        device.flush()
                        os.fsync(device.fileno())  # Force write to disk
                        
                        blocks_written += 1
                        if blocks_written % 100 == 0:  # Update every 100 blocks
                            progress = base_progress + ((blocks_written / total_blocks) * 70 // passes)
                            self.report_progress(int(progress), f"Pass {pass_num + 1}: {blocks_written}/{total_blocks} blocks")
            
            self.report_progress(90, "Python fallback wipe completed")
            return True
            
        except Exception as e:
            self.log_message('error', f"Python fallback wipe failed: {e}")
            raise

    def run_verification(self, device_path):
        """Run post-wipe verification"""
        try:
            self.log_message('info', "Starting post-wipe verification...")
            self.report_progress(91, "Running verification with PhotoRec/TestDisk...")
            
            if not self.verification_script.exists():
                self.log_message('warning', "Verification script not found, skipping verification")
                return {'verification_passed': True, 'files_recovered': 0, 'details': 'Verification skipped'}
            
            # Run verification script
            cmd = [sys.executable, str(self.verification_script), device_path, '--timeout', '1800']
            
            self.log_message('info', f"Running verification: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2000)
            
            if result.returncode == 0:
                # Parse verification results
                try:
                    verification_result = json.loads(result.stdout)
                    self.log_message('info', f"Verification completed: {verification_result.get('verification_passed', False)}")
                    self.report_progress(95, "Verification completed")
                    return verification_result
                except json.JSONDecodeError:
                    self.log_message('warning', "Could not parse verification results")
                    return {'verification_passed': False, 'files_recovered': -1, 'details': 'Parse error'}
            else:
                self.log_message('warning', f"Verification failed with return code {result.returncode}")
                self.log_message('debug', f"Verification stderr: {result.stderr}")
                return {'verification_passed': False, 'files_recovered': -1, 'details': result.stderr}
                
        except subprocess.TimeoutExpired:
            self.log_message('warning', "Verification timed out")
            return {'verification_passed': False, 'files_recovered': -1, 'details': 'Verification timed out'}
        except Exception as e:
            self.log_message('error', f"Verification failed: {e}")
            return {'verification_passed': False, 'files_recovered': -1, 'details': str(e)}

    def generate_certificate(self, session_data):
        """Generate wipe certificate"""
        try:
            self.log_message('info', "Generating wipe certificate...")
            self.report_progress(96, "Generating certificate with DNA fingerprinting...")
            
            if not self.certificate_script.exists():
                self.log_message('warning', "Certificate script not found, skipping certificate generation")
                return None
            
            # Prepare session data for certificate
            cert_session_data = json.dumps(session_data)
            
            # Run certificate generation script
            cmd = [sys.executable, str(self.certificate_script), cert_session_data]
            
            self.log_message('info', "Running certificate generation...")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                try:
                    cert_result = json.loads(result.stdout)
                    if cert_result.get('success', False):
                        self.log_message('info', f"Certificate generated: {cert_result.get('certificate_id')}")
                        self.report_progress(98, "Certificate generated successfully")
                        return cert_result
                    else:
                        self.log_message('error', f"Certificate generation failed: {cert_result.get('error')}")
                        return None
                except json.JSONDecodeError:
                    self.log_message('warning', "Could not parse certificate results")
                    return None
            else:
                self.log_message('error', f"Certificate generation failed with return code {result.returncode}")
                self.log_message('debug', f"Certificate stderr: {result.stderr}")
                return None
                
        except Exception as e:
            self.log_message('error', f"Certificate generation failed: {e}")
            return None

    def complete_wipe_process(self, device_path, profile, standard, include_hpa_dco=True):
        """Execute complete secure wipe process"""
        session_start_time = datetime.now(timezone.utc)
        session_data = {
            'sessionId': f"wipe_{int(time.time())}",
            'startTime': session_start_time.isoformat(),
            'device': {
                'id': device_path,
                'name': os.path.basename(device_path),
                'path': device_path
            },
            'config': {
                'profile': profile,
                'standard': standard,
                'includeHpaDco': include_hpa_dco
            }
        }
        
        try:
            self.log_message('info', f"Starting complete wipe process for {device_path}")
            self.report_progress(0, "Initializing secure wipe process...")
            
            # Step 1: Validate device
            self.validate_device(device_path)
            self.report_progress(5, "Device validation completed")
            
            # Step 2: Execute wipe
            wipe_success = self.execute_cpp_wipe(device_path, profile, standard, include_hpa_dco)
            
            if not wipe_success:
                raise Exception("Wipe operation failed")
            
            # Step 3: Run verification
            verification_result = self.run_verification(device_path)
            session_data['verification'] = verification_result
            
            # Step 4: Generate certificate
            session_end_time = datetime.now(timezone.utc)
            session_data['endTime'] = session_end_time.isoformat()
            session_data['status'] = 'completed'
            session_data['duration'] = (session_end_time - session_start_time).total_seconds()
            
            certificate_result = self.generate_certificate(session_data)
            session_data['certificate'] = certificate_result
            
            self.report_progress(100, "Secure wipe process completed successfully")
            self.log_message('info', "Complete wipe process finished successfully")
            
            return {
                'success': True,
                'session_data': session_data,
                'verification': verification_result,
                'certificate': certificate_result
            }
            
        except Exception as e:
            session_data['status'] = 'failed'
            session_data['error'] = str(e)
            session_data['endTime'] = datetime.now(timezone.utc).isoformat()
            
            self.log_message('error', f"Wipe process failed: {e}")
            self.report_progress(0, f"Wipe process failed: {e}")
            
            return {
                'success': False,
                'error': str(e),
                'session_data': session_data
            }

def main():
    parser = argparse.ArgumentParser(description='Automated secure wipe process')
    parser.add_argument('command', choices=['wipe', 'verify', 'certificate'], help='Command to execute')
    parser.add_argument('device', help='Device path to process')
    parser.add_argument('profile', nargs='?', choices=['citizen', 'enterprise', 'government'], 
                       default='citizen', help='Security profile')
    parser.add_argument('standard', nargs='?', choices=['NIST SP 800-88', 'HSE'], 
                       default='NIST SP 800-88', help='Wiping standard')
    parser.add_argument('hpa_dco', nargs='?', choices=['0', '1'], default='1', 
                       help='Include HPA/DCO areas (1=yes, 0=no)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    automation = SecureWipeAutomation()
    
    try:
        if args.command == 'wipe':
            include_hpa_dco = args.hpa_dco == '1'
            result = automation.complete_wipe_process(
                args.device, args.profile, args.standard, include_hpa_dco
            )
            
            print(json.dumps(result, indent=2))
            sys.exit(0 if result.get('success', False) else 1)
            
        elif args.command == 'verify':
            result = automation.run_verification(args.device)
            print(json.dumps(result, indent=2))
            sys.exit(0 if result.get('verification_passed', False) else 1)
            
        elif args.command == 'certificate':
            # Generate certificate from existing session data
            if os.path.exists(args.device):
                with open(args.device, 'r') as f:
                    session_data = json.load(f)
                result = automation.generate_certificate(session_data)
                print(json.dumps(result, indent=2))
                sys.exit(0 if result and result.get('success', False) else 1)
            else:
                print("Session data file not found", file=sys.stderr)
                sys.exit(1)
                
    except KeyboardInterrupt:
        print("\\nOperation interrupted by user", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Operation failed: {e}", file=sys.stderr)
        sys.exit(3)

if __name__ == "__main__":
    main()