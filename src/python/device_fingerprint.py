#!/usr/bin/env python3
"""
Device Fingerprinting Module
Generates unique hardware fingerprints for device identification and DNA
"""

import os
import sys
import json
import hashlib
import platform
import subprocess
import uuid
import time
from pathlib import Path
import argparse
import logging

class DeviceFingerprinter:
    def __init__(self):
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
    def get_system_info(self):
        """Get comprehensive system information"""
        system_info = {}
        
        try:
            # Basic platform information
            system_info['platform'] = platform.platform()
            system_info['system'] = platform.system()
            system_info['release'] = platform.release()
            system_info['version'] = platform.version()
            system_info['machine'] = platform.machine()
            system_info['processor'] = platform.processor()
            system_info['architecture'] = platform.architecture()
            system_info['hostname'] = platform.node()
            
            # Python version
            system_info['python_version'] = platform.python_version()
            
        except Exception as e:
            self.logger.error(f"Failed to get basic system info: {e}")
            
        return system_info
    
    def get_hardware_info(self):
        """Get hardware-specific information"""
        hardware_info = {}
        
        try:
            # CPU information
            hardware_info['cpu'] = self.get_cpu_info()
            
            # Memory information
            hardware_info['memory'] = self.get_memory_info()
            
            # Disk information
            hardware_info['disks'] = self.get_disk_info()
            
            # Network interfaces
            hardware_info['network'] = self.get_network_info()
            
            # BIOS/UEFI information
            hardware_info['firmware'] = self.get_firmware_info()
            
        except Exception as e:
            self.logger.error(f"Failed to get hardware info: {e}")
            
        return hardware_info
    
    def get_cpu_info(self):
        """Get CPU information"""
        cpu_info = {}
        
        try:
            if os.name == 'nt':  # Windows
                # Use wmic to get CPU info
                result = subprocess.run([
                    'wmic', 'cpu', 'get', 
                    'Name,Manufacturer,Architecture,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed',
                    '/format:csv'
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\\n')[1:]  # Skip header
                    for line in lines:
                        if line.strip():
                            parts = line.split(',')
                            if len(parts) >= 6:
                                cpu_info = {
                                    'architecture': parts[1],
                                    'manufacturer': parts[2],
                                    'max_clock_speed': parts[3],
                                    'name': parts[4],
                                    'cores': parts[5],
                                    'logical_processors': parts[6]
                                }
                                break
            else:  # Linux/Unix
                # Try to read from /proc/cpuinfo
                if os.path.exists('/proc/cpuinfo'):
                    with open('/proc/cpuinfo', 'r') as f:
                        content = f.read()
                        
                    cpu_info['raw_cpuinfo'] = content[:1000]  # First 1000 chars
                    
                    # Extract key information
                    lines = content.split('\\n')
                    for line in lines:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            key = key.strip().lower()
                            value = value.strip()
                            
                            if key in ['model name', 'cpu family', 'vendor_id', 'stepping', 'microcode']:
                                cpu_info[key.replace(' ', '_')] = value
                            elif key == 'processor' and 'processor_count' not in cpu_info:
                                cpu_info['processor_count'] = 1
                            elif key == 'processor':
                                cpu_info['processor_count'] = cpu_info.get('processor_count', 0) + 1
        
        except Exception as e:
            self.logger.warning(f"Could not get CPU info: {e}")
            
        return cpu_info
    
    def get_memory_info(self):
        """Get memory information"""
        memory_info = {}
        
        try:
            if os.name == 'nt':  # Windows
                # Get total physical memory
                result = subprocess.run([
                    'wmic', 'computersystem', 'get', 'TotalPhysicalMemory', '/format:csv'
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\\n')[1:]
                    for line in lines:
                        if line.strip():
                            parts = line.split(',')
                            if len(parts) >= 2:
                                memory_info['total_physical'] = parts[1]
                                break
                
                # Get memory modules
                result = subprocess.run([
                    'wmic', 'memorychip', 'get', 
                    'Capacity,Speed,Manufacturer,PartNumber', '/format:csv'
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\\n')[1:]
                    modules = []
                    for line in lines:
                        if line.strip():
                            parts = line.split(',')
                            if len(parts) >= 4:
                                modules.append({
                                    'capacity': parts[1],
                                    'manufacturer': parts[2],
                                    'part_number': parts[3],
                                    'speed': parts[4]
                                })
                    memory_info['modules'] = modules
                    
            else:  # Linux/Unix
                # Try to read from /proc/meminfo
                if os.path.exists('/proc/meminfo'):
                    with open('/proc/meminfo', 'r') as f:
                        content = f.read()
                    
                    memory_info['raw_meminfo'] = content[:500]  # First 500 chars
                    
                    # Extract key values
                    lines = content.split('\\n')
                    for line in lines:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            key = key.strip().lower()
                            value = value.strip()
                            
                            if key in ['memtotal', 'memfree', 'memavailable', 'swaptotal']:
                                memory_info[key] = value
        
        except Exception as e:
            self.logger.warning(f"Could not get memory info: {e}")
            
        return memory_info
    
    def get_disk_info(self):
        """Get disk/storage information"""
        disk_info = {}
        
        try:
            if os.name == 'nt':  # Windows
                # Get physical drives
                result = subprocess.run([
                    'wmic', 'diskdrive', 'get', 
                    'Model,Size,SerialNumber,InterfaceType', '/format:csv'
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\\n')[1:]
                    drives = []
                    for line in lines:
                        if line.strip():
                            parts = line.split(',')
                            if len(parts) >= 4:
                                drives.append({
                                    'interface_type': parts[1],
                                    'model': parts[2],
                                    'serial_number': parts[3],
                                    'size': parts[4]
                                })
                    disk_info['physical_drives'] = drives
                    
            else:  # Linux/Unix
                # Try to read from /proc/partitions
                if os.path.exists('/proc/partitions'):
                    with open('/proc/partitions', 'r') as f:
                        content = f.read()
                    disk_info['partitions'] = content
                
                # Get block device information
                try:
                    result = subprocess.run(['lsblk', '-J'], capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        disk_info['lsblk_json'] = result.stdout
                except:
                    pass
        
        except Exception as e:
            self.logger.warning(f"Could not get disk info: {e}")
            
        return disk_info
    
    def get_network_info(self):
        """Get network interface information"""
        network_info = {}
        
        try:
            if os.name == 'nt':  # Windows
                # Get network adapters
                result = subprocess.run([
                    'wmic', 'path', 'win32_networkadapter', 'get', 
                    'MACAddress,Name,AdapterType', '/format:csv'
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\\n')[1:]
                    adapters = []
                    for line in lines:
                        if line.strip():
                            parts = line.split(',')
                            if len(parts) >= 3:
                                adapters.append({
                                    'adapter_type': parts[1],
                                    'mac_address': parts[2],
                                    'name': parts[3]
                                })
                    network_info['adapters'] = adapters
                    
            else:  # Linux/Unix
                # Try to get network interfaces
                interfaces = []
                try:
                    net_path = Path('/sys/class/net')
                    if net_path.exists():
                        for interface_dir in net_path.iterdir():
                            if interface_dir.is_dir():
                                interface_name = interface_dir.name
                                mac_file = interface_dir / 'address'
                                if mac_file.exists():
                                    try:
                                        with open(mac_file, 'r') as f:
                                            mac_address = f.read().strip()
                                        interfaces.append({
                                            'name': interface_name,
                                            'mac_address': mac_address
                                        })
                                    except:
                                        pass
                    network_info['interfaces'] = interfaces
                except:
                    pass
        
        except Exception as e:
            self.logger.warning(f"Could not get network info: {e}")
            
        return network_info
    
    def get_firmware_info(self):
        """Get BIOS/UEFI firmware information"""
        firmware_info = {}
        
        try:
            if os.name == 'nt':  # Windows
                # Get BIOS information
                result = subprocess.run([
                    'wmic', 'bios', 'get', 
                    'Manufacturer,Name,SerialNumber,Version,SMBIOSBIOSVersion', '/format:csv'
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\\n')[1:]
                    for line in lines:
                        if line.strip():
                            parts = line.split(',')
                            if len(parts) >= 5:
                                firmware_info = {
                                    'manufacturer': parts[1],
                                    'name': parts[2],
                                    'serial_number': parts[3],
                                    'smbios_version': parts[4],
                                    'version': parts[5]
                                }
                                break
                                
                # Get motherboard information
                result = subprocess.run([
                    'wmic', 'baseboard', 'get', 
                    'Manufacturer,Product,SerialNumber,Version', '/format:csv'
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\\n')[1:]
                    for line in lines:
                        if line.strip():
                            parts = line.split(',')
                            if len(parts) >= 4:
                                firmware_info['motherboard'] = {
                                    'manufacturer': parts[1],
                                    'product': parts[2],
                                    'serial_number': parts[3],
                                    'version': parts[4]
                                }
                                break
                                
            else:  # Linux/Unix
                # Try to read from /sys/class/dmi/id
                dmi_path = Path('/sys/class/dmi/id')
                if dmi_path.exists():
                    dmi_files = [
                        'bios_vendor', 'bios_version', 'bios_date',
                        'board_vendor', 'board_name', 'board_serial',
                        'product_name', 'product_serial', 'product_uuid'
                    ]
                    
                    for dmi_file in dmi_files:
                        try:
                            file_path = dmi_path / dmi_file
                            if file_path.exists():
                                with open(file_path, 'r') as f:
                                    content = f.read().strip()
                                    if content:
                                        firmware_info[dmi_file] = content
                        except:
                            pass
        
        except Exception as e:
            self.logger.warning(f"Could not get firmware info: {e}")
            
        return firmware_info
    
    def generate_device_fingerprint(self, device_info=None):
        """Generate a comprehensive device fingerprint"""
        fingerprint = {
            'timestamp': time.time(),
            'generation_id': str(uuid.uuid4()),
            'system': self.get_system_info(),
            'hardware': self.get_hardware_info()
        }
        
        # Include specific device information if provided
        if device_info:
            fingerprint['device'] = device_info
        
        # Generate fingerprint hashes
        fingerprint_json = json.dumps(fingerprint, sort_keys=True, separators=(',', ':'))
        
        fingerprint['hashes'] = {
            'md5': hashlib.md5(fingerprint_json.encode()).hexdigest(),
            'sha1': hashlib.sha1(fingerprint_json.encode()).hexdigest(),
            'sha256': hashlib.sha256(fingerprint_json.encode()).hexdigest(),
            'sha512': hashlib.sha512(fingerprint_json.encode()).hexdigest()
        }
        
        # Generate short fingerprint code
        short_code = fingerprint['hashes']['sha256'][:16].upper()
        fingerprint['short_code'] = f"{short_code[:4]}-{short_code[4:8]}-{short_code[8:12]}-{short_code[12:16]}"
        
        return fingerprint
    
    def save_fingerprint(self, fingerprint, output_file=None):
        """Save fingerprint to file"""
        try:
            if output_file is None:
                timestamp = int(time.time())
                output_file = f"device_fingerprint_{timestamp}.json"
            
            with open(output_file, 'w') as f:
                json.dump(fingerprint, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Fingerprint saved to: {output_file}")
            return output_file
            
        except Exception as e:
            self.logger.error(f"Failed to save fingerprint: {e}")
            return None
    
    def compare_fingerprints(self, fp1, fp2):
        """Compare two fingerprints and return similarity score"""
        try:
            if isinstance(fp1, str):
                with open(fp1, 'r') as f:
                    fp1 = json.load(f)
            if isinstance(fp2, str):
                with open(fp2, 'r') as f:
                    fp2 = json.load(f)
            
            # Compare various components
            comparison = {
                'identical': fp1.get('hashes', {}).get('sha256') == fp2.get('hashes', {}).get('sha256'),
                'system_match': fp1.get('system', {}) == fp2.get('system', {}),
                'hardware_match': fp1.get('hardware', {}) == fp2.get('hardware', {}),
                'device_match': fp1.get('device', {}) == fp2.get('device', {}),
                'timestamp_diff': abs(fp1.get('timestamp', 0) - fp2.get('timestamp', 0))
            }
            
            # Calculate similarity score (0-100)
            score = 0
            if comparison['identical']:
                score = 100
            else:
                if comparison['system_match']:
                    score += 30
                if comparison['hardware_match']:
                    score += 50
                if comparison['device_match']:
                    score += 20
            
            comparison['similarity_score'] = score
            
            return comparison
            
        except Exception as e:
            self.logger.error(f"Failed to compare fingerprints: {e}")
            return None

def main():
    parser = argparse.ArgumentParser(description='Generate device hardware fingerprints')
    parser.add_argument('--device-info', help='Device info JSON file or JSON string')
    parser.add_argument('--output', '-o', help='Output file for fingerprint')
    parser.add_argument('--compare', nargs=2, help='Compare two fingerprint files')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    fingerprinter = DeviceFingerprinter()
    
    try:
        if args.compare:
            # Compare fingerprints
            result = fingerprinter.compare_fingerprints(args.compare[0], args.compare[1])
            if result:
                print(json.dumps(result, indent=2))
                sys.exit(0 if result['similarity_score'] > 90 else 1)
            else:
                sys.exit(1)
        
        # Generate fingerprint
        device_info = None
        if args.device_info:
            if args.device_info.startswith('{'):
                device_info = json.loads(args.device_info)
            else:
                with open(args.device_info, 'r') as f:
                    device_info = json.load(f)
        
        fingerprint = fingerprinter.generate_device_fingerprint(device_info)
        
        if args.output:
            output_file = fingerprinter.save_fingerprint(fingerprint, args.output)
            if output_file:
                print(f"Fingerprint saved to: {output_file}")
        else:
            print(json.dumps(fingerprint, indent=2))
        
        sys.exit(0)
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()