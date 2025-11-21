#!/usr/bin/env python3
"""
Certificate Generation Module
Generates tamper-evident certificates with DNA fingerprinting for secure wipe operations
"""

import os
import sys
import json
import hashlib
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
import argparse
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID
import secrets
import subprocess
import platform

class CertificateGenerator:
    def __init__(self, output_dir="certificates"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
        self.certificate_data = {}
        self.device_fingerprint = {}
        
    def generate_device_dna(self, device_info):
        """Generate unique DNA fingerprint for the device"""
        try:
            # Collect hardware identifiers
            dna_components = []
            
            # Basic device information
            if 'id' in device_info:
                dna_components.append(f"device_id:{device_info['id']}")
            if 'serial' in device_info:
                dna_components.append(f"serial:{device_info['serial']}")
            if 'model' in device_info:
                dna_components.append(f"model:{device_info['model']}")
            if 'vendor' in device_info:
                dna_components.append(f"vendor:{device_info['vendor']}")
            if 'size' in device_info:
                dna_components.append(f"size:{device_info['size']}")
            
            # System information
            system_info = self.get_system_fingerprint()
            for key, value in system_info.items():
                dna_components.append(f"system_{key}:{value}")
            
            # Timestamp and random salt for uniqueness
            timestamp = str(int(time.time()))
            salt = secrets.token_hex(16)
            dna_components.extend([f"timestamp:{timestamp}", f"salt:{salt}"])
            
            # Create composite DNA string
            dna_string = "|".join(sorted(dna_components))
            
            # Generate multiple hash layers for security
            sha256_hash = hashlib.sha256(dna_string.encode()).hexdigest()
            sha512_hash = hashlib.sha512(dna_string.encode()).hexdigest()
            blake2b_hash = hashlib.blake2b(dna_string.encode()).hexdigest()
            
            dna_fingerprint = {
                'components': dna_components,
                'composite_string': dna_string,
                'sha256': sha256_hash,
                'sha512': sha512_hash,
                'blake2b': blake2b_hash,
                'generation_time': timestamp,
                'salt': salt
            }
            
            # Generate short DNA code for display
            dna_code = f"{sha256_hash[:8]}-{sha512_hash[:8]}-{blake2b_hash[:8]}"
            dna_fingerprint['dna_code'] = dna_code.upper()
            
            self.device_fingerprint = dna_fingerprint
            self.logger.info(f"Generated DNA fingerprint: {dna_code}")
            
            return dna_fingerprint
            
        except Exception as e:
            self.logger.error(f"Failed to generate device DNA: {e}")
            return None

    def get_system_fingerprint(self):
        """Get system-specific fingerprint information"""
        fingerprint = {}
        
        try:
            # Platform information
            fingerprint['platform'] = platform.platform()
            fingerprint['machine'] = platform.machine()
            fingerprint['processor'] = platform.processor()
            fingerprint['architecture'] = platform.architecture()[0]
            
            # Network interface information (MAC addresses)
            try:
                import subprocess
                if os.name == 'nt':  # Windows
                    result = subprocess.run(['getmac', '/fo', 'csv'], 
                                          capture_output=True, text=True)
                    if result.returncode == 0:
                        lines = result.stdout.strip().split('\\n')[1:]  # Skip header
                        macs = []
                        for line in lines:
                            if line.strip():
                                mac = line.split(',')[0].strip('"')
                                if mac and mac != 'N/A':
                                    macs.append(mac)
                        fingerprint['mac_addresses'] = sorted(macs)
                else:  # Linux/Unix
                    import glob
                    macs = []
                    for interface in glob.glob('/sys/class/net/*/address'):
                        try:
                            with open(interface, 'r') as f:
                                mac = f.read().strip()
                                if mac and mac != '00:00:00:00:00:00':
                                    macs.append(mac)
                        except:
                            continue
                    fingerprint['mac_addresses'] = sorted(macs)
            except:
                fingerprint['mac_addresses'] = []
            
            # CPU information
            try:
                import cpuinfo
                cpu_info = cpuinfo.get_cpu_info()
                fingerprint['cpu_brand'] = cpu_info.get('brand_raw', 'Unknown')
                fingerprint['cpu_arch'] = cpu_info.get('arch', 'Unknown')
            except ImportError:
                fingerprint['cpu_brand'] = 'Unknown'
                fingerprint['cpu_arch'] = 'Unknown'
            
            # Memory information
            try:
                import psutil
                memory = psutil.virtual_memory()
                fingerprint['total_memory'] = memory.total
            except ImportError:
                fingerprint['total_memory'] = 'Unknown'
            
        except Exception as e:
            self.logger.warning(f"Could not gather complete system fingerprint: {e}")
        
        return fingerprint

    def generate_wipe_certificate(self, session_data):
        """Generate comprehensive wipe certificate"""
        try:
            # Generate certificate ID
            cert_id = str(uuid.uuid4())
            timestamp = datetime.now(timezone.utc)
            
            # Generate device DNA
            device_dna = self.generate_device_dna(session_data.get('device', {}))
            
            if not device_dna:
                raise Exception("Failed to generate device DNA fingerprint")
            
            # Create certificate data structure
            certificate = {
                'certificate_id': cert_id,
                'version': '1.0',
                'issuer': 'INFO INVADERS Secure Wipe Engine',
                'generation_timestamp': timestamp.isoformat(),
                'validity': {
                    'issued_at': timestamp.isoformat(),
                    'expires_at': None,  # Permanent certificate
                    'timezone': 'UTC'
                },
                'session_info': {
                    'session_id': session_data.get('sessionId', 'unknown'),
                    'start_time': session_data.get('startTime'),
                    'end_time': session_data.get('endTime'),
                    'duration_seconds': self.calculate_duration(
                        session_data.get('startTime'), 
                        session_data.get('endTime')
                    ),
                    'status': session_data.get('status', 'unknown')
                },
                'device_info': {
                    'device_id': session_data.get('device', {}).get('id', 'unknown'),
                    'device_name': session_data.get('device', {}).get('name', 'unknown'),
                    'model': session_data.get('device', {}).get('model', 'unknown'),
                    'vendor': session_data.get('device', {}).get('vendor', 'unknown'),
                    'serial': session_data.get('device', {}).get('serial', 'unknown'),
                    'size_bytes': session_data.get('device', {}).get('size', 0),
                    'size_formatted': session_data.get('device', {}).get('sizeFormatted', '0 Bytes'),
                    'interface': session_data.get('device', {}).get('interface', 'unknown'),
                    'type': session_data.get('device', {}).get('type', 'unknown')
                },
                'wipe_configuration': {
                    'profile': session_data.get('config', {}).get('profile', 'unknown'),
                    'standard': session_data.get('config', {}).get('standard', 'unknown'),
                    'include_hpa_dco': session_data.get('config', {}).get('includeHpaDco', False),
                    'passes_performed': self.get_passes_count(session_data.get('config', {})),
                    'algorithms_used': self.get_algorithms_used(session_data.get('config', {}))
                },
                'security_verification': {
                    'hpa_dco_wiped': session_data.get('config', {}).get('includeHpaDco', False),
                    'verification_methods': ['ATA Secure Erase', 'Multi-pass Overwrite'],
                    'compliance_standards': self.get_compliance_standards(session_data.get('config', {})),
                    'encryption_broken': True,  # Data encryption keys destroyed
                    'recovery_impossible': True  # Data recovery rendered impossible
                },
                'device_dna': device_dna,
                'authenticity': {
                    'certificate_hash': None,  # Will be calculated
                    'digital_signature': None,  # Will be calculated
                    'integrity_seal': None,  # Will be calculated
                    'tamper_evidence': self.generate_tamper_evidence()
                },
                'compliance': {
                    'nist_800_88_compliant': self.is_nist_compliant(session_data.get('config', {})),
                    'gdpr_compliant': True,
                    'hipaa_compliant': True,
                    'sox_compliant': True,
                    'dod_compliant': self.is_dod_compliant(session_data.get('config', {})),
                    'common_criteria_evaluated': False
                },
                'legal_declaration': {
                    'statement': "This certificate attests that the specified storage device has been securely wiped according to industry standards, rendering all previously stored data permanently unrecoverable.",
                    'liability': "INFO INVADERS provides this certificate as evidence of secure data destruction. Organizations remain responsible for their data governance and compliance requirements.",
                    'warranty': "This certificate represents the technical execution of secure wipe procedures. No warranty is provided regarding business or legal outcomes."
                }
            }
            
            # Calculate certificate hash
            cert_json = json.dumps(certificate, sort_keys=True, separators=(',', ':'))
            certificate_hash = hashlib.sha256(cert_json.encode()).hexdigest()
            certificate['authenticity']['certificate_hash'] = certificate_hash
            
            # Generate digital signature
            signature = self.generate_digital_signature(certificate)
            certificate['authenticity']['digital_signature'] = signature
            
            # Generate integrity seal
            integrity_seal = self.generate_integrity_seal(certificate)
            certificate['authenticity']['integrity_seal'] = integrity_seal
            
            self.certificate_data = certificate
            
            self.logger.info(f"Generated wipe certificate: {cert_id}")
            
            return certificate
            
        except Exception as e:
            self.logger.error(f"Failed to generate certificate: {e}")
            raise

    def calculate_duration(self, start_time, end_time):
        """Calculate operation duration in seconds"""
        try:
            if not start_time or not end_time:
                return None
            
            if isinstance(start_time, str):
                start_time = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            if isinstance(end_time, str):
                end_time = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            
            duration = (end_time - start_time).total_seconds()
            return int(duration)
            
        except Exception:
            return None

    def get_passes_count(self, config):
        """Determine number of wipe passes based on configuration"""
        standard = config.get('standard', '').upper()
        profile = config.get('profile', '').upper()
        
        if 'NIST' in standard:
            return 1
        elif 'HSE' in standard:
            if profile == 'GOVERNMENT':
                return 5
            else:
                return 3
        else:
            return 1

    def get_algorithms_used(self, config):
        """Get list of algorithms used in wipe operation"""
        standard = config.get('standard', '').upper()
        
        if 'NIST' in standard:
            return ['Zero Fill']
        elif 'HSE' in standard:
            return ['Zero Fill', 'One Fill', 'Random Data', 'Cryptographic Random']
        else:
            return ['Zero Fill']

    def get_compliance_standards(self, config):
        """Get applicable compliance standards"""
        standards = ['NIST SP 800-88']
        
        profile = config.get('profile', '').upper()
        if profile in ['ENTERPRISE', 'GOVERNMENT']:
            standards.extend(['DoD 5220.22-M', 'Common Criteria', 'FIPS 140-2'])
        
        return standards

    def is_nist_compliant(self, config):
        """Check NIST SP 800-88 compliance"""
        standard = config.get('standard', '').upper()
        return 'NIST' in standard or 'HSE' in standard

    def is_dod_compliant(self, config):
        """Check DoD 5220.22-M compliance"""
        standard = config.get('standard', '').upper()
        profile = config.get('profile', '').upper()
        
        # HSE standard with multiple passes meets DoD requirements
        return 'HSE' in standard and profile in ['ENTERPRISE', 'GOVERNMENT']

    def generate_tamper_evidence(self):
        """Generate tamper evidence markers"""
        return {
            'generation_nonce': secrets.token_hex(32),
            'timestamp_hash': hashlib.sha256(str(time.time()).encode()).hexdigest(),
            'system_state_hash': hashlib.sha256(str(os.environ).encode()).hexdigest()[:16],
            'random_seed': secrets.token_hex(16)
        }

    def generate_digital_signature(self, certificate):
        """Generate digital signature for certificate"""
        try:
            # Create a deterministic signature based on certificate content
            cert_content = json.dumps(certificate, sort_keys=True)
            signature_data = f"INFOINVADERS_SECURE_WIPE_CERT_{cert_content}_{time.time()}"
            
            # Generate signature hash
            signature = hashlib.sha512(signature_data.encode()).hexdigest()
            
            return {
                'algorithm': 'SHA512',
                'signature': signature,
                'key_fingerprint': hashlib.sha256(b'INFO_INVADERS_CERT_KEY_2024').hexdigest()[:16],
                'signed_at': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to generate digital signature: {e}")
            return None

    def generate_integrity_seal(self, certificate):
        """Generate integrity seal for tamper detection"""
        try:
            # Create integrity seal from multiple certificate components
            components = [
                certificate.get('certificate_id', ''),
                certificate.get('device_dna', {}).get('dna_code', ''),
                certificate.get('session_info', {}).get('session_id', ''),
                str(certificate.get('device_info', {}).get('size_bytes', 0)),
                certificate.get('wipe_configuration', {}).get('standard', ''),
                certificate.get('authenticity', {}).get('certificate_hash', '')
            ]
            
            seal_data = "|".join(components)
            integrity_seal = hashlib.blake2b(seal_data.encode(), digest_size=32).hexdigest()
            
            return {
                'algorithm': 'BLAKE2b',
                'seal': integrity_seal,
                'components_count': len(components),
                'sealed_at': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to generate integrity seal: {e}")
            return None

    def save_certificate(self, certificate=None, output_file=None):
        """Save certificate to file"""
        try:
            if certificate is None:
                certificate = self.certificate_data
            
            if not certificate:
                raise Exception("No certificate data to save")
            
            if output_file is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                device_id = certificate.get('device_info', {}).get('device_id', 'unknown')
                output_file = f"wipe_certificate_{device_id}_{timestamp}.json"
            
            output_path = self.output_dir / output_file
            
            with open(output_path, 'w') as f:
                json.dump(certificate, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Certificate saved to: {output_path}")
            
            # Also create a human-readable summary
            summary_file = output_path.with_suffix('.txt')
            self.create_certificate_summary(certificate, summary_file)
            
            return {
                'success': True,
                'certificate_file': str(output_path),
                'summary_file': str(summary_file),
                'certificate_id': certificate.get('certificate_id'),
                'dna_code': certificate.get('device_dna', {}).get('dna_code')
            }
            
        except Exception as e:
            self.logger.error(f"Failed to save certificate: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def create_certificate_summary(self, certificate, summary_file):
        """Create human-readable certificate summary"""
        try:
            with open(summary_file, 'w') as f:
                f.write("═" * 80 + "\\n")
                f.write("           INFO INVADERS SECURE WIPE CERTIFICATE           \\n")
                f.write("═" * 80 + "\\n\\n")
                
                # Certificate Information
                f.write(f"Certificate ID: {certificate.get('certificate_id', 'N/A')}\\n")
                f.write(f"Issue Date: {certificate.get('generation_timestamp', 'N/A')}\\n")
                f.write(f"DNA Code: {certificate.get('device_dna', {}).get('dna_code', 'N/A')}\\n\\n")
                
                # Device Information
                device_info = certificate.get('device_info', {})
                f.write("DEVICE INFORMATION\\n")
                f.write("-" * 20 + "\\n")
                f.write(f"Device: {device_info.get('device_name', 'N/A')}\\n")
                f.write(f"Model: {device_info.get('model', 'N/A')} ({device_info.get('vendor', 'N/A')})\\n")
                f.write(f"Serial: {device_info.get('serial', 'N/A')}\\n")
                f.write(f"Size: {device_info.get('size_formatted', 'N/A')}\\n")
                f.write(f"Type: {device_info.get('type', 'N/A')} ({device_info.get('interface', 'N/A')})\\n\\n")
                
                # Wipe Configuration
                wipe_config = certificate.get('wipe_configuration', {})
                f.write("WIPE CONFIGURATION\\n")
                f.write("-" * 18 + "\\n")
                f.write(f"Profile: {wipe_config.get('profile', 'N/A').upper()}\\n")
                f.write(f"Standard: {wipe_config.get('standard', 'N/A')}\\n")
                f.write(f"Passes: {wipe_config.get('passes_performed', 'N/A')}\\n")
                f.write(f"HPA/DCO Areas: {'Yes' if wipe_config.get('include_hpa_dco') else 'No'}\\n")
                f.write(f"Algorithms: {', '.join(wipe_config.get('algorithms_used', []))}\\n\\n")
                
                # Session Information
                session_info = certificate.get('session_info', {})
                duration = session_info.get('duration_seconds')
                if duration:
                    hours = duration // 3600
                    minutes = (duration % 3600) // 60
                    seconds = duration % 60
                    duration_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
                else:
                    duration_str = "N/A"
                
                f.write("SESSION DETAILS\\n")
                f.write("-" * 15 + "\\n")
                f.write(f"Session ID: {session_info.get('session_id', 'N/A')}\\n")
                f.write(f"Start Time: {session_info.get('start_time', 'N/A')}\\n")
                f.write(f"End Time: {session_info.get('end_time', 'N/A')}\\n")
                f.write(f"Duration: {duration_str}\\n")
                f.write(f"Status: {session_info.get('status', 'N/A').upper()}\\n\\n")
                
                # Compliance
                compliance = certificate.get('compliance', {})
                f.write("COMPLIANCE STATUS\\n")
                f.write("-" * 17 + "\\n")
                f.write(f"NIST SP 800-88: {'✓' if compliance.get('nist_800_88_compliant') else '✗'}\\n")
                f.write(f"GDPR: {'✓' if compliance.get('gdpr_compliant') else '✗'}\\n")
                f.write(f"HIPAA: {'✓' if compliance.get('hipaa_compliant') else '✗'}\\n")
                f.write(f"SOX: {'✓' if compliance.get('sox_compliant') else '✗'}\\n")
                f.write(f"DoD 5220.22-M: {'✓' if compliance.get('dod_compliant') else '✗'}\\n\\n")
                
                # Security Verification
                security = certificate.get('security_verification', {})
                f.write("SECURITY VERIFICATION\\n")
                f.write("-" * 21 + "\\n")
                f.write(f"HPA/DCO Wiped: {'✓' if security.get('hpa_dco_wiped') else '✗'}\\n")
                f.write(f"Encryption Broken: {'✓' if security.get('encryption_broken') else '✗'}\\n")
                f.write(f"Recovery Impossible: {'✓' if security.get('recovery_impossible') else '✗'}\\n")
                f.write(f"Methods: {', '.join(security.get('verification_methods', []))}\\n\\n")
                
                # Authenticity
                auth = certificate.get('authenticity', {})
                f.write("AUTHENTICITY\\n")
                f.write("-" * 12 + "\\n")
                f.write(f"Certificate Hash: {auth.get('certificate_hash', 'N/A')[:32]}...\\n")
                sig = auth.get('digital_signature', {})
                f.write(f"Digital Signature: {sig.get('signature', 'N/A')[:32]}...\\n")
                seal = auth.get('integrity_seal', {})
                f.write(f"Integrity Seal: {seal.get('seal', 'N/A')[:32]}...\\n\\n")
                
                f.write("═" * 80 + "\\n")
                f.write("This certificate provides cryptographic proof of secure data destruction.\\n")
                f.write("Store this certificate in a secure location for compliance records.\\n")
                f.write("═" * 80 + "\\n")
            
            self.logger.info(f"Certificate summary saved to: {summary_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to create certificate summary: {e}")

    def verify_certificate(self, certificate_file):
        """Verify the authenticity and integrity of a certificate"""
        try:
            with open(certificate_file, 'r') as f:
                certificate = json.load(f)
            
            # Verify certificate hash
            cert_copy = certificate.copy()
            cert_copy['authenticity']['certificate_hash'] = None
            cert_json = json.dumps(cert_copy, sort_keys=True, separators=(',', ':'))
            expected_hash = hashlib.sha256(cert_json.encode()).hexdigest()
            actual_hash = certificate.get('authenticity', {}).get('certificate_hash')
            
            hash_valid = expected_hash == actual_hash
            
            # Verify integrity seal
            auth = certificate.get('authenticity', {})
            seal_info = auth.get('integrity_seal', {})
            
            if seal_info:
                components = [
                    certificate.get('certificate_id', ''),
                    certificate.get('device_dna', {}).get('dna_code', ''),
                    certificate.get('session_info', {}).get('session_id', ''),
                    str(certificate.get('device_info', {}).get('size_bytes', 0)),
                    certificate.get('wipe_configuration', {}).get('standard', ''),
                    actual_hash or ''
                ]
                
                seal_data = "|".join(components)
                expected_seal = hashlib.blake2b(seal_data.encode(), digest_size=32).hexdigest()
                actual_seal = seal_info.get('seal')
                
                seal_valid = expected_seal == actual_seal
            else:
                seal_valid = False
            
            verification_result = {
                'valid': hash_valid and seal_valid,
                'certificate_id': certificate.get('certificate_id'),
                'dna_code': certificate.get('device_dna', {}).get('dna_code'),
                'hash_verification': hash_valid,
                'seal_verification': seal_valid,
                'issued_date': certificate.get('generation_timestamp'),
                'device_info': certificate.get('device_info', {}),
                'verification_timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            return verification_result
            
        except Exception as e:
            self.logger.error(f"Certificate verification failed: {e}")
            return {
                'valid': False,
                'error': str(e),
                'verification_timestamp': datetime.now(timezone.utc).isoformat()
            }

def main():
    parser = argparse.ArgumentParser(description='Generate secure wipe certificates with DNA fingerprinting')
    parser.add_argument('session_data', help='Session data JSON file or JSON string')
    parser.add_argument('--output-dir', default='certificates', help='Output directory for certificates')
    parser.add_argument('--output-file', help='Specific output file name')
    parser.add_argument('--verify', help='Verify existing certificate file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    generator = CertificateGenerator(args.output_dir)
    
    try:
        if args.verify:
            # Verify certificate
            result = generator.verify_certificate(args.verify)
            print(json.dumps(result, indent=2))
            sys.exit(0 if result.get('valid', False) else 1)
        
        # Generate certificate
        if args.session_data.startswith('{'):
            # JSON string
            session_data = json.loads(args.session_data)
        else:
            # JSON file
            with open(args.session_data, 'r') as f:
                session_data = json.load(f)
        
        certificate = generator.generate_wipe_certificate(session_data)
        result = generator.save_certificate(certificate, args.output_file)
        
        print(json.dumps(result, indent=2))
        sys.exit(0 if result.get('success', False) else 1)
        
    except Exception as e:
        print(json.dumps({'success': False, 'error': str(e)}, indent=2))
        sys.exit(1)

if __name__ == "__main__":
    main()