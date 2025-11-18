#!/usr/bin/env python3
"""
Advanced Service Enumeration Tool
==================================
Identifies services running on open ports through:
- Banner grabbing
- HTTP probing
- SSL/TLS detection
- Service fingerprinting
- Works with URLs, domains, and IP addresses
"""

import socket
import ssl
import sys
import argparse
import requests
from urllib.parse import urlparse

class ServiceEnumerator:
    def __init__(self, target, port, timeout=5):
        # Extract domain/IP from URL if provided
        self.original_target = target
        self.target = self._normalize_target(target)
        self.port = port
        self.timeout = timeout
        self.service_info = {
            'port': port,
            'target': self.original_target,
            'domain': self.target,
            'service': 'Unknown',
            'version': '',
            'banner': '',
            'ssl': False,
            'http': False,
            'details': []
        }
    
    def _normalize_target(self, target):
        """Extract domain/IP from URL"""
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            return parsed.netloc.split(':')[0]
        return target.split(':')[0]
    
    def enumerate(self):
        """Run all enumeration techniques"""
        print(f"\n{'='*70}")
        print(f"SERVICE ENUMERATION")
        print(f"{'='*70}")
        print(f"Target: {self.target}:{self.port}")
        print(f"{'='*70}\n")
        
        # Try multiple techniques
        self._banner_grab()
        self._check_http()
        self._check_https()
        self._fingerprint_service()
        
        # Print results
        self._print_results()
        
        return self.service_info
    
    def _banner_grab(self):
        """Grab service banner"""
        print("[*] Attempting banner grab...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            
            # Try to receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner:
                self.service_info['banner'] = banner
                print(f"[+] Banner received:")
                print(f"    {banner[:200]}")
                
                # Identify service from banner
                self._identify_from_banner(banner)
            else:
                print("[-] No banner received")
        
        except socket.timeout:
            print("[-] Connection timed out")
        except ConnectionRefusedError:
            print("[-] Connection refused - port may be closed")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    def _identify_from_banner(self, banner):
        """Identify service from banner text"""
        banner_lower = banner.lower()
        
        identifiers = {
            'ssh': ['ssh', 'openssh'],
            'ftp': ['ftp', '220 '],
            'smtp': ['smtp', '220 ', 'mail'],
            'http': ['http/', 'server:'],
            'mysql': ['mysql'],
            'postgresql': ['postgresql'],
            'redis': ['redis'],
            'mongodb': ['mongodb'],
            'apache': ['apache'],
            'nginx': ['nginx'],
            'iis': ['microsoft-iis', 'iis/'],
        }
        
        for service, keywords in identifiers.items():
            if any(kw in banner_lower for kw in keywords):
                self.service_info['service'] = service.upper()
                self.service_info['details'].append(f"Identified from banner: {service}")
                break
    
    def _check_http(self):
        """Check if service is HTTP"""
        print("\n[*] Checking for HTTP...")
        try:
            url = f"http://{self.target}:{self.port}/"
            response = requests.get(url, timeout=self.timeout, verify=False)
            
            self.service_info['http'] = True
            self.service_info['service'] = 'HTTP'
            
            print(f"[+] HTTP service detected!")
            print(f"    Status: {response.status_code}")
            print(f"    Server: {response.headers.get('Server', 'Unknown')}")
            print(f"    Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
            
            if 'Server' in response.headers:
                self.service_info['version'] = response.headers['Server']
                self.service_info['details'].append(f"Server: {response.headers['Server']}")
            
            # Check for common services
            content = response.text[:500].lower()
            if 'phpmyadmin' in content:
                self.service_info['details'].append("PHPMyAdmin detected")
            elif 'wordpress' in content:
                self.service_info['details'].append("WordPress detected")
            elif 'joomla' in content:
                self.service_info['details'].append("Joomla detected")
            elif 'drupal' in content:
                self.service_info['details'].append("Drupal detected")
            
            # Get title
            import re
            title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
            if title_match:
                title = title_match.group(1).strip()
                print(f"    Title: {title[:50]}")
                self.service_info['details'].append(f"Title: {title[:50]}")
        
        except requests.exceptions.ConnectionError:
            print("[-] Not an HTTP service")
        except requests.exceptions.Timeout:
            print("[-] HTTP request timed out")
        except Exception as e:
            print(f"[-] HTTP check failed: {e}")
    
    def _check_https(self):
        """Check if service is HTTPS"""
        print("\n[*] Checking for HTTPS...")
        try:
            url = f"https://{self.target}:{self.port}/"
            response = requests.get(url, timeout=self.timeout, verify=False)
            
            self.service_info['ssl'] = True
            self.service_info['service'] = 'HTTPS'
            
            print(f"[+] HTTPS service detected!")
            print(f"    Status: {response.status_code}")
            print(f"    Server: {response.headers.get('Server', 'Unknown')}")
            
            if 'Server' in response.headers:
                self.service_info['version'] = response.headers['Server']
        
        except requests.exceptions.SSLError:
            # Try SSL socket connection
            self._check_ssl_socket()
        except requests.exceptions.ConnectionError:
            print("[-] Not an HTTPS service")
        except Exception as e:
            print(f"[-] HTTPS check failed: {e}")
    
    def _check_ssl_socket(self):
        """Check SSL with raw socket"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    self.service_info['ssl'] = True
                    print("[+] SSL/TLS detected")
                    
                    # Get certificate info
                    cert = ssock.getpeercert()
                    if cert:
                        print(f"    SSL Version: {ssock.version()}")
                        self.service_info['details'].append(f"SSL: {ssock.version()}")
        except:
            pass
    
    def _fingerprint_service(self):
        """Try to fingerprint service by sending probes"""
        print("\n[*] Attempting service fingerprinting...")
        
        # Common service probes
        probes = {
            'HTTP': b'GET / HTTP/1.0\r\n\r\n',
            'FTP': b'\r\n',
            'SMTP': b'EHLO test\r\n',
            'SSH': b'',
            'MySQL': b'',
        }
        
        for probe_name, probe_data in probes.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((self.target, self.port))
                
                if probe_data:
                    sock.send(probe_data)
                
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                if response and len(response) > 10:
                    print(f"[+] Response to {probe_name} probe:")
                    print(f"    {response[:100]}")
                    
                    if self.service_info['service'] == 'Unknown':
                        self.service_info['service'] = probe_name
            except:
                continue
    
    def _print_results(self):
        """Print enumeration results"""
        print(f"\n{'='*70}")
        print("ENUMERATION RESULTS")
        print(f"{'='*70}")
        print(f"Target:    {self.service_info['target']}:{self.service_info['port']}")
        print(f"Service:   {self.service_info['service']}")
        
        if self.service_info['version']:
            print(f"Version:   {self.service_info['version']}")
        
        if self.service_info['ssl']:
            print(f"SSL/TLS:   ✓ Enabled")
        
        if self.service_info['http']:
            print(f"HTTP:      ✓ Detected")
        
        if self.service_info['banner']:
            print(f"\nBanner:")
            print(f"  {self.service_info['banner'][:200]}")
        
        if self.service_info['details']:
            print(f"\nAdditional Details:")
            for detail in self.service_info['details']:
                print(f"  • {detail}")
        
        print(f"{'='*70}\n")

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Service Enumeration Tool - Works with URLs, domains, and IPs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Domain
  %(prog)s www.example.com 2000
  
  # IP address
  %(prog)s 192.168.1.1 8020
  
  # Full URL
  %(prog)s https://example.com 443
  
  # With custom timeout
  %(prog)s target.com 5060 --timeout 10
        """
    )
    
    parser.add_argument('target', help='Target URL, domain, or IP address')
    parser.add_argument('port', type=int, help='Port to enumerate')
    parser.add_argument('--timeout', type=int, default=5, help='Connection timeout (default: 5)')
    parser.add_argument('--standard', action='store_true', help='Standard enumeration')
    parser.add_argument('--aggressive', action='store_true', help='Aggressive enumeration')
    
    args = parser.parse_args()
    
    print(f"\n🔎 Advanced Service Enumerator")
    print(f"Target: {args.target}")
    print(f"Port: {args.port}\n")
    
    enumerator = ServiceEnumerator(args.target, args.port, args.timeout)
    enumerator.enumerate()

if __name__ == "__main__":
    main()
