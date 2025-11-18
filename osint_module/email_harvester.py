#!/usr/bin/env python3
"""
Email Harvester - OSINT Module
Extracts email addresses from websites and search engines
Can be used on ANY website for intelligence gathering
"""

import requests
import re
import sys
import argparse
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class EmailHarvester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.emails = set()
        self.visited_urls = set()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
        
        # Email regex pattern
        self.email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    
    def extract_emails_from_text(self, text):
        """Extract emails from text using regex"""
        found = self.email_pattern.findall(text)
        for email in found:
            # Filter out common false positives
            if not any(x in email.lower() for x in ['example.com', 'test.com', 'domain.com']):
                self.emails.add(email.lower())
    
    def harvest_from_url(self, url, depth=0, max_depth=2):
        """Recursively harvest emails from URL"""
        if depth > max_depth or url in self.visited_urls:
            return
        
        print(f"{'  ' * depth}[*] Scanning: {url}")
        self.visited_urls.add(url)
        
        try:
            response = self.session.get(url, timeout=5)
            
            # Extract emails from page content
            self.extract_emails_from_text(response.text)
            
            # Extract emails from links (mailto:)
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                if link['href'].startswith('mailto:'):
                    email = link['href'].replace('mailto:', '').split('?')[0]
                    self.emails.add(email.lower())
            
            # Follow links on same domain
            if depth < max_depth:
                parsed_target = urlparse(self.target_url)
                for link in soup.find_all('a', href=True):
                    absolute_url = urljoin(url, link['href'])
                    parsed_url = urlparse(absolute_url)
                    
                    if parsed_url.netloc == parsed_target.netloc:
                        if absolute_url not in self.visited_urls:
                            self.harvest_from_url(absolute_url, depth + 1, max_depth)
        
        except Exception as e:
            print(f"{'  ' * depth}[-] Error: {e}")
    
    def search_google(self, domain):
        """Search Google for emails (limited without API)"""
        print(f"[*] Searching for emails related to: {domain}")
        # Note: This is a basic implementation. Real OSINT tools use Google Dorks
        # Format: site:domain.com intext:"@domain.com"
        print(f"[!] Manual Google Dork: site:{domain} intext:\"@{domain}\"")
    
    def print_report(self):
        """Print harvesting report"""
        print("\n" + "=" * 60)
        print("EMAIL HARVESTING REPORT")
        print("=" * 60)
        print(f"Target: {self.target_url}")
        print(f"URLs Visited: {len(self.visited_urls)}")
        print(f"Emails Found: {len(self.emails)}")
        print("=" * 60)
        
        if self.emails:
            print("\n📧 Discovered Email Addresses:")
            for email in sorted(self.emails):
                print(f"  - {email}")
                
                # Extract domain and username
                username, domain = email.split('@')
                print(f"    Username: {username}")
                print(f"    Domain: {domain}")
        else:
            print("\n[-] No email addresses found")
        
        print("=" * 60)
        
        return list(self.emails)

def main():
    parser = argparse.ArgumentParser(
        description='Email Harvester - OSINT Module',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 email_harvester.py http://example.com
  python3 email_harvester.py http://company.com --depth 3
  python3 email_harvester.py http://university.edu --limit 50
  python3 email_harvester.py http://target.com --depth 2 -o emails.txt
        """
    )
    
    parser.add_argument('target', help='Target URL or domain to harvest emails from')
    parser.add_argument('--depth', type=int, default=2, help='Maximum crawl depth (default: 2)')
    parser.add_argument('--limit', type=int, default=100, help='Maximum number of emails to collect (default: 100)')
    parser.add_argument('-o', '--output', help='Output file to save emails')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Add http:// if not present
    target_url = args.target
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    harvester = EmailHarvester(target_url)
    
    print("=" * 60)
    print("EMAIL HARVESTER - OSINT MODULE")
    print("=" * 60)
    print(f"Target: {target_url}")
    print(f"Max Depth: {args.depth}")
    print(f"Limit: {args.limit} emails")
    print("=" * 60)
    
    harvester.harvest_from_url(target_url, max_depth=args.depth)
    
    # Extract domain for Google search suggestion
    domain = urlparse(target_url).netloc
    harvester.search_google(domain)
    
    emails = harvester.print_report()
    
    # Save to file if specified
    if args.output and emails:
        with open(args.output, 'w') as f:
            for email in sorted(emails)[:args.limit]:
                f.write(email + '\n')
        print(f"\n[+] Emails saved to: {args.output}")

if __name__ == "__main__":
    main()
