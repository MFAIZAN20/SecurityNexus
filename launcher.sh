#!/usr/bin/env bash
# Quick Launcher Script for SecurityNexus v5.0

set -o pipefail
IFS=$'\n\t'
umask 077

info() {
    echo "[+] $*"
}

warn() {
    echo "[!] $*" >&2
}

die() {
    echo "[x] $*" >&2
    exit 1
}

pause() {
    read -r -p "Press ENTER to continue..." _
}

is_yes() {
    case "$1" in
        y|Y|yes|YES) return 0 ;;
        *) return 1 ;;
    esac
}

confirm_authorized() {
    if [ "${SECURITYNEXUS_ACK:-}" = "1" ]; then
        return 0
    fi
    echo "This toolkit is for authorized testing only."
    read -r -p "Confirm you have written permission for the target(s)? (yes/no): " ack
    if ! is_yes "$ack"; then
        die "Authorization not confirmed. Exiting."
    fi
    export SECURITYNEXUS_ACK=1
}

ensure_command() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

install_requirements_if_needed() {
    local marker="$VENV_DIR/.requirements.installed"
    if [ "${FORCE_DEPS:-}" = "1" ] || [ ! -f "$marker" ] || [ "$REQUIREMENTS" -nt "$marker" ]; then
        info "Installing/updating dependencies..."
        PIP_DISABLE_PIP_VERSION_CHECK=1 "$VENV_DIR/bin/python" -m pip install -r "$REQUIREMENTS" || die "Dependency installation failed"
        touch "$marker"
    else
        info "Dependencies are up to date"
    fi
}

ensure_venv() {
    ensure_command python3
    if [ ! -d "$VENV_DIR" ]; then
        info "Creating virtual environment..."
        python3 -m venv "$VENV_DIR" || die "Failed to create virtual environment"
    else
        info "Virtual environment found"
    fi

    if [ ! -f "$VENV_ACTIVATE" ]; then
        die "Virtual environment activate script missing: $VENV_ACTIVATE"
    fi

    if [ -f "$REQUIREMENTS" ]; then
        install_requirements_if_needed
    else
        warn "requirements.txt not found; skipping dependency install"
    fi
}

activate_venv() {
    # shellcheck disable=SC1090
    source "$VENV_ACTIVATE" || die "Failed to activate virtual environment"
}

ensure_reports_dir() {
    mkdir -p "$REPORTS_DIR" || die "Failed to create reports directory: $REPORTS_DIR"
    chmod 700 "$REPORTS_DIR" 2>/dev/null || true
}

trap 'echo ""; warn "Interrupted"; exit 130' INT TERM

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  SECURITYNEXUS v5.0 🛡️                                   ║"
echo "║  Full-Stack Cybersecurity Assessment Platform             ║"
echo "║  ⚠️  FOR AUTHORIZED TESTING ONLY ⚠️                       ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
VENV_DIR="$SCRIPT_DIR/venv"
VENV_ACTIVATE="$VENV_DIR/bin/activate"
REQUIREMENTS="$SCRIPT_DIR/requirements.txt"
REPORTS_DIR="$SCRIPT_DIR/reports"

cd "$SCRIPT_DIR" || die "Failed to change directory to $SCRIPT_DIR"

confirm_authorized
ensure_venv
activate_venv
info "Virtual environment activated"
ensure_reports_dir
echo ""

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  ATTACK MODULES                                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "  [1] 🌐 Start Vulnerable Web App (localhost:5000)"
echo ""
echo "  WEB APPLICATION ATTACKS"
echo "  [2] 💉 SQL Injection Scanner (Advanced v3.0)"
echo "  [3] 🔗 XSS Scanner (Advanced v3.0)"
echo "  [4] 🔨 Brute Force Login Attack"
echo ""
echo "  DATABASE ATTACKS"
echo "  [5] 🗄️  MySQL Attack Module"
echo ""
echo "  FILE TRANSFER ATTACKS"
echo "  [6] 📁 FTP Attack Module"
echo ""
echo "  CONTROL PANEL ATTACKS"
echo "  [7] ⚙️  cPanel/WHM Attack Module"
echo ""
echo "  NETWORK RECONNAISSANCE (ADVANCED)"
echo "  [8] 🚀 Advanced Port Scanner (OS Detection + CVE Lookup)"
echo "  [9] 🕷️  Advanced Web Crawler (JS Analysis + API Discovery)"
echo "  [10] 🔍 Advanced Service Identifier (Exploit Correlation)"
echo "  [11] 🔬 Advanced Port Analysis"
echo "  [12] 🔎 Service Enumerator"
echo "  [13] 🔍 Subdomain Scanner & Takeover"
echo "  [14] 📁 Directory & File Fuzzer"
echo "  [15] 🔧 Technology Fingerprinter"
echo ""
echo "  ADVANCED WEB ATTACKS"
echo "  [16] 🔓 JWT Security Analyzer"
echo "  [17] 🌐 SSRF Scanner"
echo ""
echo "  OSINT MODULES"
echo "  [18] 📧 Email Harvester"
echo "  [19] 📄 Metadata Extractor"
echo ""
echo "  AUTOMATION"
echo "  [24] 🚀 Quick Site Audit (fingerprint + crawl + fuzz)"
echo ""
echo "  SECURITY TOOLS"
echo "  [20] 🛡️  Security Hardening & Audit"
echo "  [21] 🚨 Emergency Hardening Script"
echo ""
echo "  SYSTEM"
echo "  [22] 💻 Open Interactive Shell"
echo "  [23] 📊 View Reports"
echo "  [0] ❌ Exit"
echo ""
read -p "Enter choice [0-23]: " choice

case $choice in
    1)
        echo ""
        echo "[*] Starting Vulnerable Web App..."
        echo "[*] Access at: http://localhost:5000"
        echo ""
        cd vulnerable_webapp && python app.py
        ;;
    2)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  💉 SQL INJECTION SCANNER (Advanced v3.0)                 ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        read -p "Enter target URL: " url
        echo ""
        echo "Scan modes:"
        echo "  [1] Quick scan (common parameters)"
        echo "  [2] Custom parameters"
        echo "  [3] Advanced scan (all payloads)"
        read -p "Choose [1-3]: " sql_choice
        
        if [ "$sql_choice" == "1" ]; then
            python attack_modules/sql_injection_attack.py "$url" -v
        elif [ "$sql_choice" == "2" ]; then
            read -p "Enter parameters (comma-separated): " params
            python attack_modules/sql_injection_attack.py "$url" -p "$params" -v
        else
            read -p "Enter parameters (comma-separated): " params
            read -p "Save report? (y/n): " save
            if [ "$save" == "y" ]; then
                filename="reports/sqli_$(date +%Y%m%d_%H%M%S).json"
                python attack_modules/sql_injection_attack.py "$url" -p "$params" --aggressive -v -o "$filename"
                echo "[+] Report saved to: $filename"
            else
                python attack_modules/sql_injection_attack.py "$url" -p "$params" --aggressive -v
            fi
        fi
        pause
        ;;
    3)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  🔗 XSS SCANNER (Advanced v3.0)                           ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        read -p "Enter target URL: " url
        echo ""
        echo "Scan modes:"
        echo "  [1] Quick scan"
        echo "  [2] Custom parameters"
        echo "  [3] Full scan (all payloads)"
        read -p "Choose [1-3]: " xss_choice
        
        if [ "$xss_choice" == "1" ]; then
            python attack_modules/xss_attack.py "$url" -v
        elif [ "$xss_choice" == "2" ]; then
            read -p "Enter parameters (comma-separated): " params
            python attack_modules/xss_attack.py "$url" -p "$params" -v
        else
            read -p "Enter parameters (comma-separated): " params
            read -p "Save report? (y/n): " save
            if [ "$save" == "y" ]; then
                filename="reports/xss_$(date +%Y%m%d_%H%M%S).json"
                python attack_modules/xss_attack.py "$url" -p "$params" -v -o "$filename"
                echo "[+] Report saved to: $filename"
            else
                python attack_modules/xss_attack.py "$url" -p "$params" -v
            fi
        fi
        pause
        ;;
    4)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  🔨 BRUTE FORCE LOGIN ATTACK                              ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        read -p "Enter login URL: " url
        echo ""
        echo "Attack modes:"
        echo "  [1] Single username with wordlist"
        echo "  [2] Username + Password wordlists"
        echo "  [3] Credential stuffing"
        read -p "Choose [1-3]: " bf_choice
        
        if [ "$bf_choice" == "1" ]; then
            read -p "Enter username: " username
            read -p "Wordlist file [attack_modules/passwords.txt]: " wordlist
            wordlist=${wordlist:-attack_modules/passwords.txt}
            python attack_modules/brute_force_attack.py "$url" --username "$username" --wordlist "$wordlist" -v
        elif [ "$bf_choice" == "2" ]; then
            read -p "Username file [attack_modules/usernames.txt]: " ufile
            ufile=${ufile:-attack_modules/usernames.txt}
            read -p "Password file [attack_modules/passwords.txt]: " pfile
            pfile=${pfile:-attack_modules/passwords.txt}
            python attack_modules/brute_force_attack.py "$url" -U "$ufile" -P "$pfile" -v
        else
            python attack_modules/brute_force_attack.py "$url" --credential-stuffing -v
        fi
        pause
        ;;
    5)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  🗄️  MYSQL ATTACK MODULE                                  ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        read -p "Enter MySQL target (URL/domain/IP): " host
        read -p "Enter port [3306]: " port
        port=${port:-3306}
        echo ""
        echo "Attack modes:"
        echo "  [1] Test default credentials"
        echo "  [2] Test defaults + enumerate"
        echo "  [3] Brute force attack"
        read -p "Choose [1-3]: " mysql_choice
        
        if [ "$mysql_choice" == "1" ]; then
            python attack_modules/mysql_attack.py "$host" --port "$port" -v
        elif [ "$mysql_choice" == "2" ]; then
            read -p "Save report? (y/n): " save
            if [ "$save" == "y" ]; then
                filename="reports/mysql_$(date +%Y%m%d_%H%M%S).json"
                python attack_modules/mysql_attack.py "$host" --port "$port" --enumerate -v -o "$filename"
                echo "[+] Report saved to: $filename"
            else
                python attack_modules/mysql_attack.py "$host" --port "$port" --enumerate -v
            fi
        else
            read -p "Username file [attack_modules/usernames.txt]: " ufile
            ufile=${ufile:-attack_modules/usernames.txt}
            read -p "Password file [attack_modules/passwords.txt]: " pfile
            pfile=${pfile:-attack_modules/passwords.txt}
            read -p "Threads [5]: " threads
            threads=${threads:-5}
            python attack_modules/mysql_attack.py "$host" --port "$port" --brute-force -U "$ufile" -P "$pfile" --threads "$threads" -v
        fi
        pause
        ;;
    6)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  📁 FTP ATTACK MODULE                                     ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        read -p "Enter FTP target (URL/domain/IP): " host
        read -p "Enter port [21]: " port
        port=${port:-21}
        echo ""
        echo "Attack modes:"
        echo "  [1] Test anonymous + default credentials"
        echo "  [2] Test credentials + enumerate"
        echo "  [3] Brute force attack"
        read -p "Choose [1-3]: " ftp_choice
        
        if [ "$ftp_choice" == "1" ]; then
            python attack_modules/ftp_attack.py "$host" --port "$port" -v
        elif [ "$ftp_choice" == "2" ]; then
            read -p "Save report? (y/n): " save
            if [ "$save" == "y" ]; then
                filename="reports/ftp_$(date +%Y%m%d_%H%M%S).json"
                python attack_modules/ftp_attack.py "$host" --port "$port" --enumerate -v -o "$filename"
                echo "[+] Report saved to: $filename"
            else
                python attack_modules/ftp_attack.py "$host" --port "$port" --enumerate -v
            fi
        else
            read -p "Username file [attack_modules/usernames.txt]: " ufile
            ufile=${ufile:-attack_modules/usernames.txt}
            read -p "Password file [attack_modules/passwords.txt]: " pfile
            pfile=${pfile:-attack_modules/passwords.txt}
            read -p "Threads [3]: " threads
            threads=${threads:-3}
            python attack_modules/ftp_attack.py "$host" --port "$port" --brute-force -U "$ufile" -P "$pfile" --threads "$threads" -v
        fi
        pause
        ;;
    7)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  ⚙️  CPANEL/WHM ATTACK MODULE                             ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        read -p "Enter cPanel/WHM URL (e.g., https://host:2087): " url
        echo ""
        echo "Attack modes:"
        echo "  [1] Security audit (test defaults, headers, SSL)"
        echo "  [2] Security audit + save report"
        echo "  [3] Brute force attack (⚠️  may lock accounts)"
        read -p "Choose [1-3]: " cpanel_choice
        
        if [ "$cpanel_choice" == "1" ]; then
            python attack_modules/cpanel_attack.py "$url" -v
        elif [ "$cpanel_choice" == "2" ]; then
            filename="reports/cpanel_$(date +%Y%m%d_%H%M%S).json"
            python attack_modules/cpanel_attack.py "$url" -v -o "$filename"
            echo "[+] Report saved to: $filename"
        else
            echo ""
            echo "⚠️  WARNING: Brute forcing may trigger account lockouts!"
            read -p "Continue? (yes/no): " confirm
            if [ "$confirm" == "yes" ]; then
                read -p "Username file [attack_modules/usernames.txt]: " ufile
                ufile=${ufile:-attack_modules/usernames.txt}
                read -p "Password file [attack_modules/passwords.txt]: " pfile
                pfile=${pfile:-attack_modules/passwords.txt}
                python attack_modules/cpanel_attack.py "$url" --brute-force -U "$ufile" -P "$pfile" -v
            else
                echo "[*] Brute force cancelled"
            fi
        fi
        pause
        ;;
    8)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  🚀 ADVANCED PORT SCANNER v2.0                            ║"
        echo "║  OS Detection | Service Fingerprinting | CVE Lookup       ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        read -p "Enter target (URL/domain/IP): " target
        echo ""
        echo "Scan types:"
        echo "  [1] Common ports (Top 100)"
        echo "  [2] Custom port range"
        echo "  [3] Top N ports"
        echo "  [4] All ports (1-65535 - SLOW!)"
        read -p "Choose [1-4]: " scan_choice
        
        if [ "$scan_choice" == "1" ]; then
            read -p "Save report? (y/n): " save
            if [ "$save" == "y" ]; then
                filename="reports/portscan_$(date +%Y%m%d_%H%M%S).json"
                python network_attacks/advanced_port_scanner.py "$target" --common -o "$filename"
            else
                python network_attacks/advanced_port_scanner.py "$target" --common
            fi
        elif [ "$scan_choice" == "2" ]; then
            read -p "Port range (e.g., 1-1000 or 80,443,3306): " ports
            read -p "Threads [100]: " threads
            threads=${threads:-100}
            python network_attacks/advanced_port_scanner.py "$target" -p "$ports" -t "$threads"
        elif [ "$scan_choice" == "3" ]; then
            read -p "Number of top ports [100]: " topn
            topn=${topn:-100}
            python network_attacks/advanced_port_scanner.py "$target" --top "$topn"
        else
            echo "⚠️  WARNING: This will take considerable time!"
            read -p "Threads [200]: " threads
            threads=${threads:-200}
            python network_attacks/advanced_port_scanner.py "$target" --all -t "$threads"
        fi
        pause
        ;;
    9)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  🕷️  ADVANCED WEB CRAWLER v2.0                            ║"
        echo "║  JS Analysis | API Discovery | Vulnerability Detection    ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        read -p "Enter URL to crawl: " url
        read -p "Crawl depth [3]: " depth
        depth=${depth:-3}
        read -p "Max URLs [500]: " maxurls
        maxurls=${maxurls:-500}
        read -p "Save report? (y/n): " save
        
        if [ "$save" == "y" ]; then
            filename="reports/crawl_$(date +%Y%m%d_%H%M%S).json"
            python network_attacks/advanced_web_crawler.py "$url" -d "$depth" -m "$maxurls" -o "$filename"
        else
            python network_attacks/advanced_web_crawler.py "$url" -d "$depth" -m "$maxurls"
        fi
        pause
        ;;
    10)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  🔍 ADVANCED SERVICE IDENTIFIER v2.0                      ║"
        echo "║  CVE Database | Exploit Correlation | Security Audit      ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        read -p "Enter target (URL/domain/IP): " target
        echo ""
        echo "Scan modes:"
        echo "  [1] Single port"
        echo "  [2] Multiple ports"
        echo "  [3] Common services"
        read -p "Choose [1-3]: " service_choice
        
        if [ "$service_choice" == "1" ]; then
            read -p "Enter port number: " port
            python network_attacks/advanced_service_identifier.py "$target" -p "$port"
        elif [ "$service_choice" == "2" ]; then
            read -p "Enter ports (comma-separated, e.g., 80,443,3306): " ports
            read -p "Save report? (y/n): " save
            if [ "$save" == "y" ]; then
                filename="reports/service_$(date +%Y%m%d_%H%M%S).json"
                python network_attacks/advanced_service_identifier.py "$target" -p "$ports" -o "$filename"
            else
                python network_attacks/advanced_service_identifier.py "$target" -p "$ports"
            fi
        else
            read -p "Save report? (y/n): " save
            if [ "$save" == "y" ]; then
                filename="reports/service_$(date +%Y%m%d_%H%M%S).json"
                python network_attacks/advanced_service_identifier.py "$target" --common -o "$filename"
            else
                python network_attacks/advanced_service_identifier.py "$target" --common
            fi
        fi
        pause
        ;;
    11)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  🔬 ADVANCED PORT ANALYSIS                                ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        read -p "Enter target (URL/domain/IP): " target
        read -p "Enter port to analyze: " port
        echo ""
        echo "Analysis options:"
        echo "  [1] Banner grabbing only"
        echo "  [2] Full analysis (HTTP, HTTPS, FTP, SSH)"
        echo "  [3] Vulnerability testing"
        read -p "Choose [1-3]: " analysis_choice
        
        if [ "$analysis_choice" == "1" ]; then
            python network_attacks/advanced_port_analysis.py "$target" "$port" --banner-only
        elif [ "$analysis_choice" == "2" ]; then
            python network_attacks/advanced_port_analysis.py "$target" "$port" --full
        else
            python network_attacks/advanced_port_analysis.py "$target" "$port" --test-vulns
        fi
        pause
        ;;
    12)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  🔎 SERVICE ENUMERATOR                                    ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        read -p "Enter target (URL/domain/IP): " target
        read -p "Enter port to enumerate: " port
        echo ""
        echo "Enumeration depth:"
        echo "  [1] Basic (banner + protocol detection)"
        echo "  [2] Standard (+ version detection)"
        echo "  [3] Aggressive (full fingerprinting)"
        read -p "Choose [1-3]: " enum_choice
        
        if [ "$enum_choice" == "1" ]; then
            python network_attacks/service_enumerator.py "$target" "$port"
        elif [ "$enum_choice" == "2" ]; then
            python network_attacks/service_enumerator.py "$target" "$port" --standard
        else
            python network_attacks/service_enumerator.py "$target" "$port" --aggressive
        fi
        pause
        ;;
    13)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  SUBDOMAIN SCANNER & TAKEOVER                            ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        read -p "Enter target domain (e.g., example.com): " domain
        read -p "Number of threads [20]: " threads
        threads=${threads:-20}
        read -p "Save report? (y/n): " save
        
        if [ "$save" == "y" ]; then
            filename="reports/subdomain_$(date +%Y%m%d_%H%M%S).json"
            python network_attacks/subdomain_scanner.py "$domain" -t "$threads" -o "$filename"
            echo "[+] Report saved to: $filename"
        else
            python network_attacks/subdomain_scanner.py "$domain" -t "$threads"
        fi
        pause
        ;;
    14)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  📁 DIRECTORY & FILE FUZZER                               ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        read -p "Enter target URL: " url
        read -p "Number of threads [20]: " threads
        threads=${threads:-20}
        read -p "Save report? (y/n): " save
        
        if [ "$save" == "y" ]; then
            filename="reports/directory_$(date +%Y%m%d_%H%M%S).json"
            python network_attacks/directory_fuzzer.py "$url" -t "$threads" -o "$filename"
            echo "[+] Report saved to: $filename"
        else
            python network_attacks/directory_fuzzer.py "$url" -t "$threads"
        fi
        pause
        ;;
    15)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  🔧 TECHNOLOGY FINGERPRINTER                              ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        read -p "Enter target URL: " url
        read -p "Save report? (y/n): " save
        
        if [ "$save" == "y" ]; then
            filename="reports/fingerprint_$(date +%Y%m%d_%H%M%S).json"
            python network_attacks/tech_fingerprinter.py "$url" -o "$filename"
            echo "[+] Report saved to: $filename"
        else
            python network_attacks/tech_fingerprinter.py "$url"
        fi
        pause
        ;;
    16)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  🔓 JWT SECURITY ANALYZER                                 ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        read -p "Enter JWT token: " token
        read -p "Use wordlist for brute-force? (y/n): " use_wordlist
        
        if [ "$use_wordlist" == "y" ]; then
            read -p "Wordlist file path [attack_modules/passwords.txt]: " wordlist
            wordlist=${wordlist:-attack_modules/passwords.txt}
            python attack_modules/jwt_analyzer.py "$token" -w "$wordlist" -v
        else
            python attack_modules/jwt_analyzer.py "$token" -v
        fi
        pause
        ;;
    17)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  🌐 SSRF SCANNER                                          ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        read -p "Enter target URL (with parameters): " url
        echo ""
        echo "Test options:"
        echo "  [1] Full scan (cloud + internal + file)"
        echo "  [2] Cloud metadata only"
        echo "  [3] Internal network only"
        echo "  [4] Custom (with callback URL)"
        read -p "Choose [1-4]: " ssrf_choice
        
        if [ "$ssrf_choice" == "1" ]; then
            python attack_modules/ssrf_scanner.py "$url" -v
        elif [ "$ssrf_choice" == "2" ]; then
            python attack_modules/ssrf_scanner.py "$url" --skip-internal --skip-file -v
        elif [ "$ssrf_choice" == "3" ]; then
            python attack_modules/ssrf_scanner.py "$url" --skip-cloud --skip-file -v
        else
            read -p "Enter callback URL (e.g., http://attacker.com/callback): " callback
            python attack_modules/ssrf_scanner.py "$url" --callback "$callback" -v
        fi
        pause
        ;;
    18)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  📧 EMAIL HARVESTER                                       ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        read -p "Enter target URL or domain: " target
        read -p "Crawl depth [2]: " depth
        depth=${depth:-2}
        read -p "Result limit [100]: " limit
        limit=${limit:-100}
        read -p "Save to file? (y/n): " save
        
        if [ "$save" == "y" ]; then
            filename="reports/emails_$(date +%Y%m%d_%H%M%S).txt"
            python osint_module/email_harvester.py "$target" --depth "$depth" --limit "$limit" -o "$filename" -v
            echo "[+] Emails saved to: $filename"
        else
            python osint_module/email_harvester.py "$target" --depth "$depth" --limit "$limit" -v
        fi
        pause
        ;;
    19)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  📄 METADATA EXTRACTOR                                    ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        read -p "Enter file path: " filepath
        python osint_module/metadata_extractor.py "$filepath"
        pause
        ;;
    20)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  🛡️  SECURITY HARDENING & AUDIT                           ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        echo "Hardening modes:"
        echo "  [1] Quick audit (basic security check)"
        echo "  [2] Full audit (comprehensive analysis)"
        echo "  [3] Auto-remediate (requires sudo)"
        echo "  [4] Custom target audit"
        read -p "Choose [1-4]: " harden_choice
        
        if [ "$harden_choice" == "1" ]; then
            read -p "Enter target domain/IP: " target
            python security_tools/harden.py verify "$target"
        elif [ "$harden_choice" == "2" ]; then
            read -p "Enter target domain/IP: " target
            read -p "Audit depth (white/orange/red) [red]: " depth
            depth=${depth:-red}
            filename="reports/audit_$(date +%Y%m%d_%H%M%S).json"
            python security_tools/harden.py audit "$target" --depth "$depth" --report "$filename"
            echo "[+] Audit report saved to: $filename"
        elif [ "$harden_choice" == "3" ]; then
            read -p "Enter audit report file: " report_file
            if [ -f "$report_file" ]; then
                sudo python security_tools/harden.py defend "$report_file"
            else
                echo "[!] Report file not found: $report_file"
            fi
        else
            read -p "Enter target domain/IP: " target
            read -p "Audit depth (white/orange/red) [red]: " depth
            depth=${depth:-red}
            filename="reports/audit_$(date +%Y%m%d_%H%M%S).json"
            python security_tools/harden.py audit "$target" --depth "$depth" --report "$filename" --skip-auth
            echo "[+] Audit report saved to: $filename"
            echo "[!] WARNING: Ran without ownership verification"
        fi
        pause
        ;;
    21)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  🚨 EMERGENCY HARDENING SCRIPT                            ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        echo "⚠️  WARNING: This script will make significant security changes!"
        echo ""
        echo "Changes include:"
        echo "  • Generate new root password"
        echo "  • Restrict WHM access by IP"
        echo "  • Enable 2FA"
        echo "  • Secure MySQL/FTP"
        echo "  • Add security headers"
        echo ""
        read -p "Are you sure you want to continue? (yes/no): " confirm
        
        if [ "$confirm" == "yes" ]; then
            if [ -f "security_tools/emergency_hardening.sh" ]; then
                sudo bash security_tools/emergency_hardening.sh
            else
                echo "[!] Emergency hardening script not found!"
                echo "[*] Create it first or check security_tools/ directory"
            fi
        else
            echo "[*] Emergency hardening cancelled"
        fi
        pause
        ;;
    22)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  💻 INTERACTIVE SHELL                                     ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        echo "[*] Opening interactive shell..."
        echo "[*] Virtual environment is active"
        echo "[*] Type 'exit' to return to launcher"
        echo ""
        bash
        ;;
    23)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  📊 VIEW REPORTS                                          ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        if [ ! -d "reports" ] || [ -z "$(ls -A reports)" ]; then
            echo "[!] No reports found in reports/ directory"
        else
            echo "[*] Available reports:"
            echo ""
            ls -lh reports/ | tail -n +2
            echo ""
            read -p "Enter report filename to view (or press ENTER to skip): " report
            if [ ! -z "$report" ]; then
                if [ -f "reports/$report" ]; then
                    echo ""
                    echo "[*] Report contents:"
                    echo ""
                    if [[ "$report" == *.json ]]; then
                        cat "reports/$report" | python -m json.tool 2>/dev/null || cat "reports/$report"
                    elif [[ "$report" == *.md ]]; then
                        less "reports/$report"
                    else
                        cat "reports/$report"
                    fi
                else
                    echo "[!] Report not found: reports/$report"
                fi
            fi
        fi
        pause
        ;;
    24)
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║  🚀 QUICK SITE AUDIT                                      ║"
        echo "║  Fingerprint + Crawl + Directory Fuzz                     ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        read -p "Enter target URL or domain: " target
        read -p "Crawl depth [2]: " depth
        depth=${depth:-2}
        read -p "Max URLs to crawl [150]: " maxurls
        maxurls=${maxurls:-150}
        read -p "Max paths to fuzz [80]: " maxpaths
        maxpaths=${maxpaths:-80}
        read -p "Threads [12]: " threads
        threads=${threads:-12}
        read -p "Timeout (seconds) [10]: " timeout
        timeout=${timeout:-10}
        read -p "Proxy (optional, e.g., http://127.0.0.1:8080): " proxy
        read -p "Disable TLS verification? (y/n): " insecure

        proxy_args=()
        if [ -n "${proxy}" ]; then
            proxy_args=(--proxy "$proxy")
        fi

        tls_args=()
        if [ "$insecure" == "y" ]; then
            tls_args=(--insecure)
        fi

        filename="reports/site_audit_$(date +%Y%m%d_%H%M%S).json"
        python site_audit.py "$target" --depth "$depth" --max-urls "$maxurls" --max-paths "$maxpaths" --threads "$threads" --timeout "$timeout" "${proxy_args[@]}" "${tls_args[@]}" -o "$filename"
        echo "[+] Combined audit saved to: $filename"
        pause
        ;;
    0)
        echo ""
        echo "[*] Thank you for using CyberAttack Lab v4.0"
        echo "[*] Remember: Use only on authorized targets!"
        echo ""
        exit 0
        ;;
    *)
        echo ""
        echo "[!] Invalid choice: $choice"
        echo "[!] Please enter a number between 0 and 24"
        pause
        ;;
esac

# Loop back to menu
exec "$0"
