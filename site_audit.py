#!/usr/bin/env python3
"""
SecurityNexus Quick Site Audit
Runs a fast recon stack (fingerprinting, directory fuzzing, crawling)
with shared HTTP controls so you can check a target in one command.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from common.http_client import build_session
from network_attacks.advanced_web_crawler import AdvancedWebCrawler
from network_attacks.directory_fuzzer import DirectoryFuzzer
from network_attacks.tech_fingerprinter import TechnologyFingerprinter


def normalize_target(raw: str) -> str:
    """Ensure the target has a scheme so downstream modules behave."""
    if not raw.startswith(("http://", "https://")):
        return "https://" + raw.strip("/")
    return raw.rstrip("/")


def build_output_path(custom_path: str | None) -> Path:
    """Return the output path (create reports/ by default)."""
    if custom_path:
        return Path(custom_path)
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return reports_dir / f"site_audit_{timestamp}.json"


def run_audit(args) -> Dict[str, Any]:
    """Run the selected audit modules and return combined report."""
    target = normalize_target(args.target)

    shared_session = build_session(
        timeout=args.timeout,
        proxy=args.proxy,
        user_agent=args.user_agent,
        verify=not args.insecure,
        retries=args.retries,
    )

    combined: Dict[str, Any] = {
        "target": target,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "settings": {
            "timeout": args.timeout,
            "proxy": args.proxy,
            "user_agent": args.user_agent,
            "verify_tls": not args.insecure,
            "retries": args.retries,
            "max_paths": args.max_paths,
            "max_urls": args.max_urls,
            "depth": args.depth,
            "threads": args.threads,
        },
        "results": {},
        "errors": [],
    }

    if not args.skip_fingerprint:
        print("\n[+] Running technology fingerprinting...")
        try:
            fp = TechnologyFingerprinter(
                target_url=target,
                verbose=args.verbose,
                timeout=args.timeout,
                proxy=args.proxy,
                user_agent=args.user_agent,
                verify=not args.insecure,
                retries=args.retries,
                session=shared_session,
            )
            combined["results"]["fingerprint"] = fp.fingerprint()
        except Exception as exc:
            combined["errors"].append(f"fingerprint: {exc}")
            if args.verbose:
                raise

    if not args.skip_fuzzer:
        print("\n[+] Running directory & file fuzzing...")
        try:
            fuzzer = DirectoryFuzzer(
                base_url=target,
                threads=args.threads,
                max_paths=args.max_paths,
                timeout=args.timeout,
                proxy=args.proxy,
                user_agent=args.user_agent,
                verify=not args.insecure,
                retries=args.retries,
            )
            fuzzer.fuzz_directory()
            combined["results"]["directories"] = fuzzer.generate_report()
        except Exception as exc:
            combined["errors"].append(f"directory_fuzzer: {exc}")
            if args.verbose:
                raise

    if not args.skip_crawler:
        print("\n[+] Running web crawler...")
        try:
            crawler = AdvancedWebCrawler(
                base_url=target,
                max_depth=args.depth,
                max_urls=args.max_urls,
                threads=args.threads,
                timeout=args.timeout,
                proxy=args.proxy,
                user_agent=args.user_agent,
                verify=not args.insecure,
                retries=args.retries,
                verbose=args.verbose,
            )
            crawler.start_crawling()
            combined["results"]["crawler"] = crawler.generate_report()
        except Exception as exc:
            combined["errors"].append(f"crawler: {exc}")
            if args.verbose:
                raise

    return combined


def parse_args():
    parser = argparse.ArgumentParser(
        description="Quick multi-module site audit (recon + fingerprint + fuzzing)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", help="Target URL or domain (e.g., https://example.com)")
    parser.add_argument("--depth", type=int, default=2, help="Crawler depth")
    parser.add_argument("--max-urls", type=int, default=150, help="Max URLs to crawl")
    parser.add_argument("--threads", type=int, default=12, help="Thread count for fuzzing/crawler")
    parser.add_argument("--max-paths", type=int, default=80, help="Limit number of paths for the fuzzer")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--retries", type=int, default=2, help="Retry count for transient failures")
    parser.add_argument("--proxy", help="HTTP/SOCKS proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--user-agent", help="Custom User-Agent")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    parser.add_argument("--skip-crawler", action="store_true", help="Skip crawler module")
    parser.add_argument("--skip-fingerprint", action="store_true", help="Skip tech fingerprinting module")
    parser.add_argument("--skip-fuzzer", action="store_true", help="Skip directory fuzzer module")
    parser.add_argument("-o", "--output", help="Output JSON path (defaults to reports/site_audit_<timestamp>.json)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose errors (raise on failure)")
    return parser.parse_args()


def main():
    args = parse_args()
    output_path = build_output_path(args.output)

    try:
        report = run_audit(args)
    except Exception as exc:  # pragma: no cover - safety net
        print(f"[x] Fatal error: {exc}")
        raise

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[+] Combined report saved to: {output_path}")
    if report.get("errors"):
        print("[!] Some modules reported errors:")
        for err in report["errors"]:
            print(f"    - {err}")


if __name__ == "__main__":
    main()
