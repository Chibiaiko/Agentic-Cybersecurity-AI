#!/usr/bin/env python3
"""
Test script to verify ANSI color codes are displaying correctly
"""

from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)

print("\n" + "="*80)
print("RISK LEVEL COLOR TEST")
print("="*80 + "\n")

# Test Risk Summary Colors
print("Risk Summary Colors:")
print("-" * 40)

# CRITICAL - Bright Red
critical_color = f"{Fore.RED}{Style.BRIGHT}CRITICAL{Style.RESET_ALL}"
print(f"{critical_color}: 2")

# HIGH - Honey color #EC9706
high_color = f"\033[38;5;214mHIGH\033[0m"
print(f"{high_color}: 5")

# MEDIUM - Yellow
medium_color = f"{Fore.YELLOW}MEDIUM{Style.RESET_ALL}"
print(f"{medium_color}: 4")

# LOW - Bright Green
low_color = f"{Fore.GREEN}{Style.BRIGHT}LOW{Style.RESET_ALL}"
print(f"{low_color}: 1")

# INFO - White
info_color = f"{Fore.WHITE}INFO{Style.RESET_ALL}"
print(f"{info_color}: 0")

print("\n" + "="*80)
print("Risk List Example:")
print("="*80 + "\n")

# Test Risk List Colors
risks = [
    {
        "severity": "CRITICAL",
        "id": "NET-001",
        "title": "Hardcoded AWS Credentials",
        "component": "build-deploy.yaml",
        "description": "Found AWS_ACCESS_KEY_ID in build script"
    },
    {
        "severity": "HIGH",
        "id": "NET-002",
        "title": "Root SSH Login Enabled",
        "component": "sshd_config",
        "description": "SSH allows direct root login"
    },
    {
        "severity": "MEDIUM",
        "id": "SYS-003",
        "title": "Firewall Not Running",
        "component": "prod-server-01",
        "description": "The system firewall is not running"
    },
    {
        "severity": "LOW",
        "id": "PKG-004",
        "title": "Outdated Package",
        "component": "requirements.txt",
        "description": "Some dependencies have newer versions"
    },
    {
        "severity": "INFO",
        "id": "LOG-005",
        "title": "Missing Documentation",
        "component": "src/auth/handler.py",
        "description": "Security-sensitive functions lack documentation"
    }
]

for risk in risks:
    severity = risk["severity"]
    
    # Format severity with proper ANSI color codes
    if severity == "CRITICAL":
        colored_severity = f"{Fore.RED}{Style.BRIGHT}{severity}{Style.RESET_ALL}"
    elif severity == "HIGH":
        # Honey color #EC9706 using ANSI 256-color code
        colored_severity = f"\033[38;5;214m{severity}\033[0m"
    elif severity == "MEDIUM":
        colored_severity = f"{Fore.YELLOW}{severity}{Style.RESET_ALL}"
    elif severity == "LOW":
        colored_severity = f"{Fore.GREEN}{Style.BRIGHT}{severity}{Style.RESET_ALL}"
    else:  # INFO
        colored_severity = f"{Fore.WHITE}{severity}{Style.RESET_ALL}"
    
    print(f"{colored_severity} {risk['id']}: {risk['title']}")
    print(f"  Component: {risk['component']}")
    print(f"  Description: {risk['description']}")
    print("")

print("="*80)
print("Color Test Complete!")
print("="*80)
print("\nExpected Colors:")
print("  CRITICAL: Bright RED text")
print("  HIGH: HONEY (#EC9706) text")
print("  MEDIUM: YELLOW text (normal brightness)")
print("  LOW: Bright GREEN text")
print("  INFO: WHITE text")
