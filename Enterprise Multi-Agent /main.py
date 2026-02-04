import os
import json
import argparse
from datetime import datetime
from colorama import Fore, Back, Style, init
from agents.pipeline_agent import PipelineAnalysisAgent
from agents.risk_agent import RiskClassificationAgent
from agents.business_agent import BusinessImpactAgent
from agents.financial_agent import FinancialLossAgent
from agents.compliance_agent import ComplianceMappingAgent
from agents.reporting_agent import ReportingAgent
from utils.formatting import print_header, console, get_risk_style, format_currency
from models.risk_model import RiskLevel

# Initialize colorama
init(autoreset=True)

def prompt_for_scan_hostname():
    """Prompt user for hostname to scan"""
    print("\n" + "=" * 80)
    console.print("[bold cyan]ENTER HOSTNAME TO SCAN[/bold cyan]")
    print("=" * 80)
    
    while True:
        hostname = input("\nEnter hostname to scan: ").strip()
        if hostname:
            return hostname
        console.print("[red]Hostname cannot be empty. Please try again.[/red]")

def main():
    parser = argparse.ArgumentParser(description="Enterprise Multi-Agent Security Platform")
    parser.add_argument("--scan", type=str, help="Path to pipeline file (dummy)", default="./pipeline.yaml")
    parser.add_argument("--hostname", type=str, help="Hostname to scan")
    args = parser.parse_args()

    print_header("ENTERPRISE SECURITY SCAN INITIALIZATION")
    
    # Get hostname - from argument or prompt
    if args.hostname:
        hostname = args.hostname
    else:
        hostname = prompt_for_scan_hostname()
    
    # 1. Initialize Tools/Connectors (No Azure/Tenable needed)
    console.print("\n[yellow]Initializing scan engine...[/yellow]")
    # Direct VM scanning - no external connectors needed

    # Get scan host information from environment variables
    console.print(f"[yellow]Preparing scan target: {hostname}[/yellow]")
    
    primary_host = {
        "hostname": hostname,
        "source": "Direct VM Scan"
    }
    console.print(f"[green]Scan target prepared: {primary_host['hostname']}[/green]")

    # 2. Pipeline Analysis
    print_header("1. PIPELINE ANALYSIS AGENT")
    console.print(f"[cyan]Scanning hostname: {hostname}[/cyan]")
    
    pipeline_agent = PipelineAnalysisAgent()
    context = {
        "hostname": hostname,
        "scan_target": primary_host
    }
    context = pipeline_agent.run(context)
    console.print(f"Found {len(context['findings'])} raw findings.")

    # 3. Risk Classification
    print_header("2. RISK CLASSIFICATION AGENT")
    risk_agent = RiskClassificationAgent()
    context = risk_agent.run(context)
    console.print(f"Classified {len(context['risks'])} technical risks.")

    # 4. Enrichment (Business, Financial, Compliance)
    print_header("3. ENRICHMENT AGENTS (Business, Financial, Compliance)")
    
    business_agent = BusinessImpactAgent()
    context = business_agent.run(context)
    
    financial_agent = FinancialLossAgent()
    context = financial_agent.run(context)
    
    compliance_agent = ComplianceMappingAgent()
    context = compliance_agent.run(context)
    console.print("Risks enriched with Business Impact, Financial Loss, and Compliance Data.")

    # 5. Reporting
    print_header("4. REPORTING AGENT")
    reporting_agent = ReportingAgent()
    context = reporting_agent.run(context)
    report = context['report']

    # --- TERMINAL OUTPUT (Simplified Risk Analysis without Audit or Data Sources) ---
    
    print_header("CI/CD SECURITY RISK ANALYSIS")
    console.print(f"Date: {report.date}\n")
    
    console.print("[bold underline]Risk Summary[/bold underline]")
    console.print(f"Total Risks Found: {len(report.risks)}")
    
    # Counts
    counts = {lvl: 0 for lvl in RiskLevel}
    for r in report.risks:
        counts[r.severity] += 1
        
    for lvl in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]:
        severity = lvl.value
        count = counts[lvl]
        
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
        
        print(f"{colored_severity}: {count}")

    console.print("\n[bold underline]Risk List[/bold underline]")
    for risk in report.risks:
        severity = risk.severity.value
        
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
        
        print(f"{colored_severity} {risk.id}: {risk.title}")
        print(f"  Component: {risk.component}")
        print(f"  Description: {risk.description}")
        print("")

    # FILE OUTPUT
    date_str = datetime.now().strftime("%m-%d-%Y")
    output_dir = f"Summary/Risk Summary {date_str}"
    os.makedirs(output_dir, exist_ok=True)

    # JSON Output
    def default_serializer(obj):
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        if isinstance(obj, RiskLevel):
            return obj.value
        return str(obj)

    json_path = os.path.join(output_dir, f"risk_summary_{date_str}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, default=default_serializer, indent=4)
    console.print(f"\n[green]JSON Report generated: {json_path}[/green]")

    # Text Output with Detailed Risk Analysis and Audit sections
    txt_path = os.path.join(output_dir, f"risk_summary_{date_str}.txt")
    
    with open(txt_path, "w", encoding="utf-8") as f:
        # Header with Enterprise Information
        f.write("=" * 80 + "\n")
        f.write("CI/CD SECURITY RISK ANALYSIS & ENTERPRISE RISK ANALYSIS REPORT\n")
        f.write("=" * 80 + "\n")
        f.write(f"Report Date: {report.date}\n")
        f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Scan Hostname: {primary_host['hostname']}\n")
        f.write(f"Scan Targets:\n")
        f.write(f"  1. Hostname: {primary_host['hostname']}\n")
        f.write("=" * 80 + "\n\n")
        
        # Executive Summary
        f.write("BOARD EXECUTIVE SUMMARY\n")
        f.write("-" * 80 + "\n")
        f.write(f"Overall Enterprise Risk Posture: {report.overall_posture}\n")
        f.write(f"CI/CD Gate Status: {report.gate_status}\n")
        f.write(f"Total Risks Identified: {len(report.risks)}\n")
        f.write(f"Risk Trend: {report.trend}\n\n")
        
        f.write("NARRATIVE:\n")
        f.write("The current pipeline scan indicates critical security deficiencies that pose significant\n")
        f.write("financial and regulatory risk. Immediate remediation of hardcoded credentials and\n")
        f.write("container privileges is required before deployment can proceed.\n\n")

        # Risk Distribution
        f.write("RISK DISTRIBUTION BY SEVERITY\n")
        f.write("-" * 80 + "\n")
        counts = {lvl: 0 for lvl in RiskLevel}
        for r in report.risks:
            counts[r.severity] += 1
        for lvl in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]:
            f.write(f"  {lvl.value:12} : {counts[lvl]:3} risks\n")
        f.write("\n")

        # Top Risks
        f.write("TOP ENTERPRISE RISKS (By Financial Exposure)\n")
        f.write("-" * 80 + "\n")
        sorted_risks = sorted(report.risks, key=lambda x: x.financial_impact.most_likely_loss if x.financial_impact else 0, reverse=True)
        
        for idx, risk in enumerate(sorted_risks, 1):
            f.write(f"{idx}. [{risk.severity.value}] {risk.title}\n")
            f.write(f"   Risk ID: {risk.id}\n")
            f.write(f"   Component: {risk.component}\n")
            if risk.financial_impact:
                f.write(f"   Est. Loss: {format_currency(risk.financial_impact.min_loss)} - {format_currency(risk.financial_impact.max_loss)}\n")
                f.write(f"   Most Likely Loss: {format_currency(risk.financial_impact.most_likely_loss)}\n")
            f.write(f"   Business Impact: {risk.business_impact.value}\n")
            f.write("\n")

        # Financial Overview
        f.write("FINANCIAL RISK OVERVIEW\n")
        f.write("-" * 80 + "\n")
        f.write(f"Minimum Potential Loss Exposure: {format_currency(report.total_financial_exposure_min)}\n")
        f.write(f"Maximum Potential Loss Exposure: {format_currency(report.total_financial_exposure_max)}\n")
        f.write(f"Risk Trend: {report.trend}\n\n")

        # ===== DETAILED RISK ANALYSIS (SEPARATE SECTION) =====
        f.write("=" * 80 + "\n")
        f.write("DETAILED RISK ANALYSIS\n")
        f.write("=" * 80 + "\n\n")
        
        for idx, risk in enumerate(sorted_risks, 1):
            f.write(f"RISK #{idx}\n")
            f.write("-" * 80 + "\n")
            f.write(f"Risk ID: {risk.id}\n")
            f.write(f"Title: {risk.title}\n")
            f.write(f"Severity: {risk.severity.value}\n")
            f.write(f"Component/File: {risk.component}\n")
            f.write(f"Description: {risk.description}\n\n")
            
            f.write("TECHNICAL DETAILS:\n")
            f.write(f"  CVSS Score: {risk.cvss_score}/10\n")
            f.write(f"  CVSS Vector: {risk.cvss_vector}\n")
            if risk.cve_id:
                f.write(f"  CVE ID: {risk.cve_id}\n")
            f.write(f"  Composite Score: {risk.composite_score:.2f}\n\n")
            
            f.write("BUSINESS IMPACT:\n")
            f.write(f"  Impact Level: {risk.business_impact.value}\n")
            if risk.financial_impact:
                f.write(f"  Min Loss: {format_currency(risk.financial_impact.min_loss)}\n")
                f.write(f"  Most Likely Loss: {format_currency(risk.financial_impact.most_likely_loss)}\n")
                f.write(f"  Max Loss: {format_currency(risk.financial_impact.max_loss)}\n")
                f.write(f"  Annualized Risk Exposure: {format_currency(risk.financial_impact.annualized_risk_exposure)}\n")
            f.write("\n")
            
            if risk.remediation_steps:
                f.write("REMEDIATION:\n")
                f.write(f"  {risk.remediation_steps}\n\n")
            
            if risk.evidence:
                f.write("EVIDENCE:\n")
                for evidence in risk.evidence:
                    f.write(f"  - {evidence}\n")
                f.write("\n")
            
            f.write("\n")

        # ===== AUDIT SECTION =====
        f.write("=" * 80 + "\n")
        f.write("AUDIT & COMPLIANCE MAPPINGS\n")
        f.write("=" * 80 + "\n\n")
        
        for idx, risk in enumerate(sorted_risks, 1):
            if risk.compliance_mappings:
                f.write(f"RISK #{idx} - {risk.title}\n")
                f.write("-" * 80 + "\n")
                f.write("COMPLIANCE MAPPINGS:\n")
                for mapping in risk.compliance_mappings:
                    f.write(f"  Framework: {mapping.framework}\n")
                    f.write(f"  Control ID: {mapping.control_id}\n")
                    f.write(f"  Control Title: {mapping.control_title}\n")
                    f.write(f"  Status: {risk.control_status.value}\n")
                f.write("\n")

        # Footer
        f.write("=" * 80 + "\n")
        f.write("END OF REPORT\n")
        f.write("=" * 80 + "\n")

    console.print(f"[green]Text Report generated: {txt_path}[/green]")
    console.print(f"[cyan]Scan Target: {primary_host['hostname']}[/cyan]")

if __name__ == "__main__":
    main()
