# main.py
import sys
from utils import (
    generate_case_id, print_green, print_red, 
    print_yellow, print_blue
)
from secrets_ import LOG_ANALYTICS_WORKSPACE_ID, API_KEY
from models import AIModel
from log_analytics_queries import LogAnalyticsQuery
from function_tools import SecurityAnalystFunctions
from tool_routing import route_tool
from summary_generator import generate_reports
from remediation_actions import get_brief_remediation


def main():
    """
    Main entry point for Zero Trust Agentic AI Security Assessment System.
    
    This system:
    1. Authenticates to Azure Log Analytics
    2. Initializes the AI model for analysis
    3. Routes user commands to analysis tools
    4. Runs Zero Trust assessments with scoring
    5. Generates comprehensive reports (TXT, JSON, PDF)
    """
    
    print_blue("\n" + "="*80)
    print_blue("ZERO TRUST AGENTIC AI - SECURITY ASSESSMENT SYSTEM")
    print_blue("="*80 + "\n")
    
    # 1. Generate Case ID
    case_id = generate_case_id()
    print(f"📋 Case ID: {case_id}\n")
    
    # 2. Initialize Components
    try:
        print("[INIT] Initializing Log Analytics connection...")
        la_query = LogAnalyticsQuery()
        print_green("✅ Log Analytics initialized\n")
        
        print("[INIT] Initializing AI Model...")
        ai_model = AIModel(model_name="gpt-5-nano")
        print_green("✅ AI Model initialized\n")
        
        print("[INIT] Initializing Security Analysis Functions...")
        functions = SecurityAnalystFunctions(ai_model)
        print_green("✅ Security Functions initialized\n")
        
    except Exception as e:
        print_red(f"❌ Initialization Error: {e}")
        sys.exit(1)
    
    # 3. Available Commands (uncomment one to run)
    # command = "run assessment"  # Run full 8-step Zero Trust assessment with scoring, MITRE tagging, and report generation
    # command = "analyze"  # Alternative trigger for Zero Trust assessment with same analysis
    # command = "zero trust"  # Alternative trigger for Zero Trust assessment with same analysis
    # command = "query SecurityEvent"  # Query Windows Security events from Log Analytics (configurable hours)
    # command = "query SigninLogs"  # Query Azure AD sign-in logs from Log Analytics (configurable hours)
    # command = "query AuditLogs"  # Query Azure AD audit logs from Log Analytics (configurable hours)
    # command = "query DeviceProcessEvents"  # Query endpoint device process events from Log Analytics (configurable hours)
    # command = "query DeviceNetworkEvents"  # Query endpoint device network events from Log Analytics (configurable hours)
    # command = "query CloudAppEvents"  # Query Microsoft Defender for Cloud Apps events from Log Analytics (configurable hours)
    
    # Default command
    command = "run assessment"  # Currently active - executes full Zero Trust assessment
    
    # Default time range     timerange_hours = 24  # located in the log_analytics_queries
    from log_analytics_queries import timerange_hours
    
    print(f"[COMMAND] Running: {command}")
    print(f"[TIME RANGE] Set to: {timerange_hours} hours\n")
    
    # 4. Route Command
    print_yellow("\n[ACTION] Processing command...\n")
    
    # Check if it's a query command
    if "query" in command.lower():
        table_name = command.split("query")[-1].strip()
        if table_name:
            print(f"📊 Querying table: {table_name}")
            print(f"⏱️  Time range: {timerange_hours} hours")
            results = la_query.query_logs(table_name=table_name, timerange_hours=timerange_hours)
            if results:
                print_green("✅ Query completed")
            else:
                print_red("❌ Query failed")
        sys.exit(0)
    
    # Route to Zero Trust assessment
    step_results = route_tool(command, functions)
    
    if not step_results:
        print_red("❌ No action taken. Please use 'run', 'analyze', or 'zero trust'.")
        sys.exit(0)
    
    # 5. Run Zero Trust Assessment
    print_green(f"✅ Zero Trust Assessment initiated\n")
    print("[ANALYSIS] Running 8-step Zero Trust assessment...\n")
    
    for step in step_results:
        status = "🚨 FLAGGED" if step["flag"] else "✅ CLEAR"
        print(f"{status} | Step {step['step']}: {step['description'][:60]}...")
        print(f"        Score: {step['score']}/10 | Confidence: {step['confidence']} | MITRE: {step['mitre']}")
        
        # Display brief remediation for flagged steps
        if step["flag"]:
            brief_remediation = get_brief_remediation(step['step'])
            print(f"        → {brief_remediation}\n")
    
    # 6. Generate Reports
    print_yellow("\n[REPORTING] Generating comprehensive reports...\n")
    
    result = generate_reports(case_id, step_results)
    
    # 7. Display Summary
    print_blue("\n" + "="*80)
    print_blue("ASSESSMENT SUMMARY")
    print_blue("="*80 + "\n")
    
    print(f"Case ID: {result['case_id']}")
    print_blue(f"Severity: {result['severity']}")
    print_green(f"Risk Score: {result['risk_score']}/10")
    print(f"30-Day Baseline: {result['baseline']}")
    print(f"Escalation Triggered: {result['escalation_triggered']}")
    
    print_blue("\n" + "="*80)
    print("📄 Generated Files:")
    for file_type, path in result['files'].items():
        print(f"  • {file_type.upper()}: {path}")
    print_blue("="*80 + "\n")
    
    print_green("✅ Zero Trust Assessment Complete\n")


if __name__ == "__main__":
    main()
