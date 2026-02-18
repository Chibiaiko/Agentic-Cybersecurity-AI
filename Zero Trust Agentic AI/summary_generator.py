# summary_generator.py
import os
import json
import hashlib
import datetime
import statistics
from pathlib import Path
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from utils import print_yellow, print_green, print_red
from remediation_actions import get_brief_remediation, generate_remediation_summary

BASE_DIR = "Summary"


def ensure_dirs(date_str):
    """Create necessary directories for daily and global reports."""
    day_path = os.path.join(BASE_DIR, date_str)
    global_path = os.path.join(BASE_DIR, "global")
    os.makedirs(day_path, exist_ok=True)
    os.makedirs(global_path, exist_ok=True)
    return day_path, global_path


def calculate_severity(score):
    """Calculate severity level based on risk score."""
    if score >= 8:
        return "CRITICAL"
    if score >= 6:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def downgrade_logic(score, baseline):
    """Apply downgrade logic if score is below baseline."""
    if score < baseline:
        return max(score - 1, 0)
    return score


def anomaly_density(total_flags, total_steps):
    """Calculate anomaly density ratio."""
    return round(total_flags / total_steps, 2) if total_steps > 0 else 0


def correlation_score(step_results):
    """Calculate correlation bonus based on multiple flagged findings."""
    flagged = [s for s in step_results if s.get("flag", False)]
    if len(flagged) >= 3:
        return 2
    return 0


def sign_report(text):
    """Generate SHA-256 signature for report integrity."""
    return hashlib.sha256(text.encode()).hexdigest()


def update_global_history(global_path, today_score):
    """Update 30-day rolling baseline and global risk history."""
    history_file = os.path.join(global_path, "zero_trust_global_risk_history.json")
    baseline_file = os.path.join(global_path, "zero_trust_30day_baseline.json")

    history = []

    if os.path.exists(history_file):
        try:
            with open(history_file, "r", encoding="utf-8") as f:
                history = json.load(f)
        except:
            history = []

    history.append({
        "date": str(datetime.date.today()),
        "risk": today_score
    })

    with open(history_file, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=4)

    # Calculate 30-day baseline
    last_30 = [x.get("risk", 0) for x in history[-30:]]
    baseline = round(statistics.mean(last_30), 2) if last_30 else today_score

    with open(baseline_file, "w", encoding="utf-8") as f:
        json.dump(
            {"30_day_baseline": baseline, "last_updated": str(datetime.datetime.now())},
            f,
            indent=4
        )

    return baseline, history


def generate_reports(case_id, step_results):
    """
    Generate comprehensive reports in TXT, JSON, and PDF formats.
    
    Args:
        case_id: Unique case identifier
        step_results: List of step analysis results
    
    Returns:
        Dictionary with case metadata
    """
    
    today = datetime.date.today().strftime("%m-%d-%Y")
    timestamp = datetime.datetime.now().strftime("%H%M%S")

    day_path, global_path = ensure_dirs(today)

    # Calculate scores
    total_flags = sum(1 for s in step_results if s.get("flag", False))
    base_score = round(sum(s.get("score", 0) for s in step_results) / len(step_results), 2) if step_results else 0

    correlation_boost = correlation_score(step_results)
    weighted_score = min(base_score + correlation_boost, 10)

    baseline, history = update_global_history(global_path, weighted_score)

    adjusted_score = downgrade_logic(weighted_score, baseline)
    severity = calculate_severity(adjusted_score)
    density = anomaly_density(total_flags, len(step_results))

    escalation_triggered = adjusted_score >= 8
    trend_change = round(adjusted_score - baseline, 2)

    # Executive summary
    executive_summary = (
        f"Case {case_id} produced a {severity} rating with "
        f"a risk score of {adjusted_score}. "
        f"Risk delta vs baseline ({baseline}) is {trend_change}."
    )

    # Email-ready alert
    email_alert = (
        f"Subject: Zero Trust Alert - {severity}\n"
        f"Case ID: {case_id}\n"
        f"Risk Score: {adjusted_score}\n"
        f"Anomaly Density: {density}\n"
        f"Escalation Triggered: {escalation_triggered}"
    )

    # Report data dictionary
    report_data = {
        "case_id": case_id,
        "date": today,
        "timestamp": timestamp,
        "risk_score": adjusted_score,
        "severity": severity,
        "anomaly_density": density,
        "baseline": baseline,
        "trend_change": trend_change,
        "correlation_boost": correlation_boost,
        "escalation_triggered": escalation_triggered,
        "steps": step_results,
        "executive_summary": executive_summary,
        "email_alert": email_alert
    }

    base_name = f"zero_trust_report_{timestamp}"

    # Generate JSON report
    json_path = os.path.join(day_path, f"{base_name}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4, default=str)

    # Generate TXT report with signature
    txt_content = f"""
ZERO TRUST ANALYSIS REPORT
================================================================================
Case ID: {case_id}
Date: {today}
Timestamp: {timestamp}

SEVERITY ASSESSMENT
────────────────────────────────────────────────────────────────────────────────
Severity Level: {severity}
Risk Score: {adjusted_score}/10
30-Day Baseline: {baseline}
Trend Change: {trend_change:+.2f}
Anomaly Density: {density}
Correlation Boost: {correlation_boost}
Escalation Triggered: {escalation_triggered}

EXECUTIVE SUMMARY
────────────────────────────────────────────────────────────────────────────────
{executive_summary}

STEP ANALYSIS DETAILS
────────────────────────────────────────────────────────────────────────────────
"""

    for s in step_results:
        status = "🚨 FLAGGED" if s.get("flag", False) else "✅ CLEAR"
        txt_content += (
            f"\n{status} | Step {s['step']}\n"
            f"  Description: {s['description']}\n"
            f"  Score: {s['score']}/10\n"
            f"  Confidence: {s['confidence']}\n"
            f"  MITRE ATT&CK: {s['mitre']}\n"
        )

    # Add remediation roadmap to report
    txt_content += generate_remediation_summary(step_results)

    txt_content += "\n\nGLOBAL RISK HISTORY (30 Days)\n"
    txt_content += "────────────────────────────────────────────────────────────────────────────────\n"
    
    if history:
        for entry in history[-30:]:
            date = entry.get("date", "Unknown")
            risk = entry.get("risk", 0)
            txt_content += f"{date}: Risk Score = {risk}\n"
    else:
        txt_content += "No historical data available\n"

    txt_content += "\n\nEMAIL-READY ALERT\n"
    txt_content += "────────────────────────────────────────────────────────────────────────────────\n"
    txt_content += email_alert

    # Sign the report
    signature = sign_report(txt_content)
    txt_content += f"\n\nReport Signature (SHA-256): {signature}\n"
    txt_content += "================================================================================\n"

    txt_path = os.path.join(day_path, f"{base_name}.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(txt_content)

    # Save daily risk history
    history_path = os.path.join(day_path, "zero_trust_report_risk_history.json")
    with open(history_path, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=4)

    # Generate PDF report with visualization
    pdf_path = os.path.join(day_path, f"{base_name}.pdf")
    doc = SimpleDocTemplate(pdf_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Add title and metadata
    elements.append(Paragraph(f"Zero Trust Report - Case {case_id}", styles["Heading1"]))
    elements.append(Spacer(1, 0.2 * inch))
    elements.append(Paragraph(f"Date: {today} | Severity: {severity} | Risk Score: {adjusted_score}", styles["Normal"]))
    elements.append(Spacer(1, 0.3 * inch))

    # Add chart
    drawing = Drawing(500, 250)
    chart = VerticalBarChart()
    chart.x = 50
    chart.y = 50
    chart.height = 150
    chart.width = 400
    chart.data = [[s.get("score", 0) for s in step_results]]
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = 10
    chart.valueAxis.valueStep = 2
    drawing.add(chart)
    elements.append(drawing)

    elements.append(Spacer(1, 0.3 * inch))
    elements.append(Paragraph("Executive Summary", styles["Heading2"]))
    elements.append(Paragraph(executive_summary, styles["Normal"]))

    doc.build(elements)

    # Print to console
    print_yellow(f"\n{'='*80}")
    print_green(f"✅ Reports Generated Successfully")
    print_yellow(f"{'='*80}")
    print(f"Case ID: {case_id}")
    print_red(f"Severity: {severity}")
    print_green(f"Risk Score: {adjusted_score}/10")
    print(f"Files saved to: {day_path}")
    print_yellow(f"{'='*80}\n")

    return {
        "case_id": case_id,
        "severity": severity,
        "risk_score": adjusted_score,
        "baseline": baseline,
        "escalation_triggered": escalation_triggered,
        "files": {
            "json": json_path,
            "txt": txt_path,
            "pdf": pdf_path,
            "history": history_path
        }
    }

