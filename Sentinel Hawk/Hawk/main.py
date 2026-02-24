# 🕊️ main.py
# ---------------------------------------------------------
# SentinelHawk — Core Runner
# ---------------------------------------------------------
import time
from skywatch import Skywatch
from hawksight import Hawksight
from nest.talonscore import TalonScore
from precision_strike import PrecisionStrike
from report_engine import ReportEngine
from models import Colors
from secrets_ import LOG_ANALYTICS_WORKSPACE_ID, API_KEY, TENABLE_ACCESS_KEY, TENABLE_SECRET_KEY

# Define missing configuration variables
STREAM_MODE = False  # Set to True to enable continuous streaming
STREAM_INTERVAL_SECONDS = 5  # Interval between collection cycles

def run():
    print(Colors.bold_colored("🦅 SentinelHawk Starting up...", Colors.CYAN))
    
    sky = Skywatch()
    sight = Hawksight()
    strike = PrecisionStrike()
    reporter = ReportEngine()

    all_incidents = []
    iteration = 0
    max_iterations = 3 if not STREAM_MODE else 999999

    try:
        while iteration < max_iterations:
            print(Colors.bold_colored(f"--- Cycle {iteration+1} ---", Colors.BLUE))
            raw_scores = sky.collect()
            print(f"📊 Collected {len(raw_scores)} events for analysis")

            incident_count_this_cycle = 0
            for scoring_data in raw_scores:
                incident = sight.analyze(scoring_data)
                
                if incident:
                    strike.respond(incident)
                    all_incidents.append(incident)
                    incident_count_this_cycle += 1
                    risk_color = Colors.risk_color(incident.risk)
                    print(f"🚨 Logged Incident: {incident.id} [Risk: {Colors.colored(f'{incident.risk}', risk_color)}]")

            print(f"📈 Incidents this cycle: {incident_count_this_cycle}")

            if not STREAM_MODE:
                break

            time.sleep(STREAM_INTERVAL_SECONDS)
            iteration += 1

    except KeyboardInterrupt:
        print(Colors.colored("\n⏹️  Stopping...", Colors.YELLOW))

    # Generate reports
    print(Colors.bold_colored("\n📋 Generating Reports...", Colors.CYAN))
    
    try:
        print("Generating TXT and Full Report PDF...")
        reporter.generate(all_incidents)
    except Exception as e:
        print(f"ERROR in generate(): {e}")
        import traceback
        traceback.print_exc()
    
    try:
        print("Generating SOC Dashboard PDF...")
        reporter.generate_dashboard_pdf(all_incidents)
    except Exception as e:
        print(f"ERROR in generate_dashboard_pdf(): {e}")
        import traceback
        traceback.print_exc()
    
    try:
        print("Generating Decision Memory TXT...")
        reporter.generate_decision_memory_txt(all_incidents)
    except Exception as e:
        print(f"ERROR in generate_decision_memory_txt(): {e}")
        import traceback
        traceback.print_exc()
    
    try:
        print("Generating Decision Memory PDF...")
        reporter.generate_decision_memory_pdf(all_incidents)
    except Exception as e:
        print(f"ERROR in generate_decision_memory_pdf(): {e}")
        import traceback
        traceback.print_exc()
    
    print(Colors.bold_colored("\n✔️ SentinelHawk run complete.", Colors.GREEN))

if __name__ == "__main__":
    run()
