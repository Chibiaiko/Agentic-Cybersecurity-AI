# utils.py
import logging
import sys
import uuid
from pathlib import Path

# ANSI Escape Codes for Colors
BLUE = "\033[94m"
RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"

# Risk Classification Colors (ANSI 24-bit true color)
RISK_COLORS = {
    "CRITICAL": "\033[38;2;71;0;0m",      # #470000
    "HIGH": "\033[38;2;209;35;0m",        # #D12300
    "MEDIUM": "\033[38;2;255;255;0m",     # #FFFF00
    "LOW": "\033[38;2;46;255;46m"         # #2EFF2E
}

# Confidence Level Colors (ANSI 24-bit true color)
CONFIDENCE_COLORS = {
    "LOW": "\033[38;2;165;220;15m",       # #A5DC0F
    "MODERATE": "\033[38;2;117;20;0m",    # #751400
    "HIGH": "\033[38;2;209;16;0m"         # #D10000
}

# Global logger instance and temp file path
_logger_instance = None
_temp_audit_file = "audit_temp.log"

def print_blue(text):
    """Prints the given text in blue color to the console."""
    print(f"{BLUE}{text}{RESET}")

def print_green(text):
    """Prints the given text in green color to the console."""
    print(f"{GREEN}{text}{RESET}")

def print_red(text):
    """Prints the given text in red color to the console."""
    print(f"{RED}{text}{RESET}")

def print_yellow(text):
    """Prints the given text in yellow color to the console."""
    print(f"{YELLOW}{text}{RESET}")

def print_risk_classification(risk_level):
    """Prints risk classification with appropriate color coding."""
    if risk_level in RISK_COLORS:
        color = RISK_COLORS[risk_level]
        print(f"{color}Risk Classification: {risk_level}{RESET}")
    else:
        print(f"Risk Classification: {risk_level}")

def print_confidence_level(confidence):
    """Prints confidence level with appropriate color coding."""
    if confidence in CONFIDENCE_COLORS:
        color = CONFIDENCE_COLORS[confidence]
        print(f"{color}Confidence Level: {confidence}{RESET}")
    else:
        print(f"Confidence Level: {confidence}")

def get_risk_color_code(risk_level):
    """Returns the color code for a risk level (for file output)."""
    return RISK_COLORS.get(risk_level, "")

def get_confidence_color_code(confidence):
    """Returns the color code for a confidence level (for file output)."""
    return CONFIDENCE_COLORS.get(confidence, "")

def generate_case_id():
    """Generate a unique Zero Trust case ID."""
    return f"ZT-{uuid.uuid4().hex[:8].upper()}"

def setup_logger(log_file="audit_temp.log"):
    """
    Configures and returns the audit logger.
    Uses a temporary file that will be moved to Summary folder later.
    """
    global _logger_instance
    
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s %(message)s"
    )
    _logger_instance = logging.getLogger("AuditLogger")
    return _logger_instance

def log_step(step_name, data):
    """Logs a specific step and its data to the audit log."""
    logging.info(f"STEP {step_name}: {data}")

def move_audit_log_to_summary(summary_dir_path):
    """
    Moves the temporary audit log to the Summary folder.
    Called by summary_generator.py after creating the Summary directory.
    """
    from datetime import datetime
    
    temp_log = Path(_temp_audit_file)
    if temp_log.exists():
        summary_dir = Path(summary_dir_path)
        audit_dest = summary_dir / "audit.log"
        
        try:
            with open(temp_log, "r", encoding='utf-8') as src:
                audit_content = src.read()
            
            with open(audit_dest, "w", encoding='utf-8') as dst:
                dst.write(audit_content)
            
            # Remove the temp file
            temp_log.unlink()
            return str(audit_dest)
        except Exception as e:
            logging.error(f"Error moving audit log: {e}")
            return None
    
    return None
