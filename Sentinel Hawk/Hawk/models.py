# models.py
# Model configurations and color codes for SentinelHawk

# =====================================================================
# OpenAI Model Configurations
# =====================================================================
GPT_4 = "gpt-4"
GPT_4_O = "gpt-4o"
GPT_4_TURBO = "gpt-4-turbo"
GPT_3_5_TURBO = "gpt-3.5-turbo"

# Default model
DEFAULT_MODEL = GPT_4_O


# =====================================================================
# Terminal Color Codes (ANSI)
# =====================================================================
class Colors:
    """ANSI color codes for terminal output"""
    
    # Foreground Colors
    RED = '\033[91m'
    ORANGE = '\033[38;5;208m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BRIGHT_GREEN = '\033[38;5;46m'  # Bright Green #00FF00
    CYAN = '\033[36m'  # Cyan #00FFFF
    BRIGHT_CYAN = '\033[96m'
    AQUA = '\033[38;5;51m'  # Aqua #7DF9FF
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    GOLD = '\033[38;5;220m'  # Gold #FCD000
    
    # Formatting
    BOLD = '\033[1m'
    RESET = '\033[0m'
    
    @staticmethod
    def risk_color(risk_score):
        """Return color based on risk score"""
        if risk_score >= 80:
            return Colors.RED  # CRITICAL
        elif risk_score >= 60:
            return Colors.ORANGE  # HIGH
        elif risk_score >= 40:
            return Colors.YELLOW  # MEDIUM
        else:
            return Colors.GREEN  # LOW
    
    @staticmethod
    def confidence_color(confidence_level):
        """Return color based on confidence level"""
        if confidence_level == "High":
            return Colors.RED  # Red
        elif confidence_level == "Medium":
            return Colors.ORANGE  # Orange
        else:
            return Colors.Yellow  # Yellow (Low)
    
    @staticmethod
    def severity_color(severity):
        """Return color based on severity"""
        if severity == "CRITICAL":
            return Colors.RED
        elif severity == "HIGH":
            return Colors.ORANGE
        elif severity == "MEDIUM":
            return Colors.YELLOW
        else:
            return Colors.GREEN
    
    @staticmethod
    def status_color(status):
        """Return color based on status"""
        if status == "PENDING_APPROVAL":
            return Colors.CYAN  # Cyan #00FFFF
        elif status == "EXECUTED":
            return Colors.GREEN
        elif status == "FAILED":
            return Colors.RED
        else:
            return Colors.YELLOW
    
    @staticmethod
    def colored(text, color):
        """Apply color to text"""
        return f"{color}{text}{Colors.RESET}"
    
    @staticmethod
    def bold_colored(text, color):
        """Apply bold and color to text"""
        return f"{Colors.BOLD}{color}{text}{Colors.RESET}"
