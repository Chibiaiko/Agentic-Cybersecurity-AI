from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from models.risk_model import RiskLevel

# Custom theme for the specific color requirements
# CRITICAL-Black
# HIGH-Red
# MEDIUM-Orange
# LOW-Yellow
# INFO-Green
custom_theme = Theme({
    "risk.critical": "black on red", # Black text on Red background for visibility/emphasis as 'Critical' usually demands
    "risk.high": "red",
    "risk.medium": "orange3", # 'orange' might be standard, orange3 is safer in rich
    "risk.low": "yellow",
    "risk.info": "green",
})

console = Console(theme=custom_theme)

def get_risk_style(level: RiskLevel) -> str:
    if level == RiskLevel.CRITICAL:
        return "risk.critical"
    elif level == RiskLevel.HIGH:
        return "risk.high"
    elif level == RiskLevel.MEDIUM:
        return "risk.medium"
    elif level == RiskLevel.LOW:
        return "risk.low"
    else:
        return "risk.info"

def print_header(title: str):
    console.print(f"\n[bold white]{title}[/bold white]")
    console.print("[bold white]" + "="*len(title) + "[/bold white]\n")

def format_currency(amount: float) -> str:
    return f"${amount:,.2f}"
