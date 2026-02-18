# tool_routing.py
from function_tools import SecurityAnalystFunctions


def route_tool(command, functions):
    """
    Route commands to the appropriate analysis tool.
    
    Args:
        command: User command/instruction
        functions: SecurityAnalystFunctions instance
    
    Returns:
        Analysis results or empty list if no action taken
    """
    
    command = command.lower()
    
    if "run" in command or "analyze" in command or "assessment" in command or "zero trust" in command:
        return functions.run_zero_trust_assessment()
    
    return []
