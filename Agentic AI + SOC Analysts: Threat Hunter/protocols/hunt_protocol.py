import json
import re
from datetime import datetime

def hunt(openai_client, threat_hunt_system_message, threat_hunt_user_message, openai_model):
    """
    Runs the threat hunting flow:
    1. Formats the logs into a string
    2. Selects appropriate system prompt from context
    3. Passes logs + role to model
    4. Parses and returns JSON findings with MITRE tagging
    """
    
    messages = [
        threat_hunt_system_message,
        threat_hunt_user_message
    ]

    response = openai_client.chat.completions.create(
        model=openai_model,
        messages=messages
    )

    content = response.choices[0].message.content.strip()

    # Attempt to extract JSON from markdown code blocks first
    match = re.search(r"```json\s*(.*?)\s*```", content, re.DOTALL | re.IGNORECASE)
    if match:
        json_str = match.group(1)
    else:
        # Fallback: look for the first '[' and last ']'
        start = content.find('[')
        end = content.rfind(']') + 1
        if start != -1 and end != 0:
            json_str = content[start:end]
        else:
            # Last resort: try the whole content
            json_str = content

    try:
        results = json.loads(json_str)
        
        # Enrich each finding with metadata
        for finding in results:
            if 'timestamp_detected' not in finding:
                finding['timestamp_detected'] = datetime.utcnow().isoformat() + 'Z'
            
            # Ensure MITRE structure exists
            if 'mitre' not in finding:
                finding['mitre'] = {
                    "tactic": "Unknown",
                    "technique": "Unknown",
                    "sub_technique": "",
                    "id": "",
                    "description": ""
                }
                
    except json.JSONDecodeError:
        print(f"Error parsing JSON from model response. Raw content snippet: {content[:100]}...")
        results = []
    
    return results


def extract_mitre_tactics(hunt_results):
    """
    Extract unique MITRE tactics and techniques from hunt results.
    
    Args:
        hunt_results: List of threat findings
        
    Returns:
        Dictionary mapping tactics to lists of techniques
    """
    mitre_mapping = {}
    
    for finding in hunt_results:
        mitre_info = finding.get('mitre', {})
        tactic = mitre_info.get('tactic', 'Unknown')
        technique = mitre_info.get('technique', 'Unknown')
        technique_id = mitre_info.get('id', '')
        
        if tactic and tactic != 'Unknown':
            if tactic not in mitre_mapping:
                mitre_mapping[tactic] = []
            
            technique_display = f"{technique_id}: {technique}" if technique_id else technique
            
            if technique_display not in mitre_mapping[tactic]:
                mitre_mapping[tactic].append(technique_display)
    
    return mitre_mapping
