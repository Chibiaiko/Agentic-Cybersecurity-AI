<p align="center">
  <img src="https://github.com/user-attachments/assets/289132d7-f743-439f-af02-183ff969bc10"
       alt="Threat Hunter Architecture Diagram"
       width="600">
</p>




<h1 align="center">Agentic AI + SOC Analysts: Threat Hunter</h1>

## Overview
This project demonstrates a **prototype, AI-augmented threat hunting workflow**
where an agentic AI collaborates with SOC analysts to:

    - 🔍 Hunt threats in security telemetry
    - ⚡ Intelligently prioritize suspicious activity
    - 📝 Investigate and document findings
    - 🛡️ Align investigations with MITRE ATT&CK

The system dynamically translates analyst intent into **log queries**, analyzes
results using an LLM, and returns structured threat findings for human review.

This work is designed for demonstration and iterative expansion toward a
fully ATT&CK-driven threat hunting platform, with humans kept firmly in the loop.

This project uses MITRE ATT&CK as a **shared language** between vulnerability
management, detection engineering, and threat hunting.

---
## Key Capabilities

🔍 **Threat Hunting**
        - Converts analyst questions into log analytics queries
        - Searches identity, authentication, and endpoint telemetry
        - Focuses on high-signal behaviors, not alerts alone
        
⚡ **Intelligent Prioritization**
        - Filters noisy log data before LLM analysis
        - Highlights suspicious patterns worthy of analyst attention
        - Reduces time-to-insight during hunts
        
📝 **Investigation & Documentation**
        - Produces narrative explanations of suspicious behavior
        - Structures findings for analyst review
        - Supports repeatable, explainable threat hunts
        
🛡️ **MITRE ATT&CK Alignment**
        - Designed to support ATT&CK-driven hunting
        - Enables mapping of observed behaviors to tactics & techniques
        - Helps SOC teams hunt by adversary behavior, not tool signatures

---

## Threat Hunting Workflow
-----
    Analyst Question
    ↓
    Agent Decides Log Parameters
    ↓
    Azure Log Analytics Query
    ↓
    Log Result Truncation & Context Prep
    ↓
    LLM-Based Cognitive Threat Analysis
    ↓
    Human Review & Action
------

## MITRE ATT&CK Framework

This project is designed around the **MITRE ATT&CK framework** for adversary behavior–driven threat hunting.

SOC analysts can use the official ATT&CK matrix to:
  - Plan hypothesis-driven hunts by tactic and technique
  - Identify telemetry gaps
  - Validate coverage across the kill chain
  - Align investigations with industry-standard adversary models

Coverage is behavior-driven and depends on available telemetry rather than static rule matching.

📌 **Reference**
- MITRE ATT&CK Matrix (April 2024 Poster)
  ![Screenshot_29-1-2026_121511_](https://github.com/user-attachments/assets/a4448fb9-f0ef-4389-88a8-504d149585e8)

---

## MITRE ATT&CK Coverage 

The framework is capable of supporting **multiple ATT&CK tactics**, depending on:
  - Log sources queried
  - KQL queries used
  - Prompt design

| MITRE Tactic        | Supported    | How |
|-------------        |----------    |--------|
| Initial Access      | ⚠️ Partial  | Suspicious logon patterns |
| Credential Access   | ✅ Yes      | Logon events, callers, identities |
| Discovery           | ⚠️ Partial  | Identity & device exploration |
| Lateral Movement    | ⚠️ Partial  | Caller/device relationships |
| Command & Control   | ⚠️ Partial  | Depends on log source |
| Defense Evasion     | ⚠️ Partial  | Requires expanded telemetry |
---

## What This POC Does Well


✅ Demonstrates **agentic decision-making**  
  - AI chooses *what* to query, not just *how to analyze*

✅ Reduces analyst cognitive load  
  - Pre-filters massive logs  
  - Summarizes suspicious activity  

✅ Enables hypothesis-driven threat hunting  
  - Analyst → AI → Logs → AI → Analyst loop  

---

## Current Gaps (Honest Assessment)

🎯 The following MITRE stages are **not yet fully implemented** but are architecturally supported:

- Resource Development
- Execution
- Persistence
- Collection
- Exfiltration
- Impact

These require:
- Additional log tables
- Expanded KQL queries
- Explicit MITRE tagging in prompts or output schemas
---

## Why This Matters

🔁 Traditional SOC workflows:
  
   ❌ Alert-driven  
   ❌ Reactive  
   ❌ High analyst burnout  

🔄 This agentic approach:
  
   ✅ Supports proactive threat hunting  
   ✅ Keeps humans in the loop  
   ✅ Makes investigations faster, clearer, and repeatable  

---
🗺️## Scope & Roadmap

This project demonstrates the **core architecture and agentic workflow**
for ATT&CK-driven threat hunting, including:

- Agent-led selection of log sources, fields, and time ranges
- LLM-assisted behavioral analysis of security telemetry
- Human-in-the-loop review and investigation of hunt results

### Planned Enhancements
The following capabilities are intentionally out of scope for the current
implementation but represent clear next steps:

- Explicit MITRE ATT&CK tactic and technique tagging in hunt outputs
- Expanded telemetry coverage (process, persistence, network, execution)
- ATT&CK-aligned hunt playbooks per tactic
- Analyst confidence scoring and triage prioritization
- Structured outputs suitable for case management or ticketing systems

### Non-Goals
- Fully automated response or remediation
- Production-scale performance tuning
- Replacement of SOC analyst decision-making
