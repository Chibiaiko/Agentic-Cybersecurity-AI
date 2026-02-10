<p align="center">
  <img 
    src="https://github.com/user-attachments/assets/a61daa83-ca17-4ed5-b299-a8e8c968304c"
    alt="Aegis Guardian Shield"
    width="500"
  >
</p>

<h1 align="center">🛡️ AEGIS – Agentic Incident Response & Triage AI (PoC)</h>



**AEGIS** is a **proof-of-concept (PoC)** agentic Incident Response (IR) and triage system that demonstrates how autonomous agents can investigate security detections, assess impact, and generate SOC-ready investigation artifacts using Microsoft Sentinel / Log Analytics data.

This PoC uses a **brute force authentication scenario** as the primary demonstration, but the architecture is **scenario-agnostic** and designed to scale to additional detections.

---

## 🎯 One-Line Summary

> AEGIS is a proof-of-concept agentic IR system that investigates brute force authentication activity and automatically generates SOC-style playbooks and incident timelines.

---
# AEGIS Architect 

<img width="600" height="700" alt="Aegis Workflow" src="https://github.com/user-attachments/assets/6a49aa53-8b10-4b40-bb21-dfbca28e3876" />


---

## 🧠 Purpose of This Project

This project was built to demonstrate:

* Agentic security investigation logic
* SOC-aligned triage decision making
* Artifact-driven incident response
* Safe, human-governed automation

It is **not** intended to replace a SOC or automatically take remediation actions.

---

## 🧪 Proof of Concept Scope

* **Primary demo scenario**: Brute force authentication attempts
* **Data source**: Microsoft Sentinel / Log Analytics
* **Focus**: Investigation, triage, and documentation
* **Non-goal**: Automated containment or enforcement

The brute force scenario was chosen because it is:

* Common in SOC environments
* Easy to reason about impact vs. attempt
* Ideal for demonstrating triage logic

---

## 🧩 Demonstrated Scenario

### Brute Force Authentication Attempt

* Detects repeated failed authentication events
* Validates whether successful authentication followed
* Determines:

  * Attempted activity (no impact)
  * Potential compromise (impact observed)

Mapped to:

* **MITRE ATT&CK**: T1110 – Brute Force

---

## 📸 Portfolio Evidence Section



---

## 🗂️ Artifacts Generated (Core Output)

AEGIS always generates investigation artifacts, regardless of outcome.

### 📄 Investigated Playbook
Link to playbook
A SOC-style playbook containing:

* Scenario context
* MITRE ATT&CK mapping
* Triage outcome
* Incident classification
* Isolation recommendation (if applicable)
* Event counts
* Full investigation timeline

---

### 🕒 Incident Timeline

PDF

A visual, chronological timeline showing:

* Evidence collection steps
* Triage decisions
* Investigation progression

---

## ⚙️ How the Agent Works

1. Analyst inputs a hostname
2. AEGIS runs the brute force investigation scenario
3. Log Analytics telemetry is collected
4. Evidence is triaged using IR decision logic
5. Impact is assessed (attempt vs compromise)
6. Investigation artifacts are generated for review

---

## 🧠 Design Principles

* **Agentic, not reactive**
* **Human-in-the-loop by design**
* **NIST 800-61 aligned triage**
* **MITRE ATT&CK mapped**
* **Documentation-first response**

---

## 🚫 Intentional Limitations

As a PoC, AEGIS:

* Does not isolate endpoints
* Does not block accounts
* Does not modify tenant state

All actions remain **analyst-driven**.

---

## 👤 Intended Audience

* SOC Analysts
* Detection Engineers
* Blue Team Practitioners
* Security automation & AI researchers
* Hiring managers reviewing IR-focused projects

---

## 🧠 Why Brute Force?

Brute force authentication activity is:

* One of the most common SOC alerts
* A clear example of “attempt vs impact”
* Ideal for demonstrating agentic triage logic

This makes it a strong foundation for expanding into:

* Credential access
* Lateral movement
* Malware execution
* Cloud identity abuse

---

## 🔮 Future Expansion (Out of Scope for This PoC)

* Additional detection scenarios
* Cross-scenario correlation
* Multi-host investigations
* SOAR integrations
* Analyst feedback loops
