<p align="center">
  <img 
    src="https://github.com/user-attachments/assets/c483d76f-fe7b-497b-8f8f-39ac14d6a33a"
    width="1536"
    height="1024"
    alt="OpsPilot Automated Ticket"
  >
</p>




---

<h1 align="center">🎟️ OpsPilot — Agentic Security Ticket(PoC)</h1>

<p align="center">
  <img 
    src="https://github.com/user-attachments/assets/9ab7db31-809f-49f6-acf0-2eb62535b8c2" 
    width="500" 
    height="500" 
    alt="Ops"
  >
</p>


**OpsPilot** is a telemetry-driven automation engine developed as a Proof of Concept to validate end-to-end automation of Azure security telemetry ingestion, correlation, classification, prioritization, routing, and documentation generation.

---

# 📃 Executive Summary

**OpsPilot** is a technical Proof-of-Concept demonstrating how security telemetry from multiple Azure sources can be automatically transformed into fully triaged, enriched, and routed tickets without manual analyst intervention.

This PoC was designed to simulate how a lightweight SOAR-style orchestration engine could operate within a cloud-native security environment.

Instead of manually reviewing Defender or Sentinel logs, OpsPilot:

1. Authenticates to Azure
2. Queries Log Analytics, Sentinel, and Defender
3. Correlates telemetry
4. Classifies the issue using a structured intelligence catalogue
5. Dynamically adjusts priority
6. Assigns the appropriate operational team
7. Generates TXT and PDF documentation
8. Moves the ticket through a structured lifecycle

This project serves as a proof-of-concept for:

* SOC automation
* Detection engineering workflows
* Cloud-native triage pipelines
* Lightweight SOAR-style orchestration

---
## 👷🏻‍♀️ Architecture Overview

<img width="500" height="700" alt="OpsPilot - Architecture Overview" src="https://github.com/user-attachments/assets/7a710f7a-2066-40cb-a360-24b5f5d00a3d"/>



```
User Input (Device / User / IP)
        ↓
Azure Authentication
        ↓
Telemetry Collection
(Log Analytics + Sentinel + Defender)
        ↓
Correlation & Classification
        ↓
Priority Assignment
        ↓
Team Routing
        ↓
Ticket Creation
        ↓
Lifecycle Progression
        ↓
TXT Documentation Output
```
---
# Tickets
---
## 🎟️ Ticket — YCN-SEC-20260216021314

<img width="271" height="185" alt="YCN-SEC-20260216021314(1)" src="https://github.com/user-attachments/assets/d7b42cbb-c8cc-4ca3-b7e3-8da81ba6fbe2" />

<img width="875" height="280" alt="YCN-SEC-20260216021314(2)" src="https://github.com/user-attachments/assets/57554da9-aed4-4917-a000-a66f7725ceb8" />


---

**OPS PILOT - LOG(N) Pacific**

Requester Name: SOC Automation Test

Affected User/Device/System: `cyberlab`

Issue Description: Malware detection signals identified across Defender and Sentinel telemetry.

---
Routing Decision
---
Ticket ID: YCN-SEC-20260216021314
Lookback Window (Timestamp): 7 Days
Identity: Device

### 🔎 What These Images Show

<img width="271" height="185" alt="YCN-SEC-20260216021314(1)" src="https://github.com/user-attachments/assets/20a67477-3977-43c6-a4f0-08dd74a8bf6d" />

* Extended 7-day lookback
* Larger telemetry dataset
* Confirms scalability of ingestion logic
* Cross-source correlation maintained


<img width="875" height="280" alt="YCN-SEC-20260216021314(2)" src="https://github.com/user-attachments/assets/d9d462b3-296b-424a-b71e-0e9c9c69c968" />

* Ticket ID: YCN-SEC-20260216021314
* Malware classification
* Critical priority maintained
* Security Team routing
* Documentation generation confirmed

Demonstrates scalability across expanded historical data.

Documentation:

* [YCN-SEC-20260216021314](https://drive.google.com/file/d/1UHAkG8PGXPDSTGac6kn3W7xXGq_bTSnz/view?usp=sharing)
---

---
## 🎟️ Ticket — YCN-SEC-20260216020217

<img width="277" height="184" alt="YCN-SEC-20260216020217(1)" src="https://github.com/user-attachments/assets/70f99d9a-6b4b-49f0-bc71-6b462b241099" />

<img width="883" height="279" alt="YCN-SEC-20260216020217(2)" src="https://github.com/user-attachments/assets/3560a93c-fbe5-4ebc-9186-4a721c0bc7fb" />


---

**OPS PILOT - LOG(N) Pacific**

Requester Name: SOC Automation Test

Affected User/Device/System: `cyberlab`

Issue Description: Malware detection signals identified across Defender and Sentinel telemetry.

---
Routing Decision
---
Ticket ID: YCN-SEC-20260216020217
Lookback Window (Timestamp): 72 Hours
Identity: Device

### 🔎 What These Images Show

<img width="277" height="184" alt="YCN-SEC-20260216020217(1)" src="https://github.com/user-attachments/assets/70f99d9a-6b4b-49f0-bc71-6b462b241099" />

* Azure authentication success
* Log Analytics query execution
* Sentinel incidents retrieved
* Defender Advanced Hunting results
* Multi-source telemetry aggregation
* Event count across 72-hour window

This demonstrates full telemetry ingestion across multiple security platforms.

<img width="883" height="279" alt="YCN-SEC-20260216020217(2)" src="https://github.com/user-attachments/assets/3560a93c-fbe5-4ebc-9186-4a721c0bc7fb" />

* Ticket ID generation: YCN-SEC-20260216020217
* Identity detection: Device
* Issue classification: Malware Detection Alert
* Priority upgraded to Critical
* Assigned Team: Security Team
* Escalation note template applied
* Documentation file path generation

This shows the full automation pipeline from detection to structured routing.

Documentation:

* [YCN-SEC-20260216020217](https://drive.google.com/file/d/1qTMETHC_BBg8emV-qw5ya0QEmdK0oXpT/view?usp=sharing)
---

---

## 🎟️ Ticket — YCN-SEC-20260216020836

<img width="272" height="182" alt="YCN-SEC-20260216020836(1)" src="https://github.com/user-attachments/assets/981e4b4f-5191-4854-885f-1fdd47d99814" />

<img width="876" height="281" alt="YCN-SEC-20260216020836(2)" src="https://github.com/user-attachments/assets/bdbfd36b-6368-48a5-946f-261982398cfa" />


---

**OPS PILOT - LOG(N) Pacific**

Requester Name: SOC Automation Test

Affected User/Device/System: `cyberlab`

Issue Description: Malware detection signals identified across Defender and Sentinel telemetry.

---
Routing Decision
---
Ticket ID: YCN-SEC-20260216020836
Lookback Window (Timestamp): 24 Hours
Identity: Device

### 🔎 What These Images Show

<img width="272" height="182" alt="YCN-SEC-20260216020836(1)" src="https://github.com/user-attachments/assets/981e4b4f-5191-4854-885f-1fdd47d99814" />

* Same device queried with a reduced 24-hour lookback
* Multi-source telemetry still present
* Event count reflects time-window filtering
* Demonstrates query flexibility and parameterized lookbacks


<img width="876" height="281" alt="YCN-SEC-20260216020836(2)" src="https://github.com/user-attachments/assets/bdbfd36b-6368-48a5-946f-261982398cfa" />

* Ticket ID: YCN-SEC-20260216020836
* Malware classification persists
* Priority remains Critical due to Defender severity
* Security Team routing confirmed
* Documentation artifacts generated

Shows consistent classification despite time-window variation.

Documentation:

* [YCN-SEC-20260216020836](https://drive.google.com/file/d/1nDB7oSI6P--eIux1sO2v2i6G5sh27lI8/view?usp=sharing)
---

---

## 🎟️ Ticket — YCN-SEC-20260216021112

<img width="284" height="187" alt="YCN-SEC-20260216021112(1)" src="https://github.com/user-attachments/assets/a0ba75bd-4f85-44da-9818-8af5e87a8bbe" />

<img width="750" height="270" alt="YCN-SEC-20260216021112(2)" src="https://github.com/user-attachments/assets/da540980-c945-436b-b90c-4e4da8cc984e" />


---

**OPS PILOT - LOG(N) Pacific**

Requester Name: SOC Automation Test

Affected User/Device/System: `cyberlab`

Issue Description: Malware detection signals identified across Defender and Sentinel telemetry.

---
Routing Decision
---
Ticket ID: YCN-SEC-20260216021112
Lookback Window (Timestamp): 12 Hours
Identity: Device

### 🔎 What These Images Show

<img width="284" height="187" alt="YCN-SEC-20260216021112(1)" src="https://github.com/user-attachments/assets/11addd22-fd09-4865-bc88-3e53d31e33d7" />

* 12-hour scoped query
* Reduced telemetry volume
* Demonstrates dynamic time filtering capability
* Validates automation under smaller data sets


<img width="750" height="270" alt="YCN-SEC-20260216021112(2)" src="https://github.com/user-attachments/assets/1f1ff506-6644-404b-b9ca-9f5f0d1b1240" />

* Ticket ID: YCN-SEC-20260216021112
* Malware detection classification
* Priority logic still escalates based on severity
* Security Team routing
* Escalation messaging populated

Demonstrates deterministic classification logic independent of event volume.

Documentation:

* [YCN-SEC-20260216021112](https://drive.google.com/file/d/19Gk_zfk3NVe0ZMzQ1ekcZ7FxMyEOMHlr/view?usp=sharing)
---

---

## 🎟️ Ticket — YCN-SEC-20260216022237

<img width="293" height="166" alt="YCN-SEC-20260216022237(1)" src="https://github.com/user-attachments/assets/f9c719fc-d73a-46d1-a0e2-69e77a61e942" />

<img width="880" height="266" alt="YCN-SEC-20260216022237(2)" src="https://github.com/user-attachments/assets/952cbf9a-2930-419d-9bf6-16a8d28aebe1" />


---

**OPS PILOT - LOG(N) Pacific**

Requester Name: SOC Automation Test

Affected User/Device/System: `cyberfun`

Issue Description: Security monitoring agent offline based on Defender DeviceInfo telemetry.

---
Routing Decision
---
Ticket ID: YCN-SEC-20260216022237
Lookback Window (Timestamp): 24 Hours
Identity: Device

### 🔎 What These Images Show

<img width="293" height="166" alt="YCN-SEC-20260216022237(1)" src="https://github.com/user-attachments/assets/5f5aeae5-ad8b-44c8-986d-2af38a7b7870" />

* Defender DeviceInfo query
* Monitoring agent offline indicators
* Single telemetry source returned
* Demonstrates partial-source handling


<img width="880" height="266" alt="YCN-SEC-20260216022237(2)" src="https://github.com/user-attachments/assets/e18df7dc-d462-4576-9b7d-88c8f6997a93" />

* Ticket ID: YCN-SEC-20260216022237
* Issue classified: Security / Monitoring Agent Offline
* Priority set to High (not Critical)
* Assigned Team: Security Team
* Escalation note applied
* Documentation generated

Demonstrates correct non-malware classification and priority differentiation.

Documentation:

* [YCN-SEC-20260216022237](https://drive.google.com/file/d/15rCsp4PHNU_BbOwz-ED-Fx8viXOAe8Zp/view?usp=sharing)


---

# 🎫 Ticket Lifecycle

<img width="700" height="500" alt="Ticket Lifecycle" src="https://github.com/user-attachments/assets/26986be7-8cf7-4207-8b21-ae956d04b99e" />


Each ticket progresses through:

```
TRIAGED → IN_PROGRESS → RESOLVED → CLOSED
```

Demonstrates structured workflow automation.

---

# 💥 Known Limitations (PoC Scope)

* Keyword-based classification (not ML-driven)
* No persistent database
* CLI-based interface
* No live ITSM API integration
* PDF formatting limitations (font constraints)

---

# 🔮 Future Enhancements

* LLM-based semantic classification
* Web UI dashboard
* ServiceNow / Jira API integration
* Slack / Teams notification integration
* Persistent ticket storage
* Timeline visualization
* Auto-remediation playbooks

---

# 📢 Why This Project Matters

OpsPilot demonstrates:

* Azure SDK integration
* KQL-based telemetry querying
* Cross-source security data normalization
* Deterministic classification logic
* Dynamic priority assignment
* Structured ticket orchestration
* Automated documentation generation

This aligns with roles such as:

* SOC Analyst (Automation-focused)
* Detection Engineer
* Cloud Security Engineer
* Security Automation Engineer
* Entry-Level Security Engineer


