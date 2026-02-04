from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict

class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class BusinessImpact(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class ControlStatus(str, Enum):
    MET = "MET"
    PARTIALLY_MET = "PARTIALLY_MET"
    NOT_MET = "NOT_MET"

@dataclass
class ComplianceMapping:
    framework: str
    control_id: str
    control_title: str
    justification: str

@dataclass
class FinancialEstimate:
    min_loss: float
    most_likely_loss: float
    max_loss: float
    annualized_risk_exposure: float
    description: str

@dataclass
class Risk:
    id: str
    title: str
    description: str
    component: str
    
    # Risk Assessment
    severity: RiskLevel
    cvss_score: float
    cvss_vector: str
    
    # Business Context
    business_impact: BusinessImpact
    
    # Optional/Default fields
    cve_id: Optional[str] = None
    composite_score: float = 0.0
    
    # Financial
    financial_impact: Optional[FinancialEstimate] = None
    
    # Compliance
    compliance_mappings: List[ComplianceMapping] = field(default_factory=list)
    control_status: ControlStatus = ControlStatus.NOT_MET
    control_gap: Optional[str] = None
    
    # Remediation
    remediation_steps: str = ""
    policy_violation_rule: Optional[str] = None
    
    evidence: List[str] = field(default_factory=list)

@dataclass
class SecurityReport:
    date: str
    risks: List[Risk] = field(default_factory=list)
    gate_status: str = "FAIL"
    overall_posture: str = "CRITICAL"
    total_financial_exposure_min: float = 0.0
    total_financial_exposure_max: float = 0.0
    trend: str = "STABLE"
