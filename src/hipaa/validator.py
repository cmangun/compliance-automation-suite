"""
HIPAA Compliance Validator

Automated HIPAA compliance checking for healthcare AI systems:
- Administrative safeguards
- Physical safeguards
- Technical safeguards
- Documentation requirements
- Risk assessment
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)


class HIPAACategory(str, Enum):
    """HIPAA safeguard categories."""
    
    ADMINISTRATIVE = "administrative"
    PHYSICAL = "physical"
    TECHNICAL = "technical"
    ORGANIZATIONAL = "organizational"
    POLICIES = "policies"


class ComplianceStatus(str, Enum):
    """Compliance check status."""
    
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    PENDING_REVIEW = "pending_review"


class RiskLevel(str, Enum):
    """Risk severity levels."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ControlType(str, Enum):
    """Types of controls."""
    
    REQUIRED = "required"
    ADDRESSABLE = "addressable"


@dataclass
class ComplianceControl:
    """A HIPAA compliance control."""
    
    control_id: str
    name: str
    description: str
    category: HIPAACategory
    control_type: ControlType
    regulation_reference: str  # e.g., "164.308(a)(1)(i)"
    implementation_guidance: str
    evidence_required: list[str]
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "control_type": self.control_type.value,
            "regulation_reference": self.regulation_reference,
            "implementation_guidance": self.implementation_guidance,
            "evidence_required": self.evidence_required,
        }


@dataclass
class ControlCheck:
    """Result of checking a compliance control."""
    
    control_id: str
    status: ComplianceStatus
    findings: list[str]
    evidence_provided: list[str]
    recommendations: list[str]
    risk_level: RiskLevel | None = None
    checked_at: datetime = field(default_factory=datetime.utcnow)
    checked_by: str = "automated"
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "status": self.status.value,
            "findings": self.findings,
            "evidence_provided": self.evidence_provided,
            "recommendations": self.recommendations,
            "risk_level": self.risk_level.value if self.risk_level else None,
            "checked_at": self.checked_at.isoformat(),
            "checked_by": self.checked_by,
        }


@dataclass
class ComplianceReport:
    """Comprehensive compliance assessment report."""
    
    report_id: str
    assessment_name: str
    organization: str
    scope: str
    assessment_date: datetime
    assessor: str
    overall_status: ComplianceStatus
    control_checks: list[ControlCheck]
    summary: dict[str, Any]
    recommendations: list[str]
    next_assessment_date: datetime | None = None
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "assessment_name": self.assessment_name,
            "organization": self.organization,
            "scope": self.scope,
            "assessment_date": self.assessment_date.isoformat(),
            "assessor": self.assessor,
            "overall_status": self.overall_status.value,
            "control_checks": [c.to_dict() for c in self.control_checks],
            "summary": self.summary,
            "recommendations": self.recommendations,
            "next_assessment_date": (
                self.next_assessment_date.isoformat()
                if self.next_assessment_date else None
            ),
        }


# Standard HIPAA controls for AI systems
HIPAA_AI_CONTROLS = [
    ComplianceControl(
        control_id="HIPAA-AI-001",
        name="Risk Analysis",
        description="Conduct accurate and thorough assessment of potential risks and vulnerabilities to PHI in AI systems",
        category=HIPAACategory.ADMINISTRATIVE,
        control_type=ControlType.REQUIRED,
        regulation_reference="164.308(a)(1)(ii)(A)",
        implementation_guidance="Document all PHI data flows through AI models, identify threats, and assess likelihood and impact",
        evidence_required=[
            "Risk assessment documentation",
            "Data flow diagrams",
            "Threat analysis",
            "Risk mitigation plan",
        ],
    ),
    ComplianceControl(
        control_id="HIPAA-AI-002",
        name="Access Control",
        description="Implement technical policies and procedures for AI systems that maintain PHI",
        category=HIPAACategory.TECHNICAL,
        control_type=ControlType.REQUIRED,
        regulation_reference="164.312(a)(1)",
        implementation_guidance="Implement role-based access control, unique user identification, and access logging",
        evidence_required=[
            "Access control policy",
            "User provisioning procedures",
            "Access logs",
            "Role definitions",
        ],
    ),
    ComplianceControl(
        control_id="HIPAA-AI-003",
        name="Audit Controls",
        description="Implement mechanisms to record and examine activity in AI systems containing PHI",
        category=HIPAACategory.TECHNICAL,
        control_type=ControlType.REQUIRED,
        regulation_reference="164.312(b)",
        implementation_guidance="Log all access to PHI, model predictions involving PHI, and administrative actions",
        evidence_required=[
            "Audit logging configuration",
            "Log retention policy",
            "Sample audit logs",
            "Log review procedures",
        ],
    ),
    ComplianceControl(
        control_id="HIPAA-AI-004",
        name="Data Encryption",
        description="Implement encryption for PHI at rest and in transit in AI systems",
        category=HIPAACategory.TECHNICAL,
        control_type=ControlType.ADDRESSABLE,
        regulation_reference="164.312(a)(2)(iv), 164.312(e)(2)(ii)",
        implementation_guidance="Use AES-256 encryption at rest, TLS 1.2+ in transit, and secure key management",
        evidence_required=[
            "Encryption policy",
            "Encryption configuration",
            "Key management procedures",
            "Certificate management",
        ],
    ),
    ComplianceControl(
        control_id="HIPAA-AI-005",
        name="PHI De-identification",
        description="Ensure AI training data and outputs comply with de-identification requirements",
        category=HIPAACategory.TECHNICAL,
        control_type=ControlType.REQUIRED,
        regulation_reference="164.514(a)-(b)",
        implementation_guidance="Use Safe Harbor or Expert Determination method, validate de-identification before AI processing",
        evidence_required=[
            "De-identification procedures",
            "Safe Harbor checklist",
            "Expert determination (if applicable)",
            "Re-identification risk assessment",
        ],
    ),
    ComplianceControl(
        control_id="HIPAA-AI-006",
        name="Minimum Necessary",
        description="Limit PHI used in AI systems to minimum necessary for intended purpose",
        category=HIPAACategory.ADMINISTRATIVE,
        control_type=ControlType.REQUIRED,
        regulation_reference="164.502(b), 164.514(d)",
        implementation_guidance="Document data requirements, implement data filtering, review periodically",
        evidence_required=[
            "Data minimization policy",
            "Use case documentation",
            "Data inventory",
            "Periodic review records",
        ],
    ),
    ComplianceControl(
        control_id="HIPAA-AI-007",
        name="Business Associate Agreements",
        description="Ensure BAAs are in place with AI vendors processing PHI",
        category=HIPAACategory.ORGANIZATIONAL,
        control_type=ControlType.REQUIRED,
        regulation_reference="164.308(b)(1), 164.502(e)",
        implementation_guidance="Execute BAAs with all AI service providers, cloud providers, and data processors",
        evidence_required=[
            "Signed BAAs",
            "Vendor inventory",
            "BAA review schedule",
            "Subcontractor agreements",
        ],
    ),
    ComplianceControl(
        control_id="HIPAA-AI-008",
        name="Workforce Training",
        description="Train workforce on HIPAA requirements for AI systems",
        category=HIPAACategory.ADMINISTRATIVE,
        control_type=ControlType.REQUIRED,
        regulation_reference="164.308(a)(5)(i)",
        implementation_guidance="Provide role-specific training on AI and PHI, document completion, refresh annually",
        evidence_required=[
            "Training materials",
            "Training completion records",
            "Training schedule",
            "Competency assessments",
        ],
    ),
    ComplianceControl(
        control_id="HIPAA-AI-009",
        name="Incident Response",
        description="Implement procedures to address security incidents involving AI systems",
        category=HIPAACategory.ADMINISTRATIVE,
        control_type=ControlType.REQUIRED,
        regulation_reference="164.308(a)(6)(i)",
        implementation_guidance="Define incident classification, response procedures, and breach notification process",
        evidence_required=[
            "Incident response plan",
            "Breach notification procedures",
            "Incident log",
            "Post-incident reviews",
        ],
    ),
    ComplianceControl(
        control_id="HIPAA-AI-010",
        name="Model Explainability",
        description="Maintain documentation of AI model decision-making for PHI-related decisions",
        category=HIPAACategory.ADMINISTRATIVE,
        control_type=ControlType.ADDRESSABLE,
        regulation_reference="164.530(j)",
        implementation_guidance="Document model logic, maintain explainability reports, support patient access requests",
        evidence_required=[
            "Model documentation",
            "Explainability reports",
            "Patient request procedures",
            "Decision audit trail",
        ],
    ),
]


class HIPAAValidatorConfig(BaseModel):
    """Configuration for HIPAA validator."""
    
    include_addressable: bool = True
    risk_threshold: RiskLevel = RiskLevel.MEDIUM
    auto_recommendations: bool = True
    detailed_findings: bool = True


class HIPAAValidator:
    """
    Automated HIPAA compliance validator for AI systems.
    
    Features:
    - Control-based assessment
    - Automated evidence checking
    - Risk scoring
    - Remediation recommendations
    - Audit-ready reporting
    """
    
    def __init__(
        self,
        config: HIPAAValidatorConfig | None = None,
        controls: list[ComplianceControl] | None = None,
    ):
        self.config = config or HIPAAValidatorConfig()
        self.controls = controls or HIPAA_AI_CONTROLS
        self._assessments: list[ComplianceReport] = []
    
    def assess_system(
        self,
        system_name: str,
        organization: str,
        scope: str,
        evidence: dict[str, list[str]],
        assessor: str = "automated",
    ) -> ComplianceReport:
        """
        Perform compliance assessment of an AI system.
        
        Args:
            system_name: Name of the AI system
            organization: Organization name
            scope: Assessment scope description
            evidence: Control ID to evidence mapping
            assessor: Name of assessor
        
        Returns:
            ComplianceReport with findings
        """
        control_checks = []
        
        for control in self.controls:
            # Skip addressable if not configured
            if not self.config.include_addressable and control.control_type == ControlType.ADDRESSABLE:
                continue
            
            check = self._check_control(control, evidence.get(control.control_id, []))
            control_checks.append(check)
        
        # Calculate summary
        summary = self._calculate_summary(control_checks)
        
        # Determine overall status
        overall_status = self._determine_overall_status(control_checks)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(control_checks)
        
        report = ComplianceReport(
            report_id=self._generate_report_id(system_name, organization),
            assessment_name=f"HIPAA Assessment - {system_name}",
            organization=organization,
            scope=scope,
            assessment_date=datetime.utcnow(),
            assessor=assessor,
            overall_status=overall_status,
            control_checks=control_checks,
            summary=summary,
            recommendations=recommendations,
        )
        
        self._assessments.append(report)
        
        logger.info(
            "hipaa_assessment_complete",
            report_id=report.report_id,
            system_name=system_name,
            overall_status=overall_status.value,
            total_controls=len(control_checks),
        )
        
        return report
    
    def _check_control(
        self,
        control: ComplianceControl,
        evidence_provided: list[str],
    ) -> ControlCheck:
        """Check a single compliance control."""
        findings = []
        recommendations = []
        
        # Check if evidence covers requirements
        required_evidence = set(control.evidence_required)
        provided_evidence = set(evidence_provided)
        
        missing_evidence = required_evidence - provided_evidence
        
        if not missing_evidence:
            status = ComplianceStatus.COMPLIANT
            findings.append("All required evidence provided")
            risk_level = RiskLevel.LOW
        elif len(provided_evidence) >= len(required_evidence) // 2:
            status = ComplianceStatus.PARTIAL
            findings.append(f"Missing evidence: {', '.join(missing_evidence)}")
            risk_level = RiskLevel.MEDIUM
            if self.config.auto_recommendations:
                recommendations.append(
                    f"Provide documentation for: {', '.join(missing_evidence)}"
                )
        else:
            status = ComplianceStatus.NON_COMPLIANT
            findings.append(f"Insufficient evidence. Missing: {', '.join(missing_evidence)}")
            risk_level = (
                RiskLevel.CRITICAL
                if control.control_type == ControlType.REQUIRED
                else RiskLevel.HIGH
            )
            if self.config.auto_recommendations:
                recommendations.append(
                    f"URGENT: Implement {control.name} control per {control.regulation_reference}"
                )
                recommendations.append(control.implementation_guidance)
        
        return ControlCheck(
            control_id=control.control_id,
            status=status,
            findings=findings,
            evidence_provided=evidence_provided,
            recommendations=recommendations,
            risk_level=risk_level,
        )
    
    def _calculate_summary(self, checks: list[ControlCheck]) -> dict[str, Any]:
        """Calculate summary statistics."""
        status_counts: dict[str, int] = defaultdict(int)
        risk_counts: dict[str, int] = defaultdict(int)
        
        for check in checks:
            status_counts[check.status.value] += 1
            if check.risk_level:
                risk_counts[check.risk_level.value] += 1
        
        total = len(checks)
        compliant = status_counts.get("compliant", 0)
        
        return {
            "total_controls": total,
            "compliant": compliant,
            "partial": status_counts.get("partial", 0),
            "non_compliant": status_counts.get("non_compliant", 0),
            "not_applicable": status_counts.get("not_applicable", 0),
            "compliance_rate": round(compliant / total * 100, 1) if total > 0 else 0,
            "risk_distribution": dict(risk_counts),
            "critical_risks": risk_counts.get("critical", 0),
            "high_risks": risk_counts.get("high", 0),
        }
    
    def _determine_overall_status(self, checks: list[ControlCheck]) -> ComplianceStatus:
        """Determine overall compliance status."""
        # Required controls must be compliant
        required_checks = [
            c for c in checks
            if self._get_control(c.control_id).control_type == ControlType.REQUIRED
        ]
        
        required_non_compliant = any(
            c.status == ComplianceStatus.NON_COMPLIANT
            for c in required_checks
        )
        
        if required_non_compliant:
            return ComplianceStatus.NON_COMPLIANT
        
        required_partial = any(
            c.status == ComplianceStatus.PARTIAL
            for c in required_checks
        )
        
        if required_partial:
            return ComplianceStatus.PARTIAL
        
        # Check addressable controls
        addressable_non_compliant = sum(
            1 for c in checks
            if c.status == ComplianceStatus.NON_COMPLIANT
            and self._get_control(c.control_id).control_type == ControlType.ADDRESSABLE
        )
        
        if addressable_non_compliant > len(checks) // 4:
            return ComplianceStatus.PARTIAL
        
        return ComplianceStatus.COMPLIANT
    
    def _generate_recommendations(self, checks: list[ControlCheck]) -> list[str]:
        """Generate prioritized recommendations."""
        recommendations = []
        
        # Critical/High risk first
        for check in sorted(
            checks,
            key=lambda c: (
                0 if c.risk_level == RiskLevel.CRITICAL else
                1 if c.risk_level == RiskLevel.HIGH else
                2 if c.risk_level == RiskLevel.MEDIUM else 3
            )
        ):
            if check.status != ComplianceStatus.COMPLIANT:
                control = self._get_control(check.control_id)
                recommendations.extend(check.recommendations)
        
        return recommendations[:10]  # Top 10 recommendations
    
    def _get_control(self, control_id: str) -> ComplianceControl:
        """Get control by ID."""
        for control in self.controls:
            if control.control_id == control_id:
                return control
        raise ValueError(f"Control not found: {control_id}")
    
    def _generate_report_id(self, system_name: str, organization: str) -> str:
        """Generate unique report ID."""
        import time
        content = f"{system_name}:{organization}:{time.time_ns()}"
        return f"hipaa_{hashlib.sha256(content.encode()).hexdigest()[:12]}"
    
    def list_controls(
        self,
        category: HIPAACategory | None = None,
        control_type: ControlType | None = None,
    ) -> list[ComplianceControl]:
        """List available controls with filters."""
        controls = self.controls
        
        if category:
            controls = [c for c in controls if c.category == category]
        if control_type:
            controls = [c for c in controls if c.control_type == control_type]
        
        return controls
    
    def get_assessment_history(
        self,
        organization: str | None = None,
        limit: int = 10,
    ) -> list[ComplianceReport]:
        """Get assessment history."""
        reports = self._assessments
        
        if organization:
            reports = [r for r in reports if r.organization == organization]
        
        return sorted(reports, key=lambda r: r.assessment_date, reverse=True)[:limit]
