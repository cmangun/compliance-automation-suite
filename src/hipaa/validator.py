"""
HIPAA Compliance Validator

Comprehensive HIPAA compliance validation for healthcare systems
covering administrative, physical, and technical safeguards.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


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
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"
    NEEDS_REVIEW = "needs_review"


@dataclass
class ComplianceCheck:
    """A single HIPAA compliance check."""
    
    check_id: str
    name: str
    description: str
    category: HIPAACategory
    status: ComplianceStatus
    findings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    cfr_reference: str = ""


@dataclass
class HIPAAComplianceReport:
    """Complete HIPAA compliance report."""
    
    organization: str
    assessment_date: datetime
    assessor: str
    checks: list[ComplianceCheck]
    overall_status: ComplianceStatus
    risk_score: float
    
    @property
    def summary(self) -> dict[str, int]:
        """Get status summary."""
        summary = {}
        for status in ComplianceStatus:
            summary[status.value] = sum(
                1 for c in self.checks if c.status == status
            )
        return summary
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "organization": self.organization,
            "assessment_date": self.assessment_date.isoformat(),
            "assessor": self.assessor,
            "overall_status": self.overall_status.value,
            "risk_score": self.risk_score,
            "summary": self.summary,
            "checks": [
                {
                    "check_id": c.check_id,
                    "name": c.name,
                    "category": c.category.value,
                    "status": c.status.value,
                    "findings": c.findings,
                    "recommendations": c.recommendations,
                    "cfr_reference": c.cfr_reference,
                }
                for c in self.checks
            ],
        }


class HIPAAValidator:
    """
    HIPAA compliance validator.
    
    Validates compliance against:
    - 45 CFR 164.308: Administrative Safeguards
    - 45 CFR 164.310: Physical Safeguards
    - 45 CFR 164.312: Technical Safeguards
    - 45 CFR 164.314: Organizational Requirements
    - 45 CFR 164.316: Policies and Procedures
    """
    
    def __init__(
        self,
        organization: str,
        assessor: str = "Automated Assessment",
    ):
        """
        Initialize validator.
        
        Args:
            organization: Organization being assessed.
            assessor: Name of assessor.
        """
        self.organization = organization
        self.assessor = assessor
        self.checks: list[ComplianceCheck] = []
    
    def run_full_assessment(
        self,
        system_config: dict[str, Any] | None = None,
    ) -> HIPAAComplianceReport:
        """
        Run complete HIPAA compliance assessment.
        
        Args:
            system_config: System configuration to validate.
            
        Returns:
            HIPAAComplianceReport with all findings.
        """
        self.checks = []
        config = system_config or {}
        
        # Run all category assessments
        self._assess_administrative_safeguards(config)
        self._assess_physical_safeguards(config)
        self._assess_technical_safeguards(config)
        self._assess_organizational_requirements(config)
        self._assess_policies_procedures(config)
        
        # Calculate overall status and risk
        overall_status = self._calculate_overall_status()
        risk_score = self._calculate_risk_score()
        
        return HIPAAComplianceReport(
            organization=self.organization,
            assessment_date=datetime.utcnow(),
            assessor=self.assessor,
            checks=self.checks,
            overall_status=overall_status,
            risk_score=risk_score,
        )
    
    def _assess_administrative_safeguards(
        self,
        config: dict[str, Any],
    ) -> None:
        """Assess 45 CFR 164.308 Administrative Safeguards."""
        
        # Security Management Process (164.308(a)(1))
        self.checks.append(
            ComplianceCheck(
                check_id="ADM-001",
                name="Risk Analysis",
                description="Conduct accurate and thorough risk analysis",
                category=HIPAACategory.ADMINISTRATIVE,
                status=self._check_config(config, "risk_analysis_complete"),
                cfr_reference="45 CFR 164.308(a)(1)(ii)(A)",
                findings=["Risk analysis documentation should be reviewed annually"],
                recommendations=[
                    "Maintain documented risk analysis",
                    "Update risk assessment annually",
                    "Include all ePHI systems in scope",
                ],
            )
        )
        
        # Assigned Security Responsibility (164.308(a)(2))
        self.checks.append(
            ComplianceCheck(
                check_id="ADM-002",
                name="Security Officer",
                description="Designate security official responsible for policies",
                category=HIPAACategory.ADMINISTRATIVE,
                status=self._check_config(config, "security_officer_assigned"),
                cfr_reference="45 CFR 164.308(a)(2)",
                recommendations=[
                    "Formally designate HIPAA Security Officer",
                    "Document security responsibilities",
                ],
            )
        )
        
        # Workforce Security (164.308(a)(3))
        self.checks.append(
            ComplianceCheck(
                check_id="ADM-003",
                name="Access Authorization",
                description="Implement policies for authorizing access to ePHI",
                category=HIPAACategory.ADMINISTRATIVE,
                status=self._check_config(config, "access_authorization_policy"),
                cfr_reference="45 CFR 164.308(a)(3)(ii)(A)",
                recommendations=[
                    "Implement role-based access control",
                    "Document access authorization procedures",
                    "Maintain access authorization records",
                ],
            )
        )
        
        # Information Access Management (164.308(a)(4))
        self.checks.append(
            ComplianceCheck(
                check_id="ADM-004",
                name="Access Establishment",
                description="Policies for granting access to ePHI",
                category=HIPAACategory.ADMINISTRATIVE,
                status=self._check_config(config, "access_management_policy"),
                cfr_reference="45 CFR 164.308(a)(4)(ii)(B)",
                recommendations=[
                    "Implement access provisioning workflow",
                    "Document access modification procedures",
                ],
            )
        )
        
        # Security Awareness Training (164.308(a)(5))
        self.checks.append(
            ComplianceCheck(
                check_id="ADM-005",
                name="Security Training",
                description="Security awareness and training program",
                category=HIPAACategory.ADMINISTRATIVE,
                status=self._check_config(config, "security_training_program"),
                cfr_reference="45 CFR 164.308(a)(5)(i)",
                recommendations=[
                    "Implement annual security training",
                    "Track training completion",
                    "Include phishing awareness training",
                ],
            )
        )
        
        # Contingency Plan (164.308(a)(7))
        self.checks.append(
            ComplianceCheck(
                check_id="ADM-006",
                name="Data Backup Plan",
                description="Establish procedures for data backup",
                category=HIPAACategory.ADMINISTRATIVE,
                status=self._check_config(config, "backup_plan"),
                cfr_reference="45 CFR 164.308(a)(7)(ii)(A)",
                recommendations=[
                    "Implement regular backup procedures",
                    "Test backup restoration",
                    "Document backup and recovery procedures",
                ],
            )
        )
    
    def _assess_physical_safeguards(
        self,
        config: dict[str, Any],
    ) -> None:
        """Assess 45 CFR 164.310 Physical Safeguards."""
        
        # Facility Access Controls (164.310(a)(1))
        self.checks.append(
            ComplianceCheck(
                check_id="PHY-001",
                name="Facility Access",
                description="Limit physical access to information systems",
                category=HIPAACategory.PHYSICAL,
                status=self._check_config(config, "facility_access_controls"),
                cfr_reference="45 CFR 164.310(a)(1)",
                recommendations=[
                    "Implement physical access controls",
                    "Maintain visitor logs",
                    "Secure server rooms",
                ],
            )
        )
        
        # Workstation Use (164.310(b))
        self.checks.append(
            ComplianceCheck(
                check_id="PHY-002",
                name="Workstation Security",
                description="Policies for workstation use and security",
                category=HIPAACategory.PHYSICAL,
                status=self._check_config(config, "workstation_policy"),
                cfr_reference="45 CFR 164.310(b)",
                recommendations=[
                    "Implement workstation security policy",
                    "Use screen locks and privacy screens",
                    "Encrypt workstation storage",
                ],
            )
        )
        
        # Device and Media Controls (164.310(d)(1))
        self.checks.append(
            ComplianceCheck(
                check_id="PHY-003",
                name="Media Disposal",
                description="Proper disposal of ePHI media",
                category=HIPAACategory.PHYSICAL,
                status=self._check_config(config, "media_disposal_policy"),
                cfr_reference="45 CFR 164.310(d)(2)(i)",
                recommendations=[
                    "Implement secure media disposal procedures",
                    "Maintain disposal records",
                    "Use certified destruction services",
                ],
            )
        )
    
    def _assess_technical_safeguards(
        self,
        config: dict[str, Any],
    ) -> None:
        """Assess 45 CFR 164.312 Technical Safeguards."""
        
        # Access Control (164.312(a)(1))
        self.checks.append(
            ComplianceCheck(
                check_id="TEC-001",
                name="Unique User Identification",
                description="Assign unique identifier for each user",
                category=HIPAACategory.TECHNICAL,
                status=self._check_config(config, "unique_user_ids"),
                cfr_reference="45 CFR 164.312(a)(2)(i)",
                recommendations=[
                    "Implement unique user IDs",
                    "Prohibit shared accounts",
                    "Document user ID assignment",
                ],
            )
        )
        
        self.checks.append(
            ComplianceCheck(
                check_id="TEC-002",
                name="Automatic Logoff",
                description="Implement automatic logoff procedures",
                category=HIPAACategory.TECHNICAL,
                status=self._check_config(config, "automatic_logoff"),
                cfr_reference="45 CFR 164.312(a)(2)(iii)",
                recommendations=[
                    "Configure session timeouts",
                    "Implement idle session termination",
                ],
            )
        )
        
        self.checks.append(
            ComplianceCheck(
                check_id="TEC-003",
                name="Encryption",
                description="Implement encryption for ePHI",
                category=HIPAACategory.TECHNICAL,
                status=self._check_config(config, "encryption_enabled"),
                cfr_reference="45 CFR 164.312(a)(2)(iv)",
                recommendations=[
                    "Encrypt ePHI at rest",
                    "Use TLS for data in transit",
                    "Implement key management",
                ],
            )
        )
        
        # Audit Controls (164.312(b))
        self.checks.append(
            ComplianceCheck(
                check_id="TEC-004",
                name="Audit Logging",
                description="Implement audit controls for ePHI access",
                category=HIPAACategory.TECHNICAL,
                status=self._check_config(config, "audit_logging"),
                cfr_reference="45 CFR 164.312(b)",
                recommendations=[
                    "Enable comprehensive audit logging",
                    "Retain logs for minimum 6 years",
                    "Implement log monitoring",
                ],
            )
        )
        
        # Integrity (164.312(c)(1))
        self.checks.append(
            ComplianceCheck(
                check_id="TEC-005",
                name="Data Integrity",
                description="Protect ePHI from improper alteration",
                category=HIPAACategory.TECHNICAL,
                status=self._check_config(config, "integrity_controls"),
                cfr_reference="45 CFR 164.312(c)(1)",
                recommendations=[
                    "Implement data integrity checks",
                    "Use checksums for data validation",
                    "Maintain change logs",
                ],
            )
        )
        
        # Transmission Security (164.312(e)(1))
        self.checks.append(
            ComplianceCheck(
                check_id="TEC-006",
                name="Transmission Security",
                description="Protect ePHI during transmission",
                category=HIPAACategory.TECHNICAL,
                status=self._check_config(config, "transmission_security"),
                cfr_reference="45 CFR 164.312(e)(1)",
                recommendations=[
                    "Use TLS 1.2 or higher",
                    "Implement end-to-end encryption",
                    "Disable insecure protocols",
                ],
            )
        )
    
    def _assess_organizational_requirements(
        self,
        config: dict[str, Any],
    ) -> None:
        """Assess 45 CFR 164.314 Organizational Requirements."""
        
        self.checks.append(
            ComplianceCheck(
                check_id="ORG-001",
                name="Business Associate Agreements",
                description="BAAs with all business associates handling ePHI",
                category=HIPAACategory.ORGANIZATIONAL,
                status=self._check_config(config, "baa_compliance"),
                cfr_reference="45 CFR 164.314(a)(1)",
                recommendations=[
                    "Maintain BAAs with all vendors",
                    "Review BAAs annually",
                    "Track BAA expiration dates",
                ],
            )
        )
    
    def _assess_policies_procedures(
        self,
        config: dict[str, Any],
    ) -> None:
        """Assess 45 CFR 164.316 Policies and Procedures."""
        
        self.checks.append(
            ComplianceCheck(
                check_id="POL-001",
                name="Policy Documentation",
                description="Maintain written security policies",
                category=HIPAACategory.POLICIES,
                status=self._check_config(config, "documented_policies"),
                cfr_reference="45 CFR 164.316(a)",
                recommendations=[
                    "Document all security policies",
                    "Review policies annually",
                    "Maintain policy version history",
                ],
            )
        )
        
        self.checks.append(
            ComplianceCheck(
                check_id="POL-002",
                name="Documentation Retention",
                description="Retain policies for 6 years",
                category=HIPAACategory.POLICIES,
                status=self._check_config(config, "policy_retention"),
                cfr_reference="45 CFR 164.316(b)(2)(i)",
                recommendations=[
                    "Implement 6-year retention policy",
                    "Archive historical policies",
                    "Maintain audit trail of changes",
                ],
            )
        )
    
    def _check_config(
        self,
        config: dict[str, Any],
        key: str,
    ) -> ComplianceStatus:
        """Check configuration for compliance status."""
        value = config.get(key)
        
        if value is True:
            return ComplianceStatus.COMPLIANT
        elif value is False:
            return ComplianceStatus.NON_COMPLIANT
        elif value == "partial":
            return ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            return ComplianceStatus.NEEDS_REVIEW
    
    def _calculate_overall_status(self) -> ComplianceStatus:
        """Calculate overall compliance status."""
        non_compliant = sum(
            1 for c in self.checks
            if c.status == ComplianceStatus.NON_COMPLIANT
        )
        partial = sum(
            1 for c in self.checks
            if c.status == ComplianceStatus.PARTIALLY_COMPLIANT
        )
        
        if non_compliant > 0:
            return ComplianceStatus.NON_COMPLIANT
        elif partial > 3:
            return ComplianceStatus.PARTIALLY_COMPLIANT
        elif partial > 0:
            return ComplianceStatus.NEEDS_REVIEW
        else:
            return ComplianceStatus.COMPLIANT
    
    def _calculate_risk_score(self) -> float:
        """Calculate risk score (0-100, lower is better)."""
        if not self.checks:
            return 100.0
        
        scores = {
            ComplianceStatus.COMPLIANT: 0,
            ComplianceStatus.PARTIALLY_COMPLIANT: 50,
            ComplianceStatus.NON_COMPLIANT: 100,
            ComplianceStatus.NOT_APPLICABLE: 0,
            ComplianceStatus.NEEDS_REVIEW: 25,
        }
        
        total_score = sum(scores[c.status] for c in self.checks)
        return total_score / len(self.checks)
