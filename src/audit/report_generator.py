"""
HIPAA Audit Report Generator.

Production audit reporting for healthcare compliance:
- Automated compliance evidence collection
- HIPAA Security Rule audit support
- Access log analysis and anomaly detection
- Risk assessment scoring
- Executive summary generation
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    
    HIPAA_SECURITY = "hipaa_security"
    HIPAA_PRIVACY = "hipaa_privacy"
    FDA_21_CFR_11 = "fda_21_cfr_11"
    SOC2_TYPE2 = "soc2_type2"
    HITRUST = "hitrust"


class ControlStatus(Enum):
    """Compliance control status."""
    
    COMPLIANT = "compliant"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    NOT_TESTED = "not_tested"


class RiskLevel(Enum):
    """Risk assessment levels."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class ControlEvidence:
    """Evidence for a compliance control."""
    
    evidence_id: str
    control_id: str
    evidence_type: str  # log, config, screenshot, document
    description: str
    source: str
    collected_at: datetime
    data: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "control_id": self.control_id,
            "evidence_type": self.evidence_type,
            "description": self.description,
            "source": self.source,
            "collected_at": self.collected_at.isoformat(),
            "data": self.data,
        }


@dataclass
class ControlAssessment:
    """Assessment of a single compliance control."""
    
    control_id: str
    control_name: str
    description: str
    category: str
    status: ControlStatus
    risk_level: RiskLevel
    evidence: list[ControlEvidence]
    findings: list[str]
    recommendations: list[str]
    tested_at: datetime
    tested_by: str = "automated"
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "control_name": self.control_name,
            "description": self.description,
            "category": self.category,
            "status": self.status.value,
            "risk_level": self.risk_level.value,
            "evidence_count": len(self.evidence),
            "evidence": [e.to_dict() for e in self.evidence],
            "findings": self.findings,
            "recommendations": self.recommendations,
            "tested_at": self.tested_at.isoformat(),
            "tested_by": self.tested_by,
        }


@dataclass
class AccessLogEntry:
    """Access log entry for audit analysis."""
    
    timestamp: datetime
    user_id: str
    resource_type: str
    resource_id: str
    action: str
    outcome: str  # success, failure, denied
    ip_address: str
    user_agent: str = ""
    phi_accessed: bool = False
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "action": self.action,
            "outcome": self.outcome,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "phi_accessed": self.phi_accessed,
        }


@dataclass
class AuditReport:
    """Complete compliance audit report."""
    
    report_id: str
    framework: ComplianceFramework
    audit_period_start: datetime
    audit_period_end: datetime
    organization: str
    assessments: list[ControlAssessment]
    overall_status: ControlStatus
    risk_score: float  # 0-100
    executive_summary: str
    generated_at: datetime
    generated_by: str
    
    @property
    def compliant_count(self) -> int:
        return sum(1 for a in self.assessments if a.status == ControlStatus.COMPLIANT)
    
    @property
    def non_compliant_count(self) -> int:
        return sum(1 for a in self.assessments if a.status == ControlStatus.NON_COMPLIANT)
    
    @property
    def compliance_percentage(self) -> float:
        tested = [a for a in self.assessments if a.status != ControlStatus.NOT_TESTED]
        if not tested:
            return 0.0
        compliant = sum(1 for a in tested if a.status == ControlStatus.COMPLIANT)
        return (compliant / len(tested)) * 100
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "framework": self.framework.value,
            "audit_period": {
                "start": self.audit_period_start.isoformat(),
                "end": self.audit_period_end.isoformat(),
            },
            "organization": self.organization,
            "summary": {
                "overall_status": self.overall_status.value,
                "risk_score": self.risk_score,
                "compliance_percentage": self.compliance_percentage,
                "total_controls": len(self.assessments),
                "compliant": self.compliant_count,
                "non_compliant": self.non_compliant_count,
            },
            "executive_summary": self.executive_summary,
            "assessments": [a.to_dict() for a in self.assessments],
            "generated_at": self.generated_at.isoformat(),
            "generated_by": self.generated_by,
        }


# HIPAA Security Rule Controls
HIPAA_SECURITY_CONTROLS = [
    {
        "id": "164.308(a)(1)(i)",
        "name": "Security Management Process",
        "description": "Implement policies and procedures to prevent, detect, contain, and correct security violations",
        "category": "Administrative Safeguards",
    },
    {
        "id": "164.308(a)(1)(ii)(A)",
        "name": "Risk Analysis",
        "description": "Conduct an accurate and thorough assessment of potential risks and vulnerabilities",
        "category": "Administrative Safeguards",
    },
    {
        "id": "164.308(a)(1)(ii)(B)",
        "name": "Risk Management",
        "description": "Implement security measures sufficient to reduce risks and vulnerabilities",
        "category": "Administrative Safeguards",
    },
    {
        "id": "164.308(a)(3)(i)",
        "name": "Workforce Security",
        "description": "Implement policies and procedures to ensure workforce members have appropriate access",
        "category": "Administrative Safeguards",
    },
    {
        "id": "164.308(a)(4)(i)",
        "name": "Information Access Management",
        "description": "Implement policies and procedures for authorizing access to ePHI",
        "category": "Administrative Safeguards",
    },
    {
        "id": "164.308(a)(5)(i)",
        "name": "Security Awareness and Training",
        "description": "Implement a security awareness and training program for workforce members",
        "category": "Administrative Safeguards",
    },
    {
        "id": "164.308(a)(6)(i)",
        "name": "Security Incident Procedures",
        "description": "Implement policies and procedures to address security incidents",
        "category": "Administrative Safeguards",
    },
    {
        "id": "164.310(a)(1)",
        "name": "Facility Access Controls",
        "description": "Implement policies and procedures to limit physical access to ePHI systems",
        "category": "Physical Safeguards",
    },
    {
        "id": "164.310(b)",
        "name": "Workstation Use",
        "description": "Implement policies and procedures for proper workstation use",
        "category": "Physical Safeguards",
    },
    {
        "id": "164.310(d)(1)",
        "name": "Device and Media Controls",
        "description": "Implement policies and procedures for receipt and removal of hardware and media",
        "category": "Physical Safeguards",
    },
    {
        "id": "164.312(a)(1)",
        "name": "Access Control",
        "description": "Implement technical policies and procedures to allow access only to authorized persons",
        "category": "Technical Safeguards",
    },
    {
        "id": "164.312(b)",
        "name": "Audit Controls",
        "description": "Implement hardware, software, and procedural mechanisms to record and examine access",
        "category": "Technical Safeguards",
    },
    {
        "id": "164.312(c)(1)",
        "name": "Integrity",
        "description": "Implement policies and procedures to protect ePHI from improper alteration or destruction",
        "category": "Technical Safeguards",
    },
    {
        "id": "164.312(d)",
        "name": "Person or Entity Authentication",
        "description": "Implement procedures to verify that a person or entity seeking access is the one claimed",
        "category": "Technical Safeguards",
    },
    {
        "id": "164.312(e)(1)",
        "name": "Transmission Security",
        "description": "Implement technical security measures to guard against unauthorized access during transmission",
        "category": "Technical Safeguards",
    },
]


class AuditReportGenerator:
    """
    HIPAA compliance audit report generator.
    
    Features:
    - Automated evidence collection
    - Control assessment
    - Risk scoring
    - Executive summary generation
    - Access log analysis
    """
    
    def __init__(
        self,
        organization: str,
        framework: ComplianceFramework = ComplianceFramework.HIPAA_SECURITY,
    ):
        self.organization = organization
        self.framework = framework
        self._access_logs: list[AccessLogEntry] = []
        self._evidence_store: dict[str, list[ControlEvidence]] = {}
    
    def add_access_log(self, entry: AccessLogEntry) -> None:
        """Add access log entry for analysis."""
        self._access_logs.append(entry)
    
    def add_evidence(self, evidence: ControlEvidence) -> None:
        """Add evidence for a control."""
        if evidence.control_id not in self._evidence_store:
            self._evidence_store[evidence.control_id] = []
        self._evidence_store[evidence.control_id].append(evidence)
    
    def generate_report(
        self,
        period_start: datetime,
        period_end: datetime,
        assessor: str = "automated",
    ) -> AuditReport:
        """
        Generate comprehensive audit report.
        
        Args:
            period_start: Audit period start date
            period_end: Audit period end date
            assessor: Name of assessor
            
        Returns:
            Complete audit report
        """
        report_id = self._generate_report_id(period_start, period_end)
        
        logger.info(
            "audit_report_generation_started",
            report_id=report_id,
            framework=self.framework.value,
            period_start=period_start.isoformat(),
            period_end=period_end.isoformat(),
        )
        
        # Assess each control
        assessments = self._assess_all_controls(period_start, period_end, assessor)
        
        # Calculate overall status and risk
        overall_status = self._calculate_overall_status(assessments)
        risk_score = self._calculate_risk_score(assessments)
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            assessments,
            overall_status,
            risk_score,
            period_start,
            period_end,
        )
        
        report = AuditReport(
            report_id=report_id,
            framework=self.framework,
            audit_period_start=period_start,
            audit_period_end=period_end,
            organization=self.organization,
            assessments=assessments,
            overall_status=overall_status,
            risk_score=risk_score,
            executive_summary=executive_summary,
            generated_at=datetime.utcnow(),
            generated_by=assessor,
        )
        
        logger.info(
            "audit_report_generated",
            report_id=report_id,
            compliance_percentage=report.compliance_percentage,
            risk_score=risk_score,
        )
        
        return report
    
    def analyze_access_patterns(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> dict[str, Any]:
        """
        Analyze access logs for compliance issues.
        
        Returns analysis including:
        - Unusual access patterns
        - Failed authentication attempts
        - PHI access frequency
        - After-hours access
        """
        relevant_logs = [
            log for log in self._access_logs
            if period_start <= log.timestamp <= period_end
        ]
        
        analysis = {
            "total_access_events": len(relevant_logs),
            "unique_users": len(set(log.user_id for log in relevant_logs)),
            "phi_access_events": sum(1 for log in relevant_logs if log.phi_accessed),
            "failed_authentications": sum(1 for log in relevant_logs if log.outcome == "failure"),
            "denied_access_attempts": sum(1 for log in relevant_logs if log.outcome == "denied"),
            "after_hours_access": self._count_after_hours_access(relevant_logs),
            "anomalies": self._detect_anomalies(relevant_logs),
            "top_phi_accessors": self._get_top_phi_accessors(relevant_logs),
            "access_by_resource_type": self._group_by_resource_type(relevant_logs),
        }
        
        return analysis
    
    def _generate_report_id(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> str:
        """Generate unique report ID."""
        content = f"{self.organization}:{self.framework.value}:{period_start.isoformat()}:{period_end.isoformat()}"
        return f"audit_{hashlib.sha256(content.encode()).hexdigest()[:12]}"
    
    def _assess_all_controls(
        self,
        period_start: datetime,
        period_end: datetime,
        assessor: str,
    ) -> list[ControlAssessment]:
        """Assess all controls for the framework."""
        assessments: list[ControlAssessment] = []
        
        controls = HIPAA_SECURITY_CONTROLS if self.framework == ComplianceFramework.HIPAA_SECURITY else []
        
        for control in controls:
            assessment = self._assess_control(
                control,
                period_start,
                period_end,
                assessor,
            )
            assessments.append(assessment)
        
        return assessments
    
    def _assess_control(
        self,
        control: dict[str, str],
        period_start: datetime,
        period_end: datetime,
        assessor: str,
    ) -> ControlAssessment:
        """Assess a single control."""
        control_id = control["id"]
        evidence = self._evidence_store.get(control_id, [])
        
        # Filter evidence to audit period
        relevant_evidence = [
            e for e in evidence
            if period_start <= e.collected_at <= period_end
        ]
        
        # Determine status based on evidence
        status, findings, recommendations = self._evaluate_control(
            control,
            relevant_evidence,
        )
        
        # Determine risk level
        risk_level = self._determine_risk_level(control, status)
        
        return ControlAssessment(
            control_id=control_id,
            control_name=control["name"],
            description=control["description"],
            category=control["category"],
            status=status,
            risk_level=risk_level,
            evidence=relevant_evidence,
            findings=findings,
            recommendations=recommendations,
            tested_at=datetime.utcnow(),
            tested_by=assessor,
        )
    
    def _evaluate_control(
        self,
        control: dict[str, str],
        evidence: list[ControlEvidence],
    ) -> tuple[ControlStatus, list[str], list[str]]:
        """Evaluate control status based on evidence."""
        findings: list[str] = []
        recommendations: list[str] = []
        
        if not evidence:
            findings.append("No evidence collected for this control")
            recommendations.append("Collect and document evidence for this control")
            return ControlStatus.NOT_TESTED, findings, recommendations
        
        # Analyze evidence types
        has_config = any(e.evidence_type == "config" for e in evidence)
        has_logs = any(e.evidence_type == "log" for e in evidence)
        has_docs = any(e.evidence_type == "document" for e in evidence)
        
        control_id = control["id"]
        
        # Control-specific evaluation logic
        if "Access Control" in control["name"] or "164.312(a)" in control_id:
            if has_config and has_logs:
                findings.append("Access control mechanisms are in place and logging is enabled")
                return ControlStatus.COMPLIANT, findings, recommendations
            elif has_config:
                findings.append("Access controls configured but audit logging may be incomplete")
                recommendations.append("Enable comprehensive access logging")
                return ControlStatus.PARTIAL, findings, recommendations
        
        elif "Audit Controls" in control["name"] or "164.312(b)" in control_id:
            if has_logs:
                findings.append("Audit logging is enabled and logs are being collected")
                return ControlStatus.COMPLIANT, findings, recommendations
            else:
                findings.append("Audit logging evidence not found")
                recommendations.append("Implement comprehensive audit logging")
                return ControlStatus.NON_COMPLIANT, findings, recommendations
        
        elif "Transmission Security" in control["name"] or "164.312(e)" in control_id:
            if has_config:
                findings.append("Encryption configuration evidence found")
                return ControlStatus.COMPLIANT, findings, recommendations
            else:
                findings.append("Transmission security configuration not documented")
                recommendations.append("Document encryption and transmission security controls")
                return ControlStatus.PARTIAL, findings, recommendations
        
        # Default evaluation based on evidence count
        if len(evidence) >= 2:
            findings.append("Sufficient evidence collected")
            return ControlStatus.COMPLIANT, findings, recommendations
        elif len(evidence) == 1:
            findings.append("Limited evidence available")
            recommendations.append("Collect additional evidence types")
            return ControlStatus.PARTIAL, findings, recommendations
        else:
            return ControlStatus.NOT_TESTED, findings, recommendations
    
    def _determine_risk_level(
        self,
        control: dict[str, str],
        status: ControlStatus,
    ) -> RiskLevel:
        """Determine risk level based on control importance and status."""
        # High-risk controls
        high_risk_controls = [
            "164.312(a)(1)",  # Access Control
            "164.312(b)",     # Audit Controls
            "164.312(e)(1)",  # Transmission Security
            "164.308(a)(1)",  # Security Management
        ]
        
        control_id = control["id"]
        
        if status == ControlStatus.COMPLIANT:
            return RiskLevel.LOW
        elif status == ControlStatus.PARTIAL:
            if any(hrc in control_id for hrc in high_risk_controls):
                return RiskLevel.MEDIUM
            return RiskLevel.LOW
        elif status == ControlStatus.NON_COMPLIANT:
            if any(hrc in control_id for hrc in high_risk_controls):
                return RiskLevel.CRITICAL
            return RiskLevel.HIGH
        else:
            return RiskLevel.INFORMATIONAL
    
    def _calculate_overall_status(
        self,
        assessments: list[ControlAssessment],
    ) -> ControlStatus:
        """Calculate overall compliance status."""
        if not assessments:
            return ControlStatus.NOT_TESTED
        
        has_critical = any(
            a.status == ControlStatus.NON_COMPLIANT
            and a.risk_level == RiskLevel.CRITICAL
            for a in assessments
        )
        
        if has_critical:
            return ControlStatus.NON_COMPLIANT
        
        non_compliant_count = sum(
            1 for a in assessments if a.status == ControlStatus.NON_COMPLIANT
        )
        
        if non_compliant_count > 0:
            return ControlStatus.PARTIAL
        
        partial_count = sum(
            1 for a in assessments if a.status == ControlStatus.PARTIAL
        )
        
        if partial_count > len(assessments) * 0.2:  # More than 20% partial
            return ControlStatus.PARTIAL
        
        return ControlStatus.COMPLIANT
    
    def _calculate_risk_score(
        self,
        assessments: list[ControlAssessment],
    ) -> float:
        """Calculate overall risk score (0-100, lower is better)."""
        if not assessments:
            return 100.0
        
        # Weight by risk level
        risk_weights = {
            RiskLevel.CRITICAL: 100,
            RiskLevel.HIGH: 75,
            RiskLevel.MEDIUM: 50,
            RiskLevel.LOW: 25,
            RiskLevel.INFORMATIONAL: 10,
        }
        
        status_multipliers = {
            ControlStatus.COMPLIANT: 0.0,
            ControlStatus.PARTIAL: 0.5,
            ControlStatus.NON_COMPLIANT: 1.0,
            ControlStatus.NOT_TESTED: 0.75,
            ControlStatus.NOT_APPLICABLE: 0.0,
        }
        
        total_risk = 0.0
        max_risk = 0.0
        
        for assessment in assessments:
            weight = risk_weights.get(assessment.risk_level, 50)
            multiplier = status_multipliers.get(assessment.status, 0.5)
            
            total_risk += weight * multiplier
            max_risk += weight
        
        if max_risk == 0:
            return 0.0
        
        return (total_risk / max_risk) * 100
    
    def _generate_executive_summary(
        self,
        assessments: list[ControlAssessment],
        overall_status: ControlStatus,
        risk_score: float,
        period_start: datetime,
        period_end: datetime,
    ) -> str:
        """Generate executive summary."""
        total = len(assessments)
        compliant = sum(1 for a in assessments if a.status == ControlStatus.COMPLIANT)
        partial = sum(1 for a in assessments if a.status == ControlStatus.PARTIAL)
        non_compliant = sum(1 for a in assessments if a.status == ControlStatus.NON_COMPLIANT)
        
        critical_findings = [
            a for a in assessments
            if a.status == ControlStatus.NON_COMPLIANT
            and a.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]
        ]
        
        summary = f"""
HIPAA Security Rule Compliance Audit Report
Organization: {self.organization}
Audit Period: {period_start.strftime('%Y-%m-%d')} to {period_end.strftime('%Y-%m-%d')}

OVERALL STATUS: {overall_status.value.upper()}
RISK SCORE: {risk_score:.1f}/100 (lower is better)

CONTROL ASSESSMENT SUMMARY:
- Total Controls Assessed: {total}
- Compliant: {compliant} ({(compliant/total)*100:.1f}%)
- Partial Compliance: {partial} ({(partial/total)*100:.1f}%)
- Non-Compliant: {non_compliant} ({(non_compliant/total)*100:.1f}%)

"""
        
        if critical_findings:
            summary += "CRITICAL FINDINGS REQUIRING IMMEDIATE ATTENTION:\n"
            for finding in critical_findings:
                summary += f"- {finding.control_id}: {finding.control_name}\n"
                for f in finding.findings:
                    summary += f"  * {f}\n"
            summary += "\n"
        
        summary += """
RECOMMENDATIONS:
1. Address all critical and high-risk findings within 30 days
2. Implement continuous monitoring for compliance drift
3. Schedule quarterly compliance reviews
4. Update security policies and procedures as needed
"""
        
        return summary.strip()
    
    # -------------------------------------------------------------------------
    # Access Log Analysis
    # -------------------------------------------------------------------------
    
    def _count_after_hours_access(
        self,
        logs: list[AccessLogEntry],
    ) -> int:
        """Count access events outside business hours (9 AM - 6 PM)."""
        count = 0
        for log in logs:
            hour = log.timestamp.hour
            if hour < 9 or hour >= 18:
                count += 1
        return count
    
    def _detect_anomalies(
        self,
        logs: list[AccessLogEntry],
    ) -> list[dict[str, Any]]:
        """Detect anomalous access patterns."""
        anomalies: list[dict[str, Any]] = []
        
        # Track access per user per day
        user_daily_access: dict[str, dict[str, int]] = {}
        
        for log in logs:
            user = log.user_id
            day = log.timestamp.strftime("%Y-%m-%d")
            
            if user not in user_daily_access:
                user_daily_access[user] = {}
            
            user_daily_access[user][day] = user_daily_access[user].get(day, 0) + 1
        
        # Detect high volume access
        for user, daily in user_daily_access.items():
            for day, count in daily.items():
                if count > 100:  # Threshold for anomaly
                    anomalies.append({
                        "type": "high_volume_access",
                        "user_id": user,
                        "date": day,
                        "access_count": count,
                        "severity": "high",
                    })
        
        # Detect multiple failed authentications
        failed_by_user: dict[str, int] = {}
        for log in logs:
            if log.outcome == "failure":
                failed_by_user[log.user_id] = failed_by_user.get(log.user_id, 0) + 1
        
        for user, count in failed_by_user.items():
            if count > 5:
                anomalies.append({
                    "type": "multiple_failed_auth",
                    "user_id": user,
                    "failure_count": count,
                    "severity": "critical" if count > 10 else "high",
                })
        
        return anomalies
    
    def _get_top_phi_accessors(
        self,
        logs: list[AccessLogEntry],
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Get users with most PHI access."""
        phi_access: dict[str, int] = {}
        
        for log in logs:
            if log.phi_accessed:
                phi_access[log.user_id] = phi_access.get(log.user_id, 0) + 1
        
        sorted_users = sorted(
            phi_access.items(),
            key=lambda x: x[1],
            reverse=True,
        )
        
        return [
            {"user_id": user, "phi_access_count": count}
            for user, count in sorted_users[:limit]
        ]
    
    def _group_by_resource_type(
        self,
        logs: list[AccessLogEntry],
    ) -> dict[str, int]:
        """Group access events by resource type."""
        by_type: dict[str, int] = {}
        
        for log in logs:
            by_type[log.resource_type] = by_type.get(log.resource_type, 0) + 1
        
        return by_type
