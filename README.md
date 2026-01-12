# Compliance Automation Suite

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![HIPAA Compliant](https://img.shields.io/badge/HIPAA-Compliant-green.svg)](#compliance)

**Automated compliance validation for healthcare AI systems - HIPAA, FDA, and SOC 2.**

## 🎯 Business Impact

- **Automated compliance checking** against HIPAA security rule
- **Pre-defined AI-specific controls** for healthcare ML systems
- **Risk-scored findings** with prioritized remediation
- **Audit-ready reporting** for regulatory submissions

## ✨ Key Features

- **10 AI-Specific HIPAA Controls** for ML systems
- **Automated Evidence Checking** for compliance validation
- **Risk Scoring** (Critical, High, Medium, Low)
- **Remediation Recommendations** with implementation guidance
- **Assessment History** for compliance tracking

## 🚀 Quick Start

```python
from src.hipaa.validator import HIPAAValidator

validator = HIPAAValidator()

# Run HIPAA assessment
report = validator.assess_system(
    system_name="Clinical ML Platform",
    organization="HealthCare Inc",
    scope="Production ML inference pipeline",
    evidence={
        "HIPAA-AI-001": ["risk_assessment.pdf", "data_flow.pdf"],
        "HIPAA-AI-002": ["access_control_policy.pdf", "rbac_config.yaml"],
        "HIPAA-AI-003": ["audit_logs.json", "log_retention_policy.pdf"],
    },
)

print(f"Status: {report.overall_status}")
print(f"Compliance Rate: {report.summary['compliance_rate']}%")
```

## 📋 Included Controls

| Control ID | Name | Type |
|------------|------|------|
| HIPAA-AI-001 | Risk Analysis | Required |
| HIPAA-AI-002 | Access Control | Required |
| HIPAA-AI-003 | Audit Controls | Required |
| HIPAA-AI-004 | Data Encryption | Addressable |
| HIPAA-AI-005 | PHI De-identification | Required |
| HIPAA-AI-006 | Minimum Necessary | Required |
| HIPAA-AI-007 | Business Associate Agreements | Required |
| HIPAA-AI-008 | Workforce Training | Required |
| HIPAA-AI-009 | Incident Response | Required |
| HIPAA-AI-010 | Model Explainability | Addressable |

## 👤 Author

**Christopher Mangun** - [LinkedIn](https://linkedin.com/in/cmangun)
