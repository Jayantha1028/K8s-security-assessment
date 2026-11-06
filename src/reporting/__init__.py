"""
Reporting Package - Kubernetes Security Assessment Platform.

Exported Modules:
  - start_web_console: Self-hosted dark-mode Web Management Console
  - generate_compliance_reports: Executive compliance audit generator (PDF & HTML)
"""

from .web_dashboard import start_web_console
from .generate_executive_audit import generate_compliance_reports

__all__ = [
    "start_web_console",
    "generate_compliance_reports",
]
