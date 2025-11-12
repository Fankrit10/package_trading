"""
Schema definitions for vulnerability detection reports.

This module defines data models for detected vulnerabilities and detection results.
"""

from typing import Optional, List
from enum import Enum
from pydantic import BaseModel, Field
from datetime import datetime


class VulnSeverity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class VulnType(str, Enum):
    """Common vulnerability types."""
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    COMMAND_INJECTION = "Command Injection"
    PATH_TRAVERSAL = "Path Traversal"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    BROKEN_AUTH = "Broken Authentication"
    SENSITIVE_DATA_EXPOSURE = "Sensitive Data Exposure"
    XML_EXTERNAL_ENTITIES = "XML External Entities (XXE)"
    BROKEN_ACCESS_CONTROL = "Broken Access Control"
    SECURITY_MISCONFIGURATION = "Security Misconfiguration"
    MISSING_VALIDATION = "Missing Input Validation"
    HARDCODED_CREDENTIALS = "Hardcoded Credentials"
    INSECURE_CRYPTOGRAPHY = "Insecure Cryptography"
    WEAK_DEPENDENCIES = "Weak Dependencies"
    UNSAFE_REGEX = "Unsafe Regular Expression"
    OTHER = "Other"


class DetectedVulnerability(BaseModel):
    """Model for a single detected vulnerability."""
    vulnerability_id: str = Field(..., description="Unique identifier for the vulnerability")
    file_path: str = Field(..., description="Path to the file containing the vulnerability")
    vuln_type: VulnType = Field(..., description="Type of vulnerability")
    severity: VulnSeverity = Field(..., description="Severity level")
    code_snippet: str = Field(..., description="The vulnerable code snippet")
    description: str = Field(..., description="Description of the vulnerability")
    line_number: Optional[int] = Field(None, description="Approximate line number (if detectable)")
    cwe_id: Optional[str] = Field(None, description="CWE identifier")
    owasp_category: Optional[str] = Field(None, description="OWASP category")
    exploitability: str = Field(..., description="Exploitability assessment")
    business_impact: str = Field(..., description="Potential business impact")
    remediation_notes: Optional[str] = Field(None, description="Initial remediation suggestions")

    class Config:
        """Pydantic configuration."""
        use_enum_values = False


class FileAnalysisResult(BaseModel):
    """Model for the analysis result of a single file."""
    file_path: str = Field(..., description="Path to the analyzed file")
    file_type: str = Field(..., description="File type/extension")
    total_vulnerabilities: int = Field(..., description="Total vulnerabilities found")
    vulnerabilities: List[DetectedVulnerability] = Field(default_factory=list)
    code_patterns_analysis: str = Field(..., description="Code pattern analysis findings")
    risk_score: float = Field(..., description="Overall file risk score (0-10)")
    analysis_status: str = Field(default="completed", description="Status of analysis")

    class Config:
        """Pydantic configuration."""
        use_enum_values = False


class DetectionReport(BaseModel):
    """Model for the complete detection report."""
    project_path: str = Field(..., description="Path to the project being scanned")
    scan_date: str = Field(default_factory=lambda: datetime.now().isoformat())
    total_files_scanned: int = Field(..., description="Total files scanned")
    files_with_vulnerabilities: int = Field(..., description="Files with at least one vulnerability")
    total_vulnerabilities: int = Field(..., description="Total vulnerabilities found")
    critical_count: int = Field(default=0)
    high_count: int = Field(default=0)
    medium_count: int = Field(default=0)
    low_count: int = Field(default=0)
    info_count: int = Field(default=0)
    file_results: List[FileAnalysisResult] = Field(default_factory=list)
    overall_risk_score: float = Field(..., description="Overall project risk score (0-10)")
    summary: str = Field(..., description="Executive summary of findings")

    class Config:
        """Pydantic configuration."""
        use_enum_values = False

