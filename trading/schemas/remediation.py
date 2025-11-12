"""
Schema definitions for remediation process data models.

This module defines Pydantic models and enumerations used to represent
the status, results, and plans generated during the security remediation workflow.
These schemas standardize how vulnerabilities, fixes, and validations are reported
and stored.
"""


from typing import Optional, List
from enum import Enum
from pydantic import BaseModel, Field


class RemediationStatus(str, Enum):
    """
    Enumeration of possible remediation statuses.

    Represents the state of a vulnerability during or after the remediation process.

    Attributes:
        PENDING: The vulnerability has not yet been processed.
        IN_PROGRESS: The remediation process is currently running.
        MITIGATED: The vulnerability was successfully remediated.
        PARTIALLY_MITIGATED: The vulnerability was partially fixed but may still pose risk.
        NOT_MITIGATED: The remediation attempt failed or was ineffective.
    """
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    MITIGATED = "mitigated"
    PARTIALLY_MITIGATED = "partially_mitigated"
    NOT_MITIGATED = "not_mitigated"


class ValidationResult(BaseModel):
    """
    Model representing the validation outcome of a remediated vulnerability.

    Contains metadata and results from the validation phase, indicating
    whether the remediation was successful and if any residual issues were found.

    Attributes:
        vulnerability_id (str): The unique identifier of the validated vulnerability.
        status (RemediationStatus): The validation status of the remediation.
        validation_method (str): The technique or tool used for validation.
        issues_found (List[str]): A list of remaining issues, if any, detected during validation.
        timestamp (str): The date and time when the validation was performed.
    """
    vulnerability_id: str
    status: RemediationStatus
    validation_method: str = Field(..., description="Method used for validation")
    issues_found: List[str] = Field(default_factory=list)
    timestamp: str


class RemediationResult(BaseModel):
    """
    Model representing the detailed result of a single vulnerability remediation.

    Captures the analysis outcome, applied fix, and validation results associated
    with an individual vulnerability.

    Attributes:
        id (str): The unique identifier of the vulnerability.
        tipo (str): The type or category of the vulnerability.
        accion (str): The remediation action or recommendation taken.
        codigo_sugerido (str): A preview of the suggested or generated secure code.
        resultado_validacion (RemediationStatus): The overall validation outcome.
        modelo_usado (str): The LLM or AI model used for remediation.
        file_path (str): The path to the remediated file.
        original_code (Optional[str]): The original (unfixed) code, if available.
        remediated_code (Optional[str]): The remediated code content, if available.
        validation_details (Optional[ValidationResult]): Detailed validation data, if provided.
    """
    id: str
    tipo: str
    accion: str
    codigo_sugerido: str
    resultado_validacion: RemediationStatus
    modelo_usado: str
    file_path: str
    original_code: Optional[str] = None
    remediated_code: Optional[str] = None
    validation_details: Optional[ValidationResult] = None


class RemediationPlan(BaseModel):
    """
    Model representing the complete remediation plan for an application.

    The plan aggregates the results of all processed vulnerabilities,
    including remediation metrics and high-level observations.

    Attributes:
        application (str): The name of the application under remediation.
        plan_fecha (str): The date when the remediation plan was generated.
        vulnerabilidades_remediadas (List[RemediationResult]): A list of all
        remediated vulnerabilities.
        tasa_exito (str): The overall remediation success rate (percentage).
        observaciones (str): Summary observations or insights from the remediation process.
    """
    application: str
    plan_fecha: str
    vulnerabilidades_remediadas: List[RemediationResult]
    tasa_exito: str
    observaciones: str
