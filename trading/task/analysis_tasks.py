"""
Task definition for vulnerability analysis within the security remediation workflow.

This module defines the function used to create a CrewAI `Task` that performs
a detailed security analysis of a detected vulnerability, providing context,
impact, and remediation requirements.
"""

from typing import Dict, Any
from crewai import Task, Agent


def create_analysis_task(agent: Agent, vulnerability: Dict[str, Any], code: str) -> Task:
    """
    Creates a task for performing detailed vulnerability analysis.

    This function builds a CrewAI `Task` that instructs an agent to analyze
    a specific vulnerability in source code. The task includes contextual
    details about the vulnerability (such as type, severity, and CWE/OWASP mappings)
    and expects a structured report covering causes, impact, and remediation needs.

    Args:
        agent (Agent): The CrewAI agent responsible for executing the analysis.
        vulnerability (Dict[str, Any]): A dictionary containing vulnerability metadata.
        code (str): The source code segment where the vulnerability was found.

    Returns:
        Task: A configured CrewAI task for performing comprehensive vulnerability analysis.
    """
    description = f"""
    Analyze the following security vulnerability in detail:

    Vulnerability ID: {vulnerability['id']}
    Type: {vulnerability['type']}
    Severity: {vulnerability['severity']}
    File: {vulnerability['file_path']}
    Line: {vulnerability['line_number']}
    Description: {vulnerability['description']}
    CWE: {vulnerability.get('cwe_id', 'N/A')}
    OWASP Category: {vulnerability.get('owasp_category', 'N/A')}

    Vulnerable Code:
    {code}

    Provide a comprehensive analysis including:
    1. Root cause of the vulnerability
    2. Potential attack vectors
    3. Impact assessment
    4. OWASP/CWE context
    5. Prerequisites for remediation
    """

    expected_output = """A detailed security analysis report containing:
    - Root cause explanation
    - Attack vector analysis
    - Impact assessment (confidentiality, integrity, availability)
    - Compliance mapping (OWASP, CWE)
    - Remediation requirements"""

    return Task(
        description=description,
        expected_output=expected_output,
        agent=agent
    )
