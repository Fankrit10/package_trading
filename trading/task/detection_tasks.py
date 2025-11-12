"""
Task definitions for vulnerability detection workflow.

This module defines CrewAI tasks for scanning files, detecting vulnerabilities,
and assessing their severity.
"""

from typing import Dict, Any, List
from crewai import Task, Agent


def create_file_scan_task(agent: Agent, file_path: str, file_content: str) -> Task:
    """
    Creates a task for scanning a file for vulnerabilities.

    Args:
        agent (Agent): The agent responsible for executing the scan.
        file_path (str): Path to the file being scanned.
        file_content (str): The content of the file to scan.

    Returns:
        Task: A configured task for file vulnerability scanning.
    """
    description = f"""
    Analyze the following source code file for security vulnerabilities.
    File Path: {file_path}
    Source Code:
    ```
    {file_content[:5000]}
    ```
    Identify and list:
    1. All potential security vulnerabilities (SQL Injection, XSS, Command Injection, etc.)
    2. The vulnerable code snippet and line numbers (if identifiable)
    3. Type of vulnerability
    4. Potential attack vectors
    5. Initial severity assessment (Critical/High/Medium/Low/Info)
    Format your response as a structured list with clear vulnerability entries.
    """

    return Task(
        description=description,
        expected_output="A detailed list of identified vulnerabilities with type, location, and severity",
        agent=agent,
        verbose=True
    )


def create_code_pattern_analysis_task(agent: Agent, file_path: str, file_content: str) -> Task:
    """
    Creates a task for analyzing code patterns and security configurations.

    Args:
        agent (Agent): The agent responsible for analysis.
        file_path (str): Path to the file being analyzed.
        file_content (str): The content of the file.

    Returns:
        Task: A configured task for code pattern analysis.
    """
    description = f"""
    Perform static code analysis on the following file to identify architectural
    security issues and vulnerable patterns.    
    File Path: {file_path}    
    Source Code:
    ```
    {file_content[:5000]}
    ```
    
    Analyze:
    1. Input validation and sanitization practices
    2. Authentication and authorization mechanisms
    3. Data exposure risks and sensitive information handling
    4. Dependency vulnerabilities (if identifiable)
    5. API security practices
    6. Configuration security issues
    7. Error handling and logging practices    
    Provide specific observations about security posture and recommendations.
    """

    return Task(
        description=description,
        expected_output="Analysis of code patterns, security practices, and identified risks",
        agent=agent,
        verbose=True
    )


def create_severity_assessment_task(
    agent: Agent,
    vulnerabilities: List[Dict[str, Any]],
    file_path: str
) -> Task:
    """
    Creates a task for assessing vulnerability severity.

    Args:
        agent (Agent): The agent responsible for severity assessment.
        vulnerabilities (List[Dict[str, Any]]): List of detected vulnerabilities.
        file_path (str): Path of the analyzed file.

    Returns:
        Task: A configured task for severity assessment.
    """
    vuln_str = "\n".join([
        f"- {v.get('type', 'Unknown')}: {v.get('description', 'No description')}"
        for v in vulnerabilities
    ])

    description = f"""
    Assess the severity of the following vulnerabilities detected in {file_path}:    
    {vuln_str}
    For each vulnerability, provide:
    1. CVSS-based severity score (Critical/High/Medium/Low/Info)
    2. Exploitability assessment (Difficult/Moderate/Easy)
    3. Business impact analysis
    4. Attack complexity
    5. Required privileges
    6. Affected asset scope    
    Use industry-standard CVSS metrics and provide justification for each rating.
    """

    return Task(
        description=description,
        expected_output="Comprehensive severity assessment with CVSS "
                        "scores and business impact analysis",
        agent=agent,
        verbose=True
    )
