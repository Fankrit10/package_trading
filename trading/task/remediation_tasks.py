"""
Task definition for generating secure code remediations.

This module provides a factory function that builds a CrewAI `Task` instructing an
agent to produce a complete, production-ready fix for a detected vulnerability,
preserving functionality while following secure coding best practices.
"""

from typing import Dict, Any
from crewai import Task, Agent


def create_remediation_task(agent: Agent, vulnerability: Dict[str, Any],
                            analysis_result: str, code: str) -> Task:
    """
    Creates a task to generate a complete, secure code remediation.

    The task supplies the agent with the vulnerability metadata, the prior analysis
    result, and the original vulnerable code, and requests a full replacement
    implementation that removes the vulnerability while maintaining functionality
    and adhering to Python secure coding practices.

    Args:
        agent (Agent): The CrewAI agent responsible for generating the remediation.
        vulnerability (Dict[str, Any]): Metadata describing the vulnerability
            (e.g., type, file path).
        analysis_result (str): The detailed analysis output produced in the previous step.
        code (str): The original vulnerable source code to be remediated.

    Returns:
        Task: A configured CrewAI task that instructs the agent to output complete,
        production-ready remediated code.
    """
    description = f"""
    Based on the following vulnerability analysis, generate a complete code remediation:

    Vulnerability: {vulnerability['type']}
    File: {vulnerability['file_path']}

    Analysis Result:
    {analysis_result}

    Original Vulnerable Code:
    {code}

    Generate a complete, secure version of this code that:
    1. Eliminates the vulnerability completely
    2. Maintains the original functionality
    3. Follows Python best practices
    4. Includes proper input validation and sanitization
    5. Uses secure libraries and methods
    6. Is production-ready

    Provide the COMPLETE remediated code, not just snippets.
    """

    expected_output = """Complete remediated Python code that:
    - Eliminates the identified vulnerability
    - Maintains original functionality
    - Follows secure coding practices
    - Includes proper error handling
    - Is fully functional and production-ready

    Format: Provide the complete Python code without markdown formatting."""

    return Task(
        description=description,
        expected_output=expected_output,
        agent=agent
    )
