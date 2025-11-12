"""
Task definition for validating security code remediations.

This module provides a factory function that builds a CrewAI `Task` instructing an
agent to evaluate whether a proposed code fix effectively mitigates a vulnerability
without introducing regressions or new security issues.
"""

from typing import Dict, Any
from crewai import Task, Agent


def create_validation_task(agent: Agent, vulnerability: Dict[str, Any],
                           original_code: str, remediated_code: str) -> Task:
    """
    Creates a task to validate the effectiveness of a code remediation.

    The task presents the agent with the original vulnerability context, the vulnerable
    code, and the remediated version, and requests a structured assessment using static
    analysis reasoning, regression checks, and risk evaluation. The agent must return a
    clear verdict (MITIGATED, PARTIALLY_MITIGATED, or NOT_MITIGATED) with supporting evidence.

    Args:
        agent (Agent): The CrewAI agent responsible for performing the validation.
        vulnerability (Dict[str, Any]): Metadata describing the vulnerability
            (e.g., type and description).
        original_code (str): The original, vulnerable source code.
        remediated_code (str): The proposed, remediated source code.

    Returns:
        Task: A configured CrewAI task for producing a validation report and verdict.
    """
    description = f"""
    Validate the following code remediation for security effectiveness:

    Vulnerability Type: {vulnerability['type']}
    Original Issue: {vulnerability['description']}

    Original Vulnerable Code:
    {original_code}

    Remediated Code:
    {remediated_code}

    Perform validation by:
    1. Using static analysis tools to scan the remediated code
    2. Comparing security posture before and after
    3. Checking for any new vulnerabilities introduced
    4. Verifying the fix addresses the root cause
    5. Confirming functionality is preserved

    Provide a clear validation verdict: MITIGATED, PARTIALLY_MITIGATED, or NOT_MITIGATED
    """

    expected_output = """A validation report containing:
    - Validation verdict (MITIGATED/PARTIALLY_MITIGATED/NOT_MITIGATED)
    - Static analysis results
    - Security improvements identified
    - Any remaining concerns or new issues
    - Recommendations for further improvements
    - Confidence level in the remediation"""

    return Task(
        description=description,
        expected_output=expected_output,
        agent=agent
    )
