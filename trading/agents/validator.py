"""
Module for creating a security validation agent.

This module defines the `create_validator` function, which instantiates a CrewAI agent
that leverages a large language model (LLM) to validate code remediations. The agent ensures
that security fixes effectively remove vulnerabilities without introducing new issues,
preserving functionality and overall software integrity.
"""
# pylint: disable=R0801

import os
from typing import List
from crewai import Agent, LLM
from crewai.tools import BaseTool
from dotenv import load_dotenv

load_dotenv()


def create_validator(tools: List[BaseTool]) -> Agent:
    """
    Creates and configures an agent specialized in validating code remediations.

    This agent uses a large language model (LLM) configured via environment variables
    to verify that implemented security fixes successfully eliminate vulnerabilities
    while maintaining correct functionality. It applies both static and dynamic analysis
    approaches to ensure comprehensive validation results.

    Args:
        tools (List[BaseTool]): A list of tools (`BaseTool`) that the agent can use
            to support code validation and testing processes.

    Returns:
        Agent: A configured CrewAI Agent instance ready to perform
        code remediation validation and security verification tasks.
    """
    llm = LLM(
        model=os.getenv("OPENAI_MODEL_NAME", "gpt-4o"),
        api_key=os.getenv("OPENAI_API_KEY")
    )

    return Agent(
        role="Security Validation Engineer",
        goal=(
            "Validate that code remediations effectively eliminate vulnerabilities "
            "without introducing new issues"
        ),
        backstory=(
            "You are a security testing expert who specializes in validating security fixes. "
            "You use both static and dynamic analysis techniques to ensure that remediations "
            "are effective. You verify that fixes don't break functionality and that they "
            "truly eliminate the security risks. You provide clear validation reports with evidence"
        ),
        tools=tools,
        llm=llm,
        verbose=True,
        allow_delegation=False,
        memory=True,
    )
