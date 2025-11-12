"""
Module for creating a secure code remediation agent.

This module defines the `create_code_remediator` function, which instantiates a CrewAI agent
that leverages a large language model (LLM) to generate secure code fixes based on
industry best practices and OWASP secure coding standards.
"""
# pylint: disable=R0801

import os
from typing import List
from crewai import Agent, LLM
from crewai.tools import BaseTool
from dotenv import load_dotenv

load_dotenv()


def create_code_remediator(tools: List[BaseTool]) -> Agent:
    """
    Creates and configures an agent specialized in secure code remediation.

    This agent uses a large language model (LLM) configured via environment variables
    to analyze vulnerable code and generate secure fixes following OWASP guidelines
    and secure software development best practices.

    Args:
        tools (List[BaseTool]): A list of tools (`BaseTool`) that the agent can use
            to perform supporting tasks during the code analysis or remediation process.

    Returns:
        Agent: A configured CrewAI Agent instance ready to perform
        secure code remediation tasks.
    """
    llm = LLM(
        model=os.getenv("OPENAI_MODEL_NAME", "gpt-4o"),
        api_key=os.getenv("OPENAI_API_KEY")
    )

    return Agent(
        role="Code Remediation Specialist",
        goal=(
            "Generate secure code fixes for identified vulnerabilities "
            "following best practices and secure coding standards"
        ),
        backstory=(
            "You are a senior software engineer with deep expertise in secure coding practices. "
            "You have mastered OWASP secure coding guidelines, understand common vulnerability "
            "patterns, and know how to refactor insecure code into secure, maintainable solutions. "
            "You always provide complete, working code fixes that preserve functionality while "
            "eliminating security risks."
        ),
        tools=tools,
        llm=llm,
        verbose=True,
        allow_delegation=False,
        memory=True,
    )
