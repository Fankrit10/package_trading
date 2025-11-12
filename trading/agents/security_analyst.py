"""
Module for creating a security vulnerability analysis agent.

This module defines the `create_security_analyst` function,
which instantiates a CrewAI agent
that leverages a large language model (LLM) to analyze code for
potential security vulnerabilities,
evaluate their risk and impact, and provide detailed assessments
aligned with OWASP and CWE standards.
"""
# pylint: disable=R0801

import os
from typing import List
from crewai import Agent, LLM
from crewai.tools import BaseTool
from dotenv import load_dotenv

load_dotenv()


def create_security_analyst(tools: List[BaseTool]) -> Agent:
    """
    Creates and configures an agent specialized in security vulnerability analysis.

    This agent uses a large language model (LLM) configured via environment variables
    to identify, assess, and describe security vulnerabilities in code. It follows
    OWASP and CWE guidelines to ensure accurate, standards-based vulnerability reporting.

    Args:
        tools (List[BaseTool]): A list of tools (`BaseTool`) that the agent can use
            to assist in the process of vulnerability detection and analysis.

    Returns:
        Agent: A configured CrewAI Agent instance ready to perform
        code security analysis and vulnerability assessments.
    """
    llm = LLM(
        model=os.getenv("OPENAI_MODEL_NAME", "gpt-4o"),
        api_key=os.getenv("OPENAI_API_KEY")
    )

    return Agent(
        role="Security Vulnerability Analyst",
        goal=(
            "Analyze security vulnerabilities in code and provide detailed "
            "assessment of risks and impacts"
        ),
        backstory=(
            "You are an expert security researcher with 15 years of experience "
            "in application security. "
            "You specialize in identifying and analyzing vulnerabilities "
            "following OWASP guidelines and CWE classifications. "
            "You understand the business impact of security issues "
            "and can explain technical concepts clearly."
        ),
        tools=tools,
        llm=llm,
        verbose=True,
        allow_delegation=False,
        memory=True,
    )
