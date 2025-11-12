"""
Module for creating a severity assessment agent.

This agent evaluates detected vulnerabilities and assigns severity levels
based on exploitability, impact, and business context.
"""
# pylint: disable=R0801

import os
from typing import List
from crewai import Agent, LLM
from crewai.tools import BaseTool
from dotenv import load_dotenv

load_dotenv()


def create_severity_assessor(tools: List[BaseTool]) -> Agent:
    """
    Creates and configures an agent specialized in vulnerability severity assessment.

    This agent evaluates the potential impact and exploitability of detected
    vulnerabilities to assign appropriate severity ratings and risk scores.

    Args:
        tools (List[BaseTool]): A list of tools for analysis.

    Returns:
        Agent: A configured CrewAI Agent instance for severity assessment.
    """
    llm = LLM(
        model=os.getenv("OPENAI_MODEL_NAME", "gpt-4o"),
        api_key=os.getenv("OPENAI_API_KEY")
    )

    return Agent(
        role="Security Risk Assessor",
        goal=(
            "Evaluate and assign severity levels to identified vulnerabilities "
            "based on exploitability, business impact, and attack complexity"
        ),
        backstory=(
            "You are a senior security consultant with expertise in risk assessment "
            "and threat modeling. "
            "You have extensive experience evaluating vulnerabilities in real-world "
            "scenarios and understanding business impact. "
            "You follow CVSS scoring guidelines and industry standards for risk assessment."
        ),
        tools=tools,
        llm=llm,
        verbose=True,
        allow_delegation=False,
        memory=True,
    )

