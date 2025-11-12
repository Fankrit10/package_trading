"""
Module for creating a code scanner agent.

This agent performs static code analysis on files to extract patterns,
dependencies, and potential security risks.
"""
# pylint: disable=R0801

import os
from typing import List
from crewai import Agent, LLM
from crewai.tools import BaseTool
from dotenv import load_dotenv

load_dotenv()


def create_code_scanner(tools: List[BaseTool]) -> Agent:
    """
    Creates and configures an agent specialized in static code analysis.

    This agent examines source code structure, patterns, and dependencies
    to identify potential security risks and vulnerable patterns.

    Args:
        tools (List[BaseTool]): A list of tools for code analysis.

    Returns:
        Agent: A configured CrewAI Agent instance for code scanning.
    """
    llm = LLM(
        model=os.getenv("OPENAI_MODEL_NAME", "gpt-4o"),
        api_key=os.getenv("OPENAI_API_KEY")
    )

    return Agent(
        role="Code Scanner Specialist",
        goal=(
            "Perform static analysis on source code to identify architectural "
            "vulnerabilities, insecure patterns, and potential attack surfaces"
        ),
        backstory=(
            "You are an experienced software security analyst with expertise in "
            "static code analysis and architectural security patterns. "
            "You can quickly assess code quality, identify design flaws, "
            "and spot security misconfigurations. "
            "You understand multiple programming paradigms and frameworks."
        ),
        tools=tools,
        llm=llm,
        verbose=True,
        allow_delegation=False,
        memory=True,
    )
