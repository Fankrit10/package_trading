"""
Tool for performing static security analysis on Python code.

This module defines the `StaticAnalyzerTool`, a CrewAI-compatible tool that
leverages Bandit to detect security vulnerabilities in Python code. It executes
static analysis, parses the results, and formats them into a readable summary.
"""
# pylint: disable=W0718,W0221,W1113

import json
import os
import subprocess  # nosec  B404
import tempfile

from typing import Any, Dict, Type

from pydantic import BaseModel, Field
from crewai.tools import BaseTool


class StaticAnalyzerInput(BaseModel):
    """
    Input schema for the Static Code Analyzer tool.

    Defines the parameters required for performing static analysis
    on a given piece of Python code.

    Attributes:
        code (str): The Python source code to analyze.
        file_path (str): Optional original file path for contextual reporting.
    """
    code: str = Field(..., description="Python code to analyze")
    file_path: str = Field(default="", description="Original file path for context")


class StaticAnalyzerTool(BaseTool):
    """
    Tool for analyzing Python code using static analysis (Bandit).

    The `StaticAnalyzerTool` executes Bandit to scan Python code for
    common security vulnerabilities, parses the JSON results, and
    returns a formatted report highlighting detected issues.
    """
    name: str = "Static Code Analyzer"
    description: str = "Analyzes Python code for security vulnerabilities using Bandit"
    args_schema: Type[BaseModel] = StaticAnalyzerInput

    def _run(self, code: str, file_path: str = "", *args, **kwargs) -> str:
        """
        Executes Bandit to analyze the provided Python code.

        Args:
            code (str): Python source code to analyze.
            file_path (str): Optional file path for context.
            *args: Additional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            str: A formatted string summarizing the detected vulnerabilities.
        """
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp_file:
                tmp_file.write(code)
                tmp_file_path = tmp_file.name

            result = subprocess.run(  # nosec
                ['bandit', '-r', tmp_file_path, '-f', 'json'],
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )

            os.unlink(tmp_file_path)

            if result.stdout:
                analysis = json.loads(result.stdout)
                return self._format_analysis(analysis, file_path)
            return "No vulnerabilities found"

        except subprocess.TimeoutExpired:
            return "Analysis timeout"
        except json.JSONDecodeError:
            return f"Error parsing analysis results: {result.stdout}"
        except Exception as e:
            return f"Analysis error: {str(e)}"

    def _format_analysis(self, analysis: Dict[str, Any], file_path: str) -> str:
        """
        Formats the Bandit analysis results into a readable report.

        Args:
            analysis (Dict[str, Any]): JSON analysis output from Bandit.
            file_path (str): File path context for reporting.

        Returns:
            str: Formatted report of detected security issues.
        """
        results = analysis.get('results', [])

        if not results:
            return "No security issues detected"

        formatted = f"Security Analysis for {file_path or 'provided code'}:\n\n"

        for issue in results:
            formatted += f"Issue: {issue.get('issue_text', 'Unknown')}\n"
            formatted += f"Severity: {issue.get('issue_severity', 'Unknown')}\n"
            formatted += f"Confidence: {issue.get('issue_confidence', 'Unknown')}\n"
            formatted += f"Line: {issue.get('line_number', 'Unknown')}\n"
            formatted += f"CWE: {issue.get('issue_cwe', {}).get('id', 'Unknown')}\n"
            formatted += "-" * 50 + "\n"

        return formatted
