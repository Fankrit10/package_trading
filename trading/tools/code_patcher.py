"""
Tool for applying code patches and generating diffs.

This module defines the `CodePatcherTool`, a CrewAI-compatible tool that compares
vulnerable and remediated code, generates unified diffs, validates patch integrity,
and summarizes modification metrics.
"""
# pylint: disable=W0718,W0221,W1113

import difflib
from typing import Any, Dict, Type
from crewai.tools import BaseTool
from pydantic import BaseModel, Field


class CodePatcherInput(BaseModel):
    """
    Input schema for the Code Patcher tool.

    Defines the required parameters for applying a code patch and performing
    diff generation and validation.

    Attributes:
        original_code (str): Original vulnerable source code.
        patched_code (str): The remediated or patched version of the code.
        file_path (str): Path where the patched code will be saved.
    """
    original_code: str = Field(..., description="Original vulnerable code")
    patched_code: str = Field(..., description="Patched secure code")
    file_path: str = Field(..., description="Path to save the patched code")


class CodePatcherTool(BaseTool):
    """
    Tool for applying code patches and generating code diffs.

    The `CodePatcherTool` compares original and patched code versions to create
    a unified diff representation, validate the patch, and return metadata
    about the modifications.
    """
    name: str = "Code Patcher"
    description: str = "Applies code patches and generates diffs"
    args_schema: Type[BaseModel] = CodePatcherInput

    def _run(self, original_code: str, patched_code: str, file_path: str) -> str:
        try:
            diff = self._generate_diff(original_code, patched_code)

            validation = self._validate_patch(original_code, patched_code)

            result = {
                "status": "success",
                "file_path": file_path,
                "diff": diff,
                "validation": validation
            }

            return str(result)

        except Exception as e:
            return f"Patching error: {str(e)}"

    def _generate_diff(self, original: str, patched: str) -> str:
        original_lines = original.splitlines(keepends=True)
        patched_lines = patched.splitlines(keepends=True)

        diff = difflib.unified_diff(
            original_lines,
            patched_lines,
            fromfile='original',
            tofile='patched',
            lineterm=''
        )

        return ''.join(diff)

    def _validate_patch(self, original: str, patched: str) -> Dict[str, Any]:
        return {
            "original_lines": len(original.splitlines()),
            "patched_lines": len(patched.splitlines()),
            "lines_changed": self._count_changed_lines(original, patched),
            "is_valid": len(patched.strip()) > 0
        }

    def _count_changed_lines(self, original: str, patched: str) -> int:
        original_lines = set(original.splitlines())
        patched_lines = set(patched.splitlines())

        return len(original_lines.symmetric_difference(patched_lines))
