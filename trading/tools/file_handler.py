"""
Tool for handling basic file operations.

This module defines the `FileHandlerTool`, a CrewAI-compatible utility that
enables reading and writing files from the local filesystem in a secure
and consistent manner.
"""
# pylint: disable=W0718,W0221,W1113

import os
from typing import Type
from crewai.tools import BaseTool
from pydantic import BaseModel, Field


class FileHandlerInput(BaseModel):
    """
    Input schema for the File Handler tool.

    Defines the parameters required to read from or write to a file.

    Attributes:
        file_path (str): Path to the file that will be read or written.
        content (str): Content to write into the file (used only for write operations).
        operation (str): The operation type — either 'read' or 'write'.
    """
    file_path: str = Field(..., description="Path to the file to read or write")
    content: str = Field(default="", description="Content to write to file")
    operation: str = Field(..., description="Operation: 'read' or 'write'")


class FileHandlerTool(BaseTool):
    """
    Tool for performing read and write operations on the filesystem.

    The `FileHandlerTool` allows agents to interact with files safely by
    abstracting reading and writing functionality. It ensures that file
    directories are created when writing new files and validates operation types.
    """
    name: str = "File Handler"
    description: str = "Reads and writes files from the filesystem"
    args_schema: Type[BaseModel] = FileHandlerInput

    def _run(self, file_path: str, content: str = "", operation: str = "read") -> str:
        try:
            if operation == "read":
                return self._read_file(file_path)

            if operation == "write":
                return self._write_file(file_path, content)

            return f"Invalid operation: {operation}"

        except Exception as e:
            return f"Error in file operation: {str(e)}"

    def _read_file(self, file_path: str) -> str:
        if not os.path.exists(file_path):
            return f"File not found: {file_path}"

        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()

    def _write_file(self, file_path: str, content: str) -> str:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

        return f"File written successfully: {file_path}"
