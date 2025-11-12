"""
Module for orchestrating multi-agent security remediation workflows.

This module defines the `SecurityRemediationCrew` class, which coordinates multiple
CrewAI agents to analyze, remediate, and validate security vulnerabilities in code.
It integrates automated analysis, patch generation, and validation to produce a
comprehensive remediation plan.
"""
# pylint: disable=R0903,W0212

import json
from typing import Dict, Any, List
from datetime import datetime
from crewai import Crew, Process

from trading.agents.code_remediator import create_code_remediator
from trading.agents.security_analyst import create_security_analyst
from trading.agents.validator import create_validator
from trading.task.analysis_tasks import create_analysis_task
from trading.task.remediation_tasks import create_remediation_task
from trading.task.validation_tasks import create_validation_task
from trading.tools.file_handler import FileHandlerTool
from trading.tools.code_patcher import CodePatcherTool
from trading.tools.static_analyzer import StaticAnalyzerTool
from trading.schemas.remediation import RemediationPlan, RemediationResult, RemediationStatus
from trading.schemas.vulnerability import VulnerabilityReport


class SecurityRemediationCrew:
    """
    Coordinates the end-to-end vulnerability remediation process.

    The `SecurityRemediationCrew` class manages three specialized agents:
    - A security analyst for vulnerability assessment.
    - A code remediator for generating secure fixes.
    - A validation engineer for verifying remediation effectiveness.

    Together, these agents perform a sequential, automated workflow
    that analyzes vulnerabilities, applies remediations, and validates results.
    """

    def __init__(self):
        self.file_handler = FileHandlerTool()
        self.static_analyzer = StaticAnalyzerTool()
        self.code_patcher = CodePatcherTool()

        self.analyst = create_security_analyst([self.file_handler])
        self.remediator = create_code_remediator([self.file_handler, self.static_analyzer])
        self.validator = create_validator([self.static_analyzer, self.code_patcher])

    def process_vulnerability_report(self, report_path: str,
                                     output_path: str) -> Dict[str, Any]:
        """
        Processes a vulnerability report and generates a complete remediation plan.

        The method reads a vulnerability report, iterates through each vulnerability,
        and applies the full analysis–remediation–validation workflow. The final
        results are compiled into a structured remediation plan and saved to disk.

        Args:
            report_path (str): Path to the input vulnerability report JSON file.
            output_path (str): Path where the generated remediation plan will be saved.

        Returns:
            Dict[str, Any]: A dictionary representation of the completed remediation plan.
        """
        report_content = self.file_handler._run(
            file_path=report_path,
            operation="read"
        )

        report_data = json.loads(report_content)
        vulnerability_report = VulnerabilityReport(**report_data)

        remediation_results = []

        for vuln in vulnerability_report.vulnerabilities:
            print(f"\n{'='*80}")
            print(f"Processing: {vuln.id} - {vuln.type}")
            print(f"{'='*80}\n")

            result = self._process_single_vulnerability(vuln)
            remediation_results.append(result)

        plan = self._generate_remediation_plan(
            vulnerability_report.application,
            remediation_results
        )

        self._save_remediation_plan(plan, output_path)

        return plan.dict()

    def _process_single_vulnerability(self, vulnerability: Any) -> RemediationResult:
        vulnerable_code = self.file_handler._run(
            file_path=vulnerability.file_path,
            operation="read"
        )

        analysis_task = create_analysis_task(
            self.analyst,
            vulnerability.dict(),
            vulnerable_code
        )

        analysis_crew = Crew(
            agents=[self.analyst],
            tasks=[analysis_task],
            process=Process.sequential,
            verbose=True
        )

        analysis_result = analysis_crew.kickoff()

        remediation_task = create_remediation_task(
            self.remediator,
            vulnerability.dict(),
            str(analysis_result),
            vulnerable_code
        )

        remediation_crew = Crew(
            agents=[self.remediator],
            tasks=[remediation_task],
            process=Process.sequential,
            verbose=True
        )

        remediation_result = remediation_crew.kickoff()
        remediated_code = str(remediation_result)

        validation_task = create_validation_task(
            self.validator,
            vulnerability.dict(),
            vulnerable_code,
            remediated_code
        )

        validation_crew = Crew(
            agents=[self.validator],
            tasks=[validation_task],
            process=Process.sequential,
            verbose=True
        )

        validation_result = validation_crew.kickoff()

        status = self._determine_status(str(validation_result))

        output_file_path = (
            f"outputs/remediated_code/"
            f"{vulnerability.id}_{vulnerability.type.replace(' ', '_')}.py"
        )

        self.file_handler._run(
            file_path=output_file_path,
            content=remediated_code,
            operation="write"
        )

        return RemediationResult(
            id=vulnerability.id,
            tipo=vulnerability.type.value,
            accion=self._extract_action(str(analysis_result)),
            codigo_sugerido=remediated_code[:200] + "...",
            resultado_validacion=status,
            modelo_usado="GPT-4",
            file_path=output_file_path,
            original_code=vulnerable_code,
            remediated_code=remediated_code
        )

    def _determine_status(self, validation_result: str) -> RemediationStatus:
        result_lower = validation_result.lower()

        if "mitigated" in result_lower and "not" not in result_lower:
            if "partially" in result_lower:
                return RemediationStatus.PARTIALLY_MITIGATED
            return RemediationStatus.MITIGATED

        if "not mitigated" in result_lower or "not_mitigated" in result_lower:
            return RemediationStatus.NOT_MITIGATED

        return RemediationStatus.PARTIALLY_MITIGATED

    def _extract_action(self, analysis: str) -> str:
        lines = analysis.split('\n')
        for line in lines:
            if 'remediation' in line.lower() or 'fix' in line.lower() or 'solution' in line.lower():
                return line.strip()
        return "Implement secure coding practices to eliminate the vulnerability"

    def _generate_remediation_plan(self, application: str,
                                   results: List[RemediationResult]) -> RemediationPlan:
        total = len(results)
        mitigated = sum(1 for r in results if r.resultado_validacion == RemediationStatus.MITIGATED)
        partially = sum(
            1
            for r in results
            if r.resultado_validacion == RemediationStatus.PARTIALLY_MITIGATED
        )

        success_rate = ((mitigated + (partially * 0.5)) / total * 100) if total > 0 else 0

        observations = f"Processed {total} vulnerabilities. "
        observations += f"{mitigated} fully mitigated, {partially} partially mitigated. "
        observations += "Multi-agent approach provided comprehensive analysis and validation."

        return RemediationPlan(
            application=application,
            plan_fecha=datetime.now().strftime("%Y-%m-%d"),
            vulnerabilidades_remediadas=results,
            tasa_exito=f"{success_rate:.1f}%",
            observaciones=observations
        )

    def _save_remediation_plan(self, plan: RemediationPlan, output_path: str):
        plan_json = json.dumps(plan.dict(), indent=2, ensure_ascii=False)

        self.file_handler._run(
            file_path=output_path,
            content=plan_json,
            operation="write"
        )
