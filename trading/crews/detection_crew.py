"""
Module for orchestrating vulnerability detection workflow.

This module defines the `VulnerabilityDetectionCrew` class, which coordinates
multiple CrewAI agents to scan code files, identify vulnerabilities, and
generate comprehensive security reports.
"""
# pylint: disable=R0903,W0212

import json
from typing import Dict, Any, List
from pathlib import Path
from crewai import Crew, Process

from trading.agents.vulnerability_detector import create_vulnerability_detector
from trading.agents.code_scanner import create_code_scanner
from trading.agents.severity_assessor import create_severity_assessor
from trading.task.detection_tasks import (
    create_file_scan_task,
    create_code_pattern_analysis_task,
    create_severity_assessment_task
)
from trading.tools.file_handler import FileHandlerTool
from trading.tools.static_analyzer import StaticAnalyzerTool
from trading.schemas.detection import (
    DetectionReport, FileAnalysisResult, DetectedVulnerability, VulnSeverity
)


class VulnerabilityDetectionCrew:
    """
    Coordinates the vulnerability detection and analysis process.

    The `VulnerabilityDetectionCrew` manages three specialized agents:
    - A vulnerability detector for identifying security issues.
    - A code scanner for static analysis.
    - A severity assessor for risk evaluation.

    Together, these agents perform automated scanning of source code files
    and generate comprehensive security reports.
    """

    def __init__(self, progress_callback=None):
        """
        Initialize the detection crew.

        Args:
            progress_callback: Optional callback function for progress updates.
        """
        self.file_handler = FileHandlerTool()
        self.static_analyzer = StaticAnalyzerTool()
        self.progress_callback = progress_callback

        self.detector = create_vulnerability_detector([self.file_handler, self.static_analyzer])
        self.scanner = create_code_scanner([self.file_handler, self.static_analyzer])
        self.assessor = create_severity_assessor([self.static_analyzer])

    def _update_progress(self, message: str, current: int = None, total: int = None):
        """Update progress if callback is provided."""
        if self.progress_callback:
            self.progress_callback(message, current, total)

    def scan_directory(self, directory_path: str, output_path: str,
                      file_extensions: List[str] = None) -> Dict[str, Any]:
        """
        Recursively scan a directory for vulnerabilities.

        Args:
            directory_path (str): Path to the directory to scan.
            output_path (str): Path where the report will be saved.
            file_extensions (List[str]): List of file extensions to scan.

        Returns:
            Dict[str, Any]: The detection report as a dictionary.
        """
        if file_extensions is None:
            file_extensions = ['.ts', '.js', '.py', '.java', '.cs', '.go']

        self._update_progress("🔍 Inicializando escaneo...")

        if not Path(directory_path).exists():
            self._update_progress(f"❌ Directorio no encontrado: {directory_path}", 0, 1)
            raise ValueError(f"Directory not found: {directory_path}")

        self._update_progress(f"📂 Buscando archivos en {directory_path}...")
        files_to_scan = self._find_files(directory_path, file_extensions)

        if not files_to_scan:
            self._update_progress("⚠️ No se encontraron archivos para escanear", 0, 1)
            return self._generate_empty_report(directory_path)

        max_files = 1
        files_to_scan_limited = files_to_scan[:max_files]

        self._update_progress(
            f"📊 Encontrados {len(files_to_scan)} archivos. "
            f"Analizando primeros {len(files_to_scan_limited)} para optimizar costos..."
        )

        file_results = []
        total_files = len(files_to_scan_limited)

        for idx, file_path in enumerate(files_to_scan_limited, 1):
            try:
                self._update_progress(f"📄 Analizando: {file_path}", idx, total_files)
                result = self._analyze_file(file_path)
                if result:
                    file_results.append(result)
            except Exception as e:
                self._update_progress(f"⚠️ Error analizando {file_path}: {str(e)}")
                continue

        self._update_progress("📋 Generando reporte final...")
        report = self._generate_detection_report(directory_path, file_results)

        self._update_progress("💾 Guardando reporte...")
        self._save_report(report, output_path)

        self._update_progress("✅ Escaneo completado exitosamente!")

        return report.dict()

    def _find_files(self, directory: str, extensions: List[str]) -> List[str]:
        """Find all files with specified extensions in directory."""
        files = []
        for ext in extensions:
            pattern = f"**/*{ext}"
            files.extend([str(p) for p in Path(directory).glob(pattern) if p.is_file()])
        return sorted(list(set(files)))

    def _analyze_file(self, file_path: str) -> FileAnalysisResult:
        """Analyze a single file for vulnerabilities."""
        try:
            file_content = self.file_handler._run(
                file_path=file_path,
                operation="read"
            )
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return None

        if not file_content:
            return None

        try:
            # Create and execute scan task
            scan_task = create_file_scan_task(self.detector, file_path, file_content)
            scan_crew = Crew(
                agents=[self.detector],
                tasks=[scan_task],
                process=Process.sequential,
                verbose=False
            )
            scan_result = scan_crew.kickoff()

            # Create and execute pattern analysis task
            pattern_task = create_code_pattern_analysis_task(self.scanner, file_path, file_content)
            pattern_crew = Crew(
                agents=[self.scanner],
                tasks=[pattern_task],
                process=Process.sequential,
                verbose=False
            )
            pattern_result = pattern_crew.kickoff()

            # Parse vulnerabilities from scan result
            vulnerabilities = self._parse_vulnerabilities(str(scan_result), file_path)

            # Create and execute severity assessment task
            if vulnerabilities:
                severity_task = create_severity_assessment_task(
                    self.assessor,
                    [v.dict() for v in vulnerabilities],
                    file_path
                )
                severity_crew = Crew(
                    agents=[self.assessor],
                    tasks=[severity_task],
                    process=Process.sequential,
                    verbose=False
                )
                severity_result = severity_crew.kickoff()

                # Update vulnerabilities with severity information
                vulnerabilities = self._update_vulnerabilities_with_severity(
                    vulnerabilities,
                    str(severity_result)
                )

            risk_score = self._calculate_risk_score(vulnerabilities)

            return FileAnalysisResult(
                file_path=file_path,
                file_type=Path(file_path).suffix,
                total_vulnerabilities=len(vulnerabilities),
                vulnerabilities=vulnerabilities,
                code_patterns_analysis=str(pattern_result),
                risk_score=risk_score,
                analysis_status="completed"
            )

        except Exception as e:
            print(f"Error analyzing file {file_path}: {e}")
            return None

    def _parse_vulnerabilities(self, scan_result: str, file_path: str) -> List[DetectedVulnerability]:
        """Parse vulnerabilities from scan result."""
        vulnerabilities = []

        # Enhanced vulnerability detection with specific patterns
        lines = scan_result.split('\n')
        vuln_counter = 0

        # Specific vulnerability patterns
        for i, line in enumerate(lines):
            line_lower = line.lower()
            detected_type = None
            detected_severity = VulnSeverity.MEDIUM
            cwe = None
            owasp = None
            code_snippet = line.strip()

            # Command Injection patterns
            if any(keyword in line_lower for keyword in ['os.system', 'subprocess.call', 'subprocess.popen', 'shell=true', 'command injection', 'os.popen']):
                detected_type = "Command Injection"
                detected_severity = VulnSeverity.CRITICAL if 'shell=true' in line_lower or 'os.system' in line_lower else VulnSeverity.HIGH
                cwe = "CWE-78"
                owasp = "A03:2021 – Injection"
                code_snippet = line.strip()

            # SQL Injection patterns
            elif any(keyword in line_lower for keyword in ['sql injection', 'select * from', 'insert into', 'update ', 'delete from']):
                detected_type = "SQL Injection"
                detected_severity = VulnSeverity.CRITICAL
                cwe = "CWE-89"
                owasp = "A03:2021 – Injection"
                code_snippet = line.strip()

            # XSS patterns
            elif any(keyword in line_lower for keyword in ['xss', 'cross-site scripting', 'innerhtml', '<script', 'dangerouslysetinnerhtml']):
                detected_type = "Cross-Site Scripting"
                detected_severity = VulnSeverity.HIGH
                cwe = "CWE-79"
                owasp = "A07:2021 – Cross-Site Scripting (XSS)"
                code_snippet = line.strip()

            # Path Traversal patterns
            elif any(keyword in line_lower for keyword in ['path traversal', '../', '..\\', 'directory traversal']):
                detected_type = "Path Traversal"
                detected_severity = VulnSeverity.HIGH
                cwe = "CWE-22"
                owasp = "A01:2021 – Broken Access Control"
                code_snippet = line.strip()

            # Hardcoded Credentials
            elif any(keyword in line_lower for keyword in ['password =', 'api_key =', 'secret =', 'token =', 'credentials =']):
                detected_type = "Hardcoded Credentials"
                detected_severity = VulnSeverity.HIGH
                cwe = "CWE-798"
                owasp = "A02:2021 – Cryptographic Failures"
                code_snippet = line.strip()

            # Insecure Deserialization
            elif any(keyword in line_lower for keyword in ['pickle', 'deserialization', 'untrusted data']):
                detected_type = "Insecure Deserialization"
                detected_severity = VulnSeverity.HIGH
                cwe = "CWE-502"
                owasp = "A08:2021 – Software and Data Integrity Failures"
                code_snippet = line.strip()

            # Weak Authentication
            elif any(keyword in line_lower for keyword in ['weak password', 'no authentication', 'missing auth', 'hardcoded password']):
                detected_type = "Broken Authentication"
                detected_severity = VulnSeverity.HIGH
                cwe = "CWE-287"
                owasp = "A07:2021 – Identification and Authentication Failures"
                code_snippet = line.strip()

            if detected_type:
                vuln_counter += 1
                vuln = DetectedVulnerability(
                    vulnerability_id=f"{Path(file_path).stem}_{vuln_counter}",
                    file_path=file_path,
                    vuln_type=detected_type,
                    severity=detected_severity,
                    code_snippet=code_snippet,
                    description=f"{detected_type} en línea {i+1}: {code_snippet[:80]}",
                    line_number=i+1,
                    cwe_id=cwe,
                    owasp_category=owasp,
                    exploitability="Easy" if detected_severity == VulnSeverity.CRITICAL else "Moderate",
                    business_impact="Ejecución de código arbitrario" if detected_severity == VulnSeverity.CRITICAL else "Riesgo de seguridad"
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

        return vulnerabilities

    def _update_vulnerabilities_with_severity(self, vulnerabilities: List[DetectedVulnerability],
                                             severity_result: str) -> List[DetectedVulnerability]:
        """Update vulnerability severity based on assessment."""
        # Parse severity result and update vulnerabilities
        result_lower = severity_result.lower()

        for vuln in vulnerabilities:
            if "critical" in result_lower:
                vuln.severity = VulnSeverity.CRITICAL
            elif "high" in result_lower:
                vuln.severity = VulnSeverity.HIGH
            elif "medium" in result_lower:
                vuln.severity = VulnSeverity.MEDIUM
            elif "low" in result_lower:
                vuln.severity = VulnSeverity.LOW

        return vulnerabilities

    def _calculate_risk_score(self, vulnerabilities: List[DetectedVulnerability]) -> float:
        """Calculate overall risk score for a file."""
        if not vulnerabilities:
            return 0.0

        severity_weights = {
            VulnSeverity.CRITICAL: 10,
            VulnSeverity.HIGH: 8,
            VulnSeverity.MEDIUM: 5,
            VulnSeverity.LOW: 2,
            VulnSeverity.INFO: 1
        }

        total_score = sum(
            severity_weights.get(v.severity, 0)
            for v in vulnerabilities
        )

        # Normalize to 0-10 scale
        max_possible = len(vulnerabilities) * 10
        score = min(10.0, (total_score / max_possible) * 10) if max_possible > 0 else 0.0

        return round(score, 2)

    def _generate_detection_report(self, project_path: str,
                                  file_results: List[FileAnalysisResult]) -> DetectionReport:
        """Generate comprehensive detection report."""
        total_vulns = sum(f.total_vulnerabilities for f in file_results)
        files_with_vulns = sum(1 for f in file_results if f.total_vulnerabilities > 0)

        severity_counts = {
            VulnSeverity.CRITICAL: 0,
            VulnSeverity.HIGH: 0,
            VulnSeverity.MEDIUM: 0,
            VulnSeverity.LOW: 0,
            VulnSeverity.INFO: 0
        }

        for file_result in file_results:
            for vuln in file_result.vulnerabilities:
                severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1

        overall_risk = sum(
            f.risk_score for f in file_results
        ) / len(file_results) if file_results else 0.0

        summary = (
            f"Análisis de seguridad completado: "
            f"{total_vulns} vulnerabilidades encontradas en {files_with_vulns} archivos. "
            f"Críticas: {severity_counts[VulnSeverity.CRITICAL]}, "
            f"Altas: {severity_counts[VulnSeverity.HIGH]}"
        )

        return DetectionReport(
            project_path=project_path,
            total_files_scanned=len(file_results),
            files_with_vulnerabilities=files_with_vulns,
            total_vulnerabilities=total_vulns,
            critical_count=severity_counts[VulnSeverity.CRITICAL],
            high_count=severity_counts[VulnSeverity.HIGH],
            medium_count=severity_counts[VulnSeverity.MEDIUM],
            low_count=severity_counts[VulnSeverity.LOW],
            info_count=severity_counts[VulnSeverity.INFO],
            file_results=file_results,
            overall_risk_score=overall_risk,
            summary=summary
        )

    def _generate_empty_report(self, project_path: str) -> Dict[str, Any]:
        """Generate empty report when no files found."""
        report = DetectionReport(
            project_path=project_path,
            total_files_scanned=0,
            files_with_vulnerabilities=0,
            total_vulnerabilities=0,
            file_results=[],
            overall_risk_score=0.0,
            summary="No files found to scan"
        )
        return report.dict()

    def _save_report(self, report: DetectionReport, output_path: str):
        """Save detection report to file."""
        report_json = json.dumps(report.dict(), indent=2, ensure_ascii=False)

        # Ensure output directory exists
        output_dir = Path(output_path).parent
        output_dir.mkdir(parents=True, exist_ok=True)

        self.file_handler._run(
            file_path=output_path,
            content=report_json,
            operation="write"
        )
