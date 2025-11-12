"""Vulnerability Detection System UI (Streamlit)

This Streamlit application provides a graphical interface for the
automated vulnerability detection system. It scans source code repositories
for security vulnerabilities and displays results in real-time.
"""

import streamlit as st
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Optional

st.set_page_config(
    page_title="Vulnerability Detection System",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        padding: 2rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }

    .status-badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.875rem;
        font-weight: 600;
    }

    .severity-critical {
        background: #f8d7da;
        color: #721c24;
        border: 1px solid #f5c6cb;
    }

    .severity-high {
        background: #fff3cd;
        color: #856404;
        border: 1px solid #ffeeba;
    }

    .severity-medium {
        background: #cce5ff;
        color: #004085;
        border: 1px solid #b8daff;
    }

    .severity-low {
        background: #d1ecf1;
        color: #0c5460;
        border: 1px solid #bee5eb;
    }

    .severity-info {
        background: #e2e3e5;
        color: #383d41;
        border: 1px solid #d6d8db;
    }

    .file-container {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 1rem;
        border-left: 4px solid #007bff;
    }

    .vulnerability-item {
        background: white;
        padding: 1rem;
        margin-bottom: 0.5rem;
        border-radius: 6px;
        border-left: 4px solid #dc3545;
    }
</style>
""", unsafe_allow_html=True)


def init_session_state():
    """Initialize all session state variables."""
    if 'detection_running' not in st.session_state:
        st.session_state.detection_running = False
    if 'current_file' not in st.session_state:
        st.session_state.current_file = None
    if 'results' not in st.session_state:
        st.session_state.results = None
    if 'logs' not in st.session_state:
        st.session_state.logs = []
    if 'progress_value' not in st.session_state:
        st.session_state.progress_value = 0
    if 'current_status' not in st.session_state:
        st.session_state.current_status = "Esperando iniciar..."


init_session_state()


def get_severity_badge(severity: str) -> str:
    """Generate severity badge HTML."""
    severity_lower = severity.lower() if isinstance(severity, str) else "info"

    if "critical" in severity_lower:
        return '<span class="status-badge severity-critical">🔴 CRITICAL</span>'
    elif "high" in severity_lower:
        return '<span class="status-badge severity-high">🟠 HIGH</span>'
    elif "medium" in severity_lower:
        return '<span class="status-badge severity-medium">🔵 MEDIUM</span>'
    elif "low" in severity_lower:
        return '<span class="status-badge severity-low">🟢 LOW</span>'
    else:
        return '<span class="status-badge severity-info">ℹ️ INFO</span>'


def add_log(message: str, level: str = "info"):
    """Add log entry."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    st.session_state.logs.append({
        "timestamp": timestamp,
        "message": message,
        "level": level
    })


def update_progress_and_status(message: str, current: Optional[int] = None,
                               total: Optional[int] = None):
    """Update progress bar and status message."""
    st.session_state.current_status = message
    add_log(message)

    if current is not None and total is not None:
        progress = int((current / total) * 100)
        st.session_state.progress_value = progress


def load_report(report_path: str) -> Optional[dict]:
    """Load detection report from file."""
    try:
        if Path(report_path).exists():
            with open(report_path, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        st.error(f"Error cargando reporte: {e}")
    return None


def run_vulnerability_detection(directory_path: str, output_path: str,
                                file_extensions: list):
    """Execute vulnerability detection using VulnerabilityDetectionCrew."""
    from trading.crews.detection_crew import VulnerabilityDetectionCrew

    try:
        st.session_state.logs = []
        st.session_state.progress_value = 0

        progress_container = st.empty()
        log_container = st.empty()

        with progress_container.container():
            progress_bar = st.progress(0)
            status_text = st.empty()

        def progress_callback(message: str, current: Optional[int] = None,
                              total: Optional[int] = None):
            update_progress_and_status(message, current, total)
            if current is not None and total is not None:
                progress = int((current / total) * 100)
                progress_bar.progress(progress)
            status_text.text(message)

            with log_container:
                with st.expander("📝 Logs en Tiempo Real", expanded=True):
                    log_text = "\n".join([
                        f"[{log['timestamp']}] {log['message']}"
                        for log in st.session_state.logs
                    ])
                    st.code(log_text, language="")

        crew = VulnerabilityDetectionCrew(progress_callback=progress_callback)

        update_progress_and_status("🚀 Iniciando escaneo de vulnerabilidades...")
        progress_bar.progress(5)
        time.sleep(0.5)

        # Run detection
        result = crew.scan_directory(
            directory_path=directory_path,
            output_path=output_path,
            file_extensions=file_extensions
        )

        update_progress_and_status("✅ Escaneo completado exitosamente!")
        progress_bar.progress(100)
        time.sleep(1)

        # Clear progress containers
        progress_container.empty()

        # Load and display results
        st.session_state.results = load_report(output_path)

        return result

    except Exception as e:
        st.error(f"❌ Error durante el escaneo: {str(e)}")
        add_log(f"Error: {str(e)}", "error")
        return None


def display_summary_metrics(report: dict):
    """Display summary metrics in columns."""
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric("Total Vulnerabilidades", report.get('total_vulnerabilities', 0))

    with col2:
        st.metric(
            "Críticas",
            report.get('critical_count', 0),
            delta=None,
            delta_color="off"
        )

    with col3:
        st.metric(
            "Altas",
            report.get('high_count', 0),
            delta=None,
            delta_color="off"
        )

    with col4:
        st.metric(
            "Medias",
            report.get('medium_count', 0),
            delta=None,
            delta_color="off"
        )

    with col5:
        st.metric(
            "Riesgo General",
            f"{report.get('overall_risk_score', 0):.1f}/10"
        )


def display_file_vulnerabilities(file_result: dict):
    """Display vulnerabilities for a single file."""
    file_path = file_result.get('file_path', 'Unknown')
    total_vulns = file_result.get('total_vulnerabilities', 0)
    risk_score = file_result.get('risk_score', 0)

    with st.container():
        st.markdown(f"""
        <div class="file-container">
            <h4>📄 {file_path}</h4>
            <p>Vulnerabilidades: <b>{total_vulns}</b> |
                Riesgo: <b>{risk_score:.1f}/10</b>
            </p>
        </div>
        """, unsafe_allow_html=True)

        if total_vulns > 0:
            vulnerabilities = file_result.get('vulnerabilities', [])
            for idx, vuln in enumerate(vulnerabilities, 1):
                vuln_type = vuln.get('vuln_type', 'Other')
                severity = vuln.get('severity', 'Info')
                description = vuln.get('description', 'No description')
                code_snippet = vuln.get('code_snippet', '')
                line_number = vuln.get('line_number', 'N/A')
                cwe = vuln.get('cwe_id', 'N/A')
                owasp = vuln.get('owasp_category', 'N/A')
                exploitability = vuln.get('exploitability', 'N/A')
                business_impact = vuln.get('business_impact', 'N/A')

                severity_badge = get_severity_badge(severity)

                with st.expander(f"{severity_badge} - {vuln_type} (#{idx})"):
                    # Información principal
                    st.markdown(f"**Línea:** `{line_number}`")
                    st.markdown(f"**CWE:** `{cwe}`")
                    st.markdown(f"**OWASP:** `{owasp}`")
                    st.markdown(f"**Exploitabilidad:** `{exploitability}`")
                    st.markdown(f"**Impacto:** {business_impact}")

                    st.divider()

                    # Código vulnerable
                    st.markdown("**📝 Código Vulnerable:**")
                    if code_snippet:
                        st.code(code_snippet, language="python")
                    else:
                        st.warning("No se capturó el código exacto")

                    st.divider()

                    # Descripción
                    st.markdown(f"**Descripción:** {description}")

                    # Recomendación basada en tipo
                    st.info("💡 **Recomendación:** Usa `shlex.quote()` para "
                            "escapar argumentos de shell o evita usar `shell=True`")


# Main UI
def main():
    """Main application interface."""
    st.markdown("""
    <div class="main-header">
        <h1>🔍 Sistema de Detección de Vulnerabilidades</h1>
        <p>Análisis automático de seguridad usando IA multi-agente</p>
    </div>
    """, unsafe_allow_html=True)

    # Sidebar configuration
    with st.sidebar:
        st.header("⚙️ Configuración")

        st.markdown("### Ruta del Proyecto")
        project_path = st.text_input(
            "Directorio a escanear:",
            value="juice-shop",
            help="Ruta relativa o absoluta del directorio"
        )

        st.markdown("### Extensiones a Escanear")
        extensions = st.multiselect(
            "Tipos de archivo:",
            ['.ts', '.js', '.py', '.java', '.cs', '.go', '.tsx', '.jsx'],
            default=['.ts', '.js', '.py']
        )

        st.markdown("### Salida")
        output_path = st.text_input(
            "Archivo de reporte:",
            value="outputs/detection_report.json",
            help="Ruta donde se guardará el reporte"
        )

        st.divider()

        # Detection control
        col1, col2 = st.columns(2)
        with col1:
            start_scan = st.button(
                "🚀 Iniciar Escaneo",
                use_container_width=True,
                type="primary"
            )

        with col2:
            if st.button("🔄 Limpiar", use_container_width=True):
                st.session_state.results = None
                st.session_state.logs = []
                st.session_state.progress_value = 0
                st.rerun()

    # Main content area
    if start_scan:
        st.session_state.detection_running = True

        with st.container():
            run_vulnerability_detection(
                directory_path=project_path,
                output_path=output_path,
                file_extensions=extensions
            )

        st.session_state.detection_running = False

    # Display results if available
    if st.session_state.results:
        st.success("✅ Escaneo completado exitosamente!")

        report = st.session_state.results

        st.markdown("### 📊 Resumen Ejecutivo")
        display_summary_metrics(report)

        st.markdown(f"**Resumen:** {report.get('summary', 'N/A')}")

        st.divider()

        st.markdown("### 📄 Análisis Detallado por Archivo")

        # Create tabs for different severity levels
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            f"🔴 Críticas ({report.get('critical_count', 0)})",
            f"🟠 Altas ({report.get('high_count', 0)})",
            f"🔵 Medias ({report.get('medium_count', 0)})",
            f"🟢 Bajas ({report.get('low_count', 0)})",
            f"ℹ️ Info ({report.get('info_count', 0)})"
        ])

        file_results = report.get('file_results', [])

        with tab1:
            critical_files = [
                f for f in file_results
                if any(v.get('severity', '').lower() == 'critical'
                       for v in f.get('vulnerabilities', []))
            ]
            if critical_files:
                for file_result in critical_files:
                    display_file_vulnerabilities(file_result)
            else:
                st.info("No se encontraron vulnerabilidades críticas.")

        with tab2:
            high_files = [
                f for f in file_results
                if any(v.get('severity', '').lower() == 'high'
                       for v in f.get('vulnerabilities', []))
            ]
            if high_files:
                for file_result in high_files:
                    display_file_vulnerabilities(file_result)
            else:
                st.info("No se encontraron vulnerabilidades altas.")

        with tab3:
            medium_files = [
                f for f in file_results
                if any(v.get('severity', '').lower() == 'medium'
                       for v in f.get('vulnerabilities', []))
            ]
            if medium_files:
                for file_result in medium_files:
                    display_file_vulnerabilities(file_result)
            else:
                st.info("No se encontraron vulnerabilidades medias.")

        with tab4:
            low_files = [
                f for f in file_results
                if any(v.get('severity', '').lower() == 'low'
                       for v in f.get('vulnerabilities', []))
            ]
            if low_files:
                for file_result in low_files:
                    display_file_vulnerabilities(file_result)
            else:
                st.info("No se encontraron vulnerabilidades bajas.")

        with tab5:
            info_files = [
                f for f in file_results
                if any(v.get('severity', '').lower() == 'info'
                       for v in f.get('vulnerabilities', []))
            ]
            if info_files:
                for file_result in info_files:
                    display_file_vulnerabilities(file_result)
            else:
                st.info("No se encontraron hallazgos informativos.")

        st.divider()

        # Raw report view
        with st.expander("📋 Ver Reporte Completo (JSON)"):
            st.json(report)

        # Download report
        report_json = json.dumps(report, indent=2, ensure_ascii=False)
        st.download_button(
            label="📥 Descargar Reporte",
            data=report_json,
            file_name=f"detection_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )

    else:
        st.info(
            "👋 Bienvenido al Sistema de Detección de Vulnerabilidades\n\n"
            "Configure los parámetros en la barra lateral y haga clic en "
            "'🚀 Iniciar Escaneo' para comenzar el análisis."
        )


if __name__ == "__main__":
    main()
