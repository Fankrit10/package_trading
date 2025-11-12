
"""Security Remediation System UI (Streamlit)

This Streamlit application provides a graphical interface for the
automated multi-agent security remediation system. It allows users
to execute, monitor, and visualize the remediation process in real time,
integrated with the `SecurityRemediationCrew` backend.
"""

import streamlit as st
import json
import time
from pathlib import Path
from datetime import datetime

st.set_page_config(
    page_title="Security Remediation System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
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

    .status-mitigated {
        background: #d4edda;
        color: #155724;
    }

    .status-partial {
        background: #fff3cd;
        color: #856404;
    }

    .status-processing {
        background: #cce5ff;
        color: #004085;
    }
</style>
""", unsafe_allow_html=True)


def init_session_state():
    """Inicializar todas las variables de estado"""
    if 'remediation_running' not in st.session_state:
        st.session_state.remediation_running = False
    if 'current_vulnerability' not in st.session_state:
        st.session_state.current_vulnerability = None
    if 'results' not in st.session_state:
        st.session_state.results = None
    if 'logs' not in st.session_state:
        st.session_state.logs = []


init_session_state()


def get_status_badge(status):
    """Generar badge de estado"""
    status_str = str(status).lower() if not isinstance(status, str) else status.lower()

    if "mitigated" in status_str and "partial" not in status_str:
        return '<span class="status-badge status-mitigated">✅ MITIGATED</span>'
    elif "partial" in status_str:
        return '<span class="status-badge status-partial">⚠️ PARTIAL</span>'
    else:
        return '<span class="status-badge status-processing">🔄 PROCESSING</span>'


def add_log(message, level="info"):
    """Agregar log"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    st.session_state.logs.append({
        "timestamp": timestamp,
        "message": message,
        "level": level
    })


def load_results():
    """Cargar resultados desde el archivo JSON"""
    plan_path = Path("outputs/plan_remediacion.json")

    if plan_path.exists():
        with open(plan_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None


def run_remediation():
    """Ejecutar remediación usando SecurityRemediationCrew"""
    from trading.crews.security_crew import SecurityRemediationCrew

    try:
        st.session_state.logs = []

        progress_container = st.empty()
        log_container = st.empty()

        with progress_container.container():
            progress_bar = st.progress(0)
            status_text = st.empty()

        add_log("🚀 Iniciando Security Remediation System...")
        status_text.text("🚀 Iniciando sistema de remediación...")
        progress_bar.progress(5)
        time.sleep(0.3)

        report_path = "data/input/reporte_vulnerabilidades.json"
        output_path = "outputs/plan_remediacion.json"

        add_log(f"📂 Verificando archivo: {report_path}")

        if not Path(report_path).exists():
            add_log(f"❌ Error: No se encontró {report_path}", "error")
            st.error(f"❌ No se encontró el archivo: {report_path}")
            return

        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)

        total_vulns = len(report_data.get('vulnerabilities', []))
        add_log(f"✅ Encontradas {total_vulns} vulnerabilidades para procesar")
        progress_bar.progress(10)

        add_log("🤖 Inicializando agentes de seguridad...")
        add_log("  - Security Vulnerability Analyst")
        add_log("  - Code Remediation Specialist")
        add_log("  - Security Validation Engineer")

        status_text.text("🤖 Inicializando agentes...")
        progress_bar.progress(15)

        crew = SecurityRemediationCrew()
        add_log("✅ Agentes inicializados correctamente")
        time.sleep(0.5)

        add_log("🔍 Iniciando proceso de remediación...")
        status_text.text(f"🔍 Procesando {total_vulns} vulnerabilidades...")
        progress_bar.progress(20)

        with log_container:
            with st.expander("📝 Ver Logs en Tiempo Real", expanded=True):
                log_text = "\n".join([
                    f"[{log['timestamp']}] {log['message']}"
                    for log in st.session_state.logs
                ])
                st.code(log_text, language="")

        add_log("⚙️ Ejecutando process_vulnerability_report()...")

        result = crew.process_vulnerability_report(
            report_path=report_path,
            output_path=output_path
        )

        add_log(
            f"✅ Proceso completado - "
            f"{len(result.get('vulnerabilidades_remediadas', []))} "
            "vulnerabilidades procesadas"
        )

        progress_bar.progress(90)
        status_text.text("💾 Guardando resultados finales...")
        add_log("💾 Guardando plan de remediación en outputs/")
        time.sleep(0.5)

        st.session_state.results = load_results()

        progress_bar.progress(100)
        status_text.text("✅ ¡Remediación completada!")
        add_log("✨ ¡Proceso completado exitosamente!")
        time.sleep(1)

        progress_container.empty()

        if st.session_state.results:
            success_rate = st.session_state.results.get('tasa_exito', 'N/A')
            total = len(st.session_state.results.get('vulnerabilidades_remediadas', []))

            st.success("✅ Remediación completada exitosamente!")

            col1, col2 = st.columns(2)
            with col1:
                st.metric("Vulnerabilidades Procesadas", total)
            with col2:
                st.metric("Tasa de Éxito", success_rate)
        else:
            st.warning("⚠️ Proceso completado pero no se encontraron resultados")

    except Exception as e:
        add_log(f"❌ Error crítico: {str(e)}", "error")
        st.error("❌ Error durante la remediación")

        import traceback
        error_details = traceback.format_exc()
        add_log(f"Detalles: {error_details}", "error")

        with st.expander("🔍 Ver detalles técnicos del error"):
            st.code(error_details)

    finally:
        if st.session_state.logs:
            with st.expander("📝 Ver Todos los Logs", expanded=False):
                log_text = "\n".join([
                    f"[{log['timestamp']}] {log['message']}"
                    for log in st.session_state.logs
                ])
                st.code(log_text, language="")


st.markdown("""
<div class="main-header">
    <h1>🛡️ Security Remediation System</h1>
    <p>Sistema Automatizado de Remediación de Vulnerabilidades con Multi-Agentes</p>
</div>
""", unsafe_allow_html=True)


with st.sidebar:
    st.header("⚙️ Panel de Control")

    st.markdown("---")

    if st.button("🚀 Iniciar Remediación",
                 use_container_width=True,
                 type="primary",
                 help="Ejecutar el sistema completo de remediación"):
        st.session_state.results = None
        st.session_state.logs = []
        run_remediation()
        st.rerun()

    st.markdown("---")

    st.subheader("📋 Configuración")

    st.text_input(
        "Archivo de entrada",
        value="data/input/reporte_vulnerabilidades.json",
        disabled=True
    )

    st.text_input(
        "Archivo de salida",
        value="outputs/plan_remediacion.json",
        disabled=True
    )

    st.markdown("---")

    if st.button("🔄 Recargar Resultados",
                 use_container_width=True,
                 help="Cargar resultados de ejecución anterior"):
        st.session_state.results = load_results()
        if st.session_state.results:
            st.success("✅ Resultados cargados")
            st.rerun()
        else:
            st.warning("⚠️ No hay resultados disponibles")

    st.markdown("---")

    if st.session_state.results:
        st.subheader("📊 Estadísticas")

        total = len(st.session_state.results.get('vulnerabilidades_remediadas', []))
        success_rate = st.session_state.results.get('tasa_exito', '0%')

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total", total)
        with col2:
            st.metric("Éxito", success_rate)

        mitigated = 0
        partial = 0

        for v in st.session_state.results['vulnerabilidades_remediadas']:
            status = str(v['resultado_validacion']).lower()
            if 'mitigated' in status and 'partial' not in status:
                mitigated += 1
            elif 'partial' in status:
                partial += 1

        st.progress(mitigated / total if total > 0 else 0)
        st.caption(f"✅ {mitigated} Mitigadas | ⚠️ {partial} Parciales")

    st.markdown("---")

    st.caption("**Agentes Activos:**")
    st.caption("🔍 Security Analyst")
    st.caption("🔧 Code Remediator")
    st.caption("✅ Validator")

tab1, tab2, tab3, tab4 = st.tabs([
    "🎯 Dashboard",
    "📝 Logs",
    "📊 Detalles",
    "💻 Código"
])

with tab1:
    if not st.session_state.results:
        st.info("👈 Haz clic en **'Iniciar Remediación'** para comenzar el análisis")

        st.subheader("📋 Vista Previa de Vulnerabilidades")

        try:
            vuln_file = Path("data/input/reporte_vulnerabilidades.json")
            if vuln_file.exists():
                with open(vuln_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                total = len(data.get('vulnerabilities', []))
                st.info(f"📊 Se encontraron **{total} vulnerabilidades** para procesar")

                for vuln in data.get('vulnerabilities', [])[:4]:
                    with st.expander(f"{vuln['id']} - {vuln['type']}", expanded=False):
                        col1, col2, col3 = st.columns(3)

                        with col1:
                            severity_emoji = {
                                'CRITICAL': '🔴',
                                'HIGH': '🟠',
                                'MEDIUM': '🟡',
                                'LOW': '🟢'
                            }
                            st.write(
                                f"**Severidad:** "
                                f"{severity_emoji.get(vuln['severity'], '⚪')} "
                                f"{vuln['severity']}"
                            )

                        with col2:
                            st.write(f"**Archivo:** `{Path(vuln['file']).name}`")

                        with col3:
                            st.write(f"**Línea:** {vuln['line']}")

                        st.write(f"**Descripción:** {vuln['description']}")

                        if 'vulnerable_code_snippet' in vuln:
                            st.code(vuln['vulnerable_code_snippet'][:300], language='python')

                if total > 4:
                    st.info(f"... y {total - 4} vulnerabilidades más")
            else:
                st.warning(f"⚠️ No se encontró: {vuln_file}")

        except Exception as e:
            st.error(f"Error: {str(e)}")

    else:
        st.subheader("📊 Resumen de Remediación")

        col1, col2, col3, col4 = st.columns(4)

        results = st.session_state.results['vulnerabilidades_remediadas']
        total = len(results)

        mitigated = sum(1 for v in results
                        if 'mitigated' in str(v['resultado_validacion']).lower()
                        and 'partial' not in str(v['resultado_validacion']).lower())

        partial = sum(1 for v in results
                      if 'partial' in str(v['resultado_validacion']).lower())

        with col1:
            st.metric("🎯 Total", total)
        with col2:
            st.metric("✅ Mitigadas", mitigated)
        with col3:
            st.metric("⚠️ Parciales", partial)
        with col4:
            st.metric("📈 Éxito", st.session_state.results['tasa_exito'])

        st.markdown("---")
        st.subheader("🔍 Detalle de Vulnerabilidades")

        for vuln in results:
            col1, col2, col3 = st.columns([3, 2, 1])

            with col1:
                st.markdown(f"### {vuln['id']} - {vuln['tipo']}")
                st.caption(f"Modelo: {vuln['modelo_usado']}")

            with col2:
                st.markdown(get_status_badge(vuln['resultado_validacion']),
                            unsafe_allow_html=True)

            with col3:
                if st.button("Ver 📄", key=f"btn_{vuln['id']}"):
                    st.session_state.current_vulnerability = vuln
                    st.rerun()

            st.markdown("---")

with tab2:
    st.subheader("📝 Logs del Sistema")

    if st.session_state.logs:
        log_text = "\n".join([
            f"[{log['timestamp']}] {log['message']}"
            for log in st.session_state.logs
        ])

        st.code(log_text, language="")
        st.caption(f"Total de eventos: {len(st.session_state.logs)}")
    else:
        st.info("📝 No hay logs todavía. Los logs aparecerán aquí durante la ejecución.")

with tab3:
    if st.session_state.current_vulnerability:
        vuln = st.session_state.current_vulnerability

        st.subheader(f"🔍 {vuln['id']} - {vuln['tipo']}")

        if st.button("⬅️ Volver"):
            st.session_state.current_vulnerability = None
            st.rerun()

        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**Estado:** {get_status_badge(vuln['resultado_validacion'])}",
                        unsafe_allow_html=True)
            st.write(f"**Modelo:** {vuln['modelo_usado']}")
        with col2:
            st.write(f"**Archivo:** `{Path(vuln['file_path']).name}`")

        st.markdown("---")

        tab_orig, tab_fix = st.tabs(["📄 Original", "✨ Remediado"])

        with tab_orig:
            st.code(vuln['original_code'], language='python', line_numbers=True)

        with tab_fix:
            code = vuln['remediated_code']
            if code.startswith('```'):
                code = code.replace('```python\n', '').replace('```', '')

            st.code(code, language='python', line_numbers=True)

            st.download_button(
                "⬇️ Descargar",
                data=code,
                file_name=f"{vuln['id']}_fixed.py",
                mime="text/x-python",
                use_container_width=True
            )

    elif st.session_state.results:
        st.info("👆 Selecciona una vulnerabilidad del dashboard")
    else:
        st.info("🚀 Ejecuta la remediación primero")

with tab4:
    if st.session_state.results:
        st.subheader("💻 Archivos Remediados")

        code_dir = Path("outputs/remediated_code")

        if code_dir.exists():
            files = sorted(code_dir.glob("*.py"))

            if files:
                file = st.selectbox("Selecciona:", files, format_func=lambda x: x.name)

                with open(file, 'r', encoding='utf-8') as f:
                    content = f.read()

                st.code(content, language='python', line_numbers=True)

                st.download_button(
                    f"⬇️ Descargar {file.name}",
                    data=content,
                    file_name=file.name,
                    mime="text/x-python",
                    use_container_width=True
                )
            else:
                st.warning("No hay archivos")
        else:
            st.warning("Directorio no existe")
    else:
        st.info("🚀 Ejecuta la remediación primero")

st.markdown("---")
st.caption("🛡️ Security Remediation System v1.0 | Multi-Agent AI System")
