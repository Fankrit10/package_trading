# pylint: disable=W0718,C0301,R0801,R0914,E1128, R0912, R0915
"""
Vulnerability analysis agent (class-based) compatible with NQA BaseFunction style.

This module exposes `SecurityAnalysis` which inherits from `BaseFunction` and
provides an `execute` method that accepts `arguments` similar to other agents
in the project. It reads ZAP JSON reports (paths provided in `arguments`),
uses `fetch_agent_config` and `openai_inference` to call the GenIA model,
and returns a standardized `response_model`. When invoked as a script it
accepts file paths and writes `reporte_vulnerabilidades.json`.
"""
import argparse
import asyncio
import configparser
import json
import os
import re
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import Request
from nqa.controllers.notifications_controller import create_notification_error
from nqa.functions.base_function import BaseFunction
from nqa.utils.utils import fetch_agent_config, openai_inference, response_model
from pnqa_2_auth.utils.logger import get_logger
from pnqa_2_auth.utils.logs_controller import safe_access

logger = get_logger(__name__)


def _read_json(path: str) -> Dict[str, Any]:
    """Read and parse JSON file."""
    with open(path, 'r', encoding='utf-8') as fh:
        return json.load(fh)


class SecurityAnalysis(BaseFunction):
    """Security analysis agent for ZAP reports."""

    def get_openai_function(self):
        """Return OpenAI function configuration."""
        return {
            "name": "security_analysis",
            "activate": "security"
        }

    async def execute(  # pylint: disable=too-many-branches,too-many-statements
        self,
        arguments: Dict[str, Any],
        request: Optional[Request] = None  # pylint: disable=unused-argument
    ):
        """Execute security analysis on ZAP reports."""
        try:
            report_paths: List[str] = safe_access(
                arguments, 'report_paths', []
            ) or []
            if not report_paths:
                return response_model(
                    response="No report_paths provided",
                    log="No input",
                    skip=False,
                    token_usage=0,
                    status_code=400,
                    name_agent="security_analysis_no_input"
                )

            arguments['agents_config'] = await fetch_agent_config(
                name_agent='security_analyzer'
            )
            agent_config = safe_access(
                arguments.get('agents_config'),
                'agent_config',
                {}
            )

            zap_reports = []
            for report_path in report_paths:
                try:
                    zap_reports.append(_read_json(report_path))
                except Exception as exc:
                    logger.error(
                        'Failed to read zap report',
                        extra_data={
                            'path': report_path,
                            'error': str(exc)
                        }
                    )

            system_prompt = safe_access(
                agent_config, 'system_prompt_agent', ''
            )

            composition = (
                f"SYSTEM:\n{system_prompt}\n"
                f"REPORTS:\n{json.dumps(zap_reports, indent=2)}"
            )
            arguments['composition'] = composition

            inference_args = {
                'agents_config': arguments.get('agents_config'),
                'composition': arguments['composition'],
                'id_bot': safe_access(
                    arguments, 'id_bot', 'security_analyzer'
                ),
                'log_security_analysis': True
            }

            try:
                start = time.time()
                data = await openai_inference(arguments=inference_args)
                latency = time.time() - start

                body_text = ''
                if hasattr(data, 'body'):
                    b = data.body
                    body_text = (
                        b.decode() if isinstance(b, bytes) else str(b)
                    )
                else:
                    body_text = json.dumps(data)

                def _extract_json_text(text: str) -> str:
                    if not isinstance(text, str):
                        return text
                    t = text.strip()
                    m = re.search(
                        r"```(?:json)?\s*([\s\S]*?)\s*```",
                        t,
                        re.IGNORECASE
                    )
                    if m:
                        return m.group(1).strip()

                    idx_obj = t.find('{') if '{' in t else -1
                    idx_arr = t.find('[') if '[' in t else -1
                    candidates = [i for i in (idx_obj, idx_arr) if i >= 0]
                    if not candidates:
                        return t
                    start_idx = min(candidates)
                    opening = t[start_idx]
                    closing = '}' if opening == '{' else ']'
                    end = t.rfind(closing)
                    if end != -1 and end > start_idx:
                        return t[start_idx:end+1].strip()
                    return t

                try:
                    parsed = json.loads(body_text)
                except Exception:
                    cleaned = _extract_json_text(body_text)
                    parsed = json.loads(cleaned)

                findings = []
                if isinstance(parsed, dict) and 'response' in parsed:
                    resp = parsed['response']
                    if isinstance(resp, str):
                        try:
                            try:
                                resp_clean = _extract_json_text(resp)
                            except Exception:
                                resp_clean = resp
                            findings = json.loads(resp_clean)
                        except Exception:
                            findings = [{
                                'id': 'VULN-UNKNOWN',
                                'tipo_vulnerabilidad': 'Unknown',
                                'categoria': 'Web',
                                'severidad': 'Media',
                                'endpoint': '',
                                'descripcion': resp,
                                'recomendacion': 'Review model output'
                            }]
                    elif isinstance(resp, list):
                        findings = resp
                elif isinstance(parsed, list):
                    findings = parsed

                final_report = {
                    'application': safe_access(
                        os.environ, 'APP_NAME', 'Trading Application'
                    ),
                    'scan_date': datetime.now().strftime('%Y-%m-%d'),
                    'findings': findings,
                    'modelo_usado': safe_access(
                        os.environ, 'MODEL_NAME', 'GPT-4o'
                    ),
                    'precision': safe_access(
                        os.environ, 'MODEL_PRECISION', '80%'
                    ),
                    'latencia_promedio': f"{latency:.2f}s"
                }

                output_path = safe_access(
                    arguments, 'output', 'reporte_vulnerabilidades.json'
                )
                try:
                    config = configparser.ConfigParser()
                    config_path = (
                        Path(__file__).resolve().parents[2] / 'setup.cfg'
                    )
                    package_version = None
                    if config_path.exists():
                        config.read(config_path)
                        package_version = config.get(
                            'metadata', 'version', fallback=None
                        )
                except Exception:
                    package_version = None

                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                out_p = Path(output_path)
                suffix = out_p.suffix if out_p.suffix else '.json'
                ver_tag = f"v{package_version}" if package_version else 'vunknown'
                final_name = f"{out_p.stem}_{ver_tag}_{timestamp}{suffix}"
                if out_p.parent and str(out_p.parent) != '.':
                    final_path = out_p.parent.joinpath(final_name)
                else:
                    final_path = Path(final_name)

                try:
                    with open(final_path, 'w', encoding='utf-8') as fh:
                        json.dump(
                            final_report, fh, indent=2, ensure_ascii=False
                        )
                    final_report['_report_path'] = str(final_path)
                    logger.info(
                        'Final vulnerability report saved',
                        extra_data={'path': str(final_path)}
                    )
                    output_path = str(final_path)
                except Exception as exc:
                    logger.error(
                        'Failed saving final report',
                        extra_data={'error': str(exc)}
                    )

                return response_model(
                    response=final_report,
                    log='Security analysis completed',
                    skip=False,
                    token_usage=1000,
                    status_code=201,
                    name_agent='security_analysis_success'
                )

            except Exception as e:
                logger.error(
                    'Error in openai_inference',
                    extra_data={'error': str(e)}
                )
                raise

        except Exception as e:
            logger.error(str(e))
            try:
                await create_notification_error(
                    repository='Package NQA / functions: security_analysis',
                    message=f"Error generate security analysis: {str(e)}",
                    user_id=safe_access(arguments, 'id_user'),
                    error_code='SECURITY_ANALYSIS_ERROR_500',
                    function_name='SecurityAnalysis.execute',
                    error_type='Exception',
                    additional_context={
                        'report_paths': safe_access(
                            arguments, 'report_paths', []
                        ),
                        'agent_config_loaded': bool(
                            safe_access(arguments, 'agents_config')
                        )
                    }
                )
            except Exception:
                logger.error('Failed to create notification')

            return response_model(
                response=f"error : {str(e)}",
                log='Failed Security Analysis',
                skip=False,
                token_usage=0,
                status_code=500,
                name_agent='security_analysis_exception'
            )


async def _cli_run(
    paths: List[str],
    output: str = 'reporte_vulnerabilidades.json'
):
    """Run security analysis from CLI."""
    arguments = {
        'report_paths': paths,
        'output': output,
        'id_bot': 'security_analyzer'
    }
    result = await SecurityAnalysis.execute(None, arguments)

    status = None
    report_path = None
    try:
        if isinstance(result, dict):
            status = safe_access(result, 'status_code')
            resp = safe_access(result, 'response')
            if isinstance(resp, dict):
                report_path = resp.get('_report_path')
        elif hasattr(result, 'body'):
            body = result.body
            body_text = (
                body.decode()
                if isinstance(body, (bytes, bytearray))
                else str(body)
            )
            try:
                json_data = json.loads(body_text)
                status = safe_access(json_data, 'status_code')
                resp = safe_access(json_data, 'response')
                if isinstance(resp, dict):
                    report_path = resp.get('_report_path')
            except Exception:
                status = None
    except Exception:
        status = None

    if not report_path:
        report_path = output

    print('Result status:', status)
    print('Report written to:', report_path)
    return report_path


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description=(
            'Analyze ZAP JSON reports and produce a consolidated '
            'vulnerabilities report'
        )
    )
    parser.add_argument(
        '-i', '--input',
        nargs='*',
        help='Input ZAP report files or directories containing reports'
    )
    parser.add_argument(
        '-o', '--output',
        default='reporte_vulnerabilidades.json',
        help='Output JSON report path'
    )
    parser.add_argument(
        '-a', '--artifacts-dir',
        default='.',
        help='Directory where HTML/JSON artifacts will be copied for CI publishing'
    )
    parser.add_argument(
        'paths',
        nargs='*',
        help='Positional input files (legacy support)'
    )

    ns = parser.parse_args()

    raw_inputs: List[str] = []
    if ns.input:
        raw_inputs.extend(ns.input)
    if ns.paths:
        raw_inputs.extend(ns.paths)

    if not raw_inputs:
        print(
            'No input reports provided. Provide JSON report paths or '
            'directories with --input or positional args.'
        )
        parser.print_help()
        sys.exit(1)

    resolved_jsons: List[str] = []
    resolved_htmls: List[Path] = []
    for item in raw_inputs:
        p = Path(item)
        if p.is_dir():
            j = p / 'zap_report.json'
            if j.exists():
                resolved_jsons.append(str(j))
            else:
                for f in p.glob('*.json'):
                    resolved_jsons.append(str(f))
            h = p / 'zap_report.html'
            if h.exists():
                resolved_htmls.append(h)
            else:
                for f in p.glob('*.html'):
                    resolved_htmls.append(f)
        else:
            if p.exists():
                if p.suffix.lower() == '.json':
                    resolved_jsons.append(str(p))
                elif p.suffix.lower() == '.html':
                    resolved_htmls.append(p)
                else:
                    resolved_jsons.append(str(p))
            else:
                print(f'Warning: input path does not exist: {item}')

    if not resolved_jsons:
        print('No JSON reports found in inputs. Exiting.')
        sys.exit(1)

    out_path = ns.output
    artifacts_dir = Path(ns.artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    report_file = asyncio.run(_cli_run(resolved_jsons, out_path))

    try:
        dst = artifacts_dir / Path(report_file).name
        shutil.copyfile(report_file, dst)
        print('Copied final JSON report to artifacts dir:', str(dst))
    except Exception as e:
        print('Failed to copy final JSON report to artifacts dir:', str(e))

    try:
        cfg = configparser.ConfigParser()
        cfg_path = Path(__file__).resolve().parents[2] / 'setup.cfg'
        pkg_version = None
        if cfg_path.exists():
            cfg.read(cfg_path)
            pkg_version = cfg.get('metadata', 'version', fallback=None)
    except Exception:
        pkg_version = None

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    version_tag = f"v{pkg_version}" if pkg_version else 'vunknown'

    for h in resolved_htmls:
        try:
            new_name = f"{h.stem}_{version_tag}_{ts}{h.suffix}"
            dst_h = artifacts_dir / new_name
            shutil.copyfile(h, dst_h)
            print('Copied HTML report to artifacts dir:', str(dst_h))
        except Exception:
            print('Failed copying HTML report:', str(h))

    for j in resolved_jsons:
        try:
            jp = Path(j)
            sibling_html = jp.with_suffix('.html')
            if sibling_html.exists():
                new_name = (
                    f"{sibling_html.stem}_{version_tag}_{ts}"
                    f"{sibling_html.suffix}"
                )
                dst_h = artifacts_dir / new_name
                shutil.copyfile(sibling_html, dst_h)
                print('Copied sibling HTML report to artifacts dir:', str(dst_h))
        except Exception:
            pass  # nosec


if __name__ == '__main__':
    main()
