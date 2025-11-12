import sys
import os
from pathlib import Path
from trading.crews.security_crew import SecurityRemediationCrew
import json

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def main():
    print("\n" + "="*80)
    print("SECURITY REMEDIATION CREW - STARTING")
    print("="*80 + "\n")

    input_report = "data/input/reporte_vulnerabilidades.json"
    output_plan = "outputs/plan_remediacion.json"

    if not os.path.exists(input_report):
        print(f"ERROR: Input report not found at {input_report}")
        print("Please ensure the vulnerability report exists.")
        return

    os.makedirs("outputs", exist_ok=True)
    os.makedirs("outputs/remediated_code", exist_ok=True)

    try:
        crew = SecurityRemediationCrew()

        print(f"Reading vulnerability report from: {input_report}")
        print(f"Output will be saved to: {output_plan}\n")

        result = crew.process_vulnerability_report(input_report, output_plan)

        print("\n" + "="*80)
        print("REMEDIATION COMPLETE")
        print("="*80)
        print(f"\nApplication: {result['application']}")
        print(f"Date: {result['plan_fecha']}")
        print(f"Success Rate: {result['tasa_exito']}")
        print(f"Total Vulnerabilities: {len(result['vulnerabilidades_remediadas'])}")
        print(f"\nRemediation plan saved to: {output_plan}")
        print("Remediated code saved to: outputs/remediated_code/")

        print("\n" + "-"*80)
        print("SUMMARY BY VULNERABILITY:")
        print("-"*80)
        for vuln in result['vulnerabilidades_remediadas']:
            print(f"\n{vuln['id']} - {vuln['tipo']}")
            print(f"  Status: {vuln['resultado_validacion']}")
            print(f"  Model: {vuln['modelo_usado']}")
            print(f"  File: {vuln['file_path']}")

        print("\n" + "="*80)
        print("PROCESS COMPLETED SUCCESSFULLY")
        print("="*80 + "\n")

    except FileNotFoundError as e:
        print(f"\nERROR: File not found - {e}")
        print("Please check that all required files exist.")
    except json.JSONDecodeError as e:
        print(f"\nERROR: Invalid JSON format - {e}")
        print("Please check the vulnerability report format.")
    except Exception as e:
        print(f"\nERROR: Unexpected error occurred - {e}")
        print("Please check the logs for more details.")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
