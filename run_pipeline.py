import subprocess
import sys

SCRIPTS = [
    ("Stage 1: Discovery", "discovery.py"),
    ("Stage 2: Vulnerability Correlation", "correlate.py"),
    ("Stage 3: AI Prioritization", "prioritize.py"),
    ("Stage 4: Dashboard Generation", "generate_dashboard.py"),
]

def main():
    print("=" * 60)
    print(" AUTOMATED ATTACK-SURFACE & VULNERABILITY AUDIT PIPELINE")
    print("=" * 60)

    for stage_name, script in SCRIPTS:
        print(f"\n>>> Executing {stage_name} ({script})...")
        result = subprocess.run([sys.executable, script])
        if result.returncode != 0:
            print(f"[!] Pipeline halted: {script} encountered an error.")
            sys.exit(result.returncode)

    print("\n" + "=" * 60)
    print(" [SUCCESS] Full pipeline execution completed successfully.")
    print("=" * 60)

if __name__ == "__main__":
    main()