import subprocess
import sys


CHECKS = [
    {
        "name": "Retrieval Test Suite",
        "command": [sys.executable, "src/test_retrieval.py"],
    },
    {
        "name": "Sample Alert Retrieval Test Suite",
        "command": [sys.executable, "src/test_sample_alerts.py"],
    },
    {
        "name": "Sample Prompt Generator",
        "command": [sys.executable, "src/generate_sample_prompts.py"],
    },
    {
        "name": "Sample Final Answer Generator",
        "command": [sys.executable, "src/generate_sample_final_answers.py"],
    },
]


def run_check(check):
    print("=" * 80)
    print(f"Running: {check['name']}")
    print("=" * 80)

    result = subprocess.run(
        check["command"],
        text=True,
        capture_output=True,
    )

    if result.stdout:
        print(result.stdout)

    if result.stderr:
        print("STDERR:")
        print(result.stderr)

    if result.returncode != 0:
        print(f"Result: FAIL - {check['name']}")
        return False

    print(f"Result: PASS - {check['name']}")
    return True


def main():
    print("CyberSOC Project Check Runner")
    print("=" * 80)

    passed = 0
    total = len(CHECKS)

    for check in CHECKS:
        if run_check(check):
            passed += 1

    print("=" * 80)
    print(f"Final Result: {passed}/{total} checks passed.")

    if passed == total:
        print("All project checks completed successfully.")
    else:
        print("Some checks failed. Review the output above.")


if __name__ == "__main__":
    main()