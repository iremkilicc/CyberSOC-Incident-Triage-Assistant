from build_context import retrieve
from query_builder import build_query_from_alert


TEST_CASES = [
    {
        "name": "Brute Force - Turkish natural input",
        "alert": (
            "admin hesabına 5 dakika içinde çok fazla giriş denemesi olmuş "
            "sonra başarılı giriş olmuş vpn üzerinden"
        ),
        "expected_files": [
            "T1110_brute_force.md",
            "login_log_fields.md",
            "brute_force_playbook.md",
        ],
    },
    {
        "name": "Phishing - English alert",
        "alert": (
            "A user reported a suspicious email with an urgent password reset subject. "
            "The email contains an unknown link. "
            "The user_clicked status is unknown. "
            "The credentials_entered status is unknown."
        ),
        "expected_files": [
            "T1566_phishing.md",
            "email_investigation_fields.md",
            "phishing_playbook.md",
        ],
    },
    {
        "name": "Suspicious PowerShell - English alert",
        "alert": (
            "A standard user executed an encoded PowerShell command on WIN-CLIENT-01. "
            "The command line contains powershell.exe -EncodedCommand. "
            "The parent_process is unknown. "
            "The network_connection status is unknown."
        ),
        "expected_files": [
            "T1059_command_and_scripting_interpreter.md",
            "endpoint_investigation_fields.md",
            "suspicious_powershell_playbook.md",
        ],
    },
]


def run_test_case(test_case):
    print("=" * 70)
    print(f"Test: {test_case['name']}")

    query = build_query_from_alert(test_case["alert"])
    results = retrieve(query, top_k=4)

    found_files = [document["path"].name for score, document in results]

    print("\nBulunan kaynaklar:")

    for score, document in results:
        print(f"- {document['path'].name} | kaynak eşleşme skoru: {score}")

    missing_files = []

    for expected_file in test_case["expected_files"]:
        if expected_file not in found_files:
            missing_files.append(expected_file)

    if missing_files:
        print("\nSonuç: FAIL")
        print("Eksik beklenen dosyalar:")

        for missing_file in missing_files:
            print(f"- {missing_file}")

        return False

    print("\nSonuç: PASS")
    return True


def main():
    print("CyberSOC Retrieval Test Suite")
    print("=" * 70)

    passed = 0
    total = len(TEST_CASES)

    for test_case in TEST_CASES:
        if run_test_case(test_case):
            passed += 1

    print("=" * 70)
    print(f"Genel Sonuç: {passed}/{total} test geçti.")

    if passed == total:
        print("Tüm retrieval testleri başarılı.")
    else:
        print("Bazı retrieval testleri başarısız. Query builder veya aliases kontrol edilmeli.")


if __name__ == "__main__":
    main()