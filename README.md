# CyberSOC Incident Triage Assistant

CyberSOC Incident Triage Assistant is an offline, knowledge-base driven SOC triage assistant prototype.

The project helps a junior SOC analyst understand and triage common security alerts using a local cybersecurity knowledge base.

Current supported alert categories:

- Brute Force / Suspicious Login
- Phishing / Suspicious Email
- Suspicious PowerShell / Endpoint Execution

This project is designed for defensive cybersecurity learning, SOC workflow practice, and portfolio demonstration.

---

## Project Goal

The goal of this project is not to automatically block IP addresses, disable accounts, remove malware, or perform destructive actions.

The goal is to help a human SOC analyst answer questions such as:

- What does this alert mean?
- Which attack behavior could it resemble?
- What evidence supports the interpretation?
- What information is missing?
- What should the analyst check next?
- When should the alert be escalated as an incident?

The assistant uses a local knowledge base and generates a structured SOC Analyst Coach style prompt for further analysis by an LLM.

---

## Current Features

- Sample final SOC Analyst Coach answers
- Local Markdown-based cybersecurity knowledge base
- Simple retrieval system
- Category-aware retrieval scoring
- SOC Analyst Coach prompt generation
- Interactive CLI triage mode
- Demo pipeline
- 9 structured sample alerts
- Retrieval test suite
- Sample alert retrieval test suite
- Automatic prompt generation for all sample alerts

---

## Supported Scenarios

### 1. Brute Force / Suspicious Login

Covers alerts such as:

- Multiple failed login attempts
- VPN login anomalies
- Failed attempts followed by successful login
- Privileged account targeting
- Password guessing
- Password spraying
- Credential stuffing suspicion

Main knowledge base files:

- `knowledge_base/mitre/T1110_brute_force.md`
- `knowledge_base/playbooks/brute_force_playbook.md`
- `knowledge_base/investigation_notes/login_log_fields.md`

---

### 2. Phishing / Suspicious Email

Covers alerts such as:

- Suspicious email reports
- Unknown links
- Password reset themes
- Credential phishing
- Malicious attachment suspicion
- User click tracking
- Credential entry suspicion
- Email authentication issues

Main knowledge base files:

- `knowledge_base/mitre/T1566_phishing.md`
- `knowledge_base/playbooks/phishing_playbook.md`
- `knowledge_base/investigation_notes/email_investigation_fields.md`

---

### 3. Suspicious PowerShell / Endpoint Execution

Covers alerts such as:

- Encoded PowerShell commands
- Suspicious command-line execution
- Unknown parent process
- PowerShell network connections
- Office document launching PowerShell
- Script execution after phishing
- EDR or AMSI detection context

Main knowledge base files:

- `knowledge_base/mitre/T1059_command_and_scripting_interpreter.md`
- `knowledge_base/playbooks/suspicious_powershell_playbook.md`
- `knowledge_base/investigation_notes/endpoint_investigation_fields.md`

---

## Knowledge Base Structure

```text
knowledge_base/
├── mitre/
│   ├── T1110_brute_force.md
│   ├── T1566_phishing.md
│   └── T1059_command_and_scripting_interpreter.md
├── nist/
│   └── nist_incident_response_summary.md
├── playbooks/
│   ├── brute_force_playbook.md
│   ├── phishing_playbook.md
│   └── suspicious_powershell_playbook.md
├── investigation_notes/
│   ├── login_log_fields.md
│   ├── email_investigation_fields.md
│   └── endpoint_investigation_fields.md
└── sample_alerts/
    ├── brute_force_low_01.json
    ├── brute_force_medium_01.json
    ├── brute_force_high_01.json
    ├── phishing_low_01.json
    ├── phishing_medium_01.json
    ├── phishing_high_01.json
    ├── powershell_low_01.json
    ├── powershell_medium_01.json
    └── powershell_high_01.json
```

---

## Sample Alerts

The project includes 9 sample alerts grouped by category and risk level.

```text
Brute Force:
- brute_force_low_01.json
- brute_force_medium_01.json
- brute_force_high_01.json

Phishing:
- phishing_low_01.json
- phishing_medium_01.json
- phishing_high_01.json

Suspicious PowerShell:
- powershell_low_01.json
- powershell_medium_01.json
- powershell_high_01.json
```

These alerts are used to test whether the retrieval system connects each alert to the correct knowledge base sources.

---

## How Retrieval Works

The retrieval system reads the Markdown files inside the knowledge base and compares them with the alert text.

The system uses:

- keyword matching
- token aliases
- category detection
- category-aware scoring
- general NIST incident response boosting

The retrieval score is not an attack probability.

It only means:

```text
How strongly the alert text matched a knowledge base source.
```

For example:

- A brute force alert should retrieve T1110, brute force playbook, login log fields, and NIST.
- A phishing alert should retrieve T1566, phishing playbook, email investigation fields, and NIST.
- A PowerShell alert should retrieve T1059, suspicious PowerShell playbook, endpoint investigation fields, and NIST.

---

## SOC Analyst Coach Output Format

The final prompt asks the LLM to answer in this format:

```text
# 1. Olayı İnsan Dilinde Açıklama

# 2. İlk İzlenim

# 3. Olası Senaryolar

# 4. MITRE ATT&CK Eşleşmesi

# 5. Bu Yorumu Destekleyen Kanıtlar

# 6. Risk Artıran Durumlar

# 7. Risk Düşüren veya False Positive Olabilecek Durumlar

# 8. Eksik Bilgiler

# 9. SOC Analyst İçin Adım Adım Kontrol Planı

# 10. Ne Zaman Incident'a Yükseltilir?

# 11. Önerilen İlk Müdahale

# 12. Kullanılan Kaynaklar

# 13. Güven Düzeyi
```

This format is designed to coach a junior SOC analyst instead of giving a short generic answer.

---

## Project Structure

```text
CyberSOC-Incident-Triage-Assistant/
├── docs/
│   └── planning/
├── knowledge_base/
│   ├── mitre/
│   ├── nist/
│   ├── playbooks/
│   ├── investigation_notes/
│   └── sample_alerts/
├── outputs/
│   ├── sample_prompts/
│   ├── retrieved_context.txt
│   ├── answer_prompt.txt
│   ├── sample_answer_bruteforce.md
│   ├── sample_answer_phishing.md
│   └── sample_answer_powershell.md
├── src/
│   ├── build_answer_prompt.py
│   ├── build_context.py
│   ├── generate_sample_alerts.py
│   ├── generate_sample_prompts.py
│   ├── load_knowledge_base.py
│   ├── query_builder.py
│   ├── run_demo_pipeline.py
│   ├── simple_retriever.py
│   ├── test_retrieval.py
│   ├── test_sample_alerts.py
│   └── triage_cli.py
├── README.md
└── .gitignore
```

---

## How to Run

### Generate sample final answers

```bash
python src/generate_sample_final_answers.py
```

This creates example final SOC Analyst Coach answers inside:

```text
outputs/sample_final_answers/
```

### Run the demo pipeline

```bash
python src/run_demo_pipeline.py
```

This runs a predefined brute force demo alert and creates:

```text
outputs/retrieved_context.txt
outputs/answer_prompt.txt
```

---

### Run interactive triage mode

```bash
python src/triage_cli.py
```

Paste an alert, log, or incident description into the terminal.

Press Enter on an empty line to finish.

The program will:

1. Build a retrieval query
2. Search the local knowledge base
3. Build a retrieved context
4. Generate a SOC Analyst Coach prompt

---

### Generate sample alerts

```bash
python src/generate_sample_alerts.py
```

This creates the 9 JSON sample alerts inside:

```text
knowledge_base/sample_alerts/
```

---

### Generate prompts for all sample alerts

```bash
python src/generate_sample_prompts.py
```

This creates 9 prompt files inside:

```text
outputs/sample_prompts/
```

Each file contains a complete SOC Analyst Coach prompt for one sample alert.

---

## Tests

### Run all project checks

```bash
python src/run_all_checks.py
```

This command runs:

- retrieval tests
- sample alert retrieval tests
- sample prompt generation

### Test basic retrieval scenarios

```bash
python src/test_retrieval.py
```

Expected result:

```text
Genel Sonuç: 3/3 test geçti.
```

---

### Test all sample alerts

```bash
python src/test_sample_alerts.py
```

Expected result:

```text
Genel Sonuç: 9/9 sample alert testi geçti.
```

The tests check whether each alert category retrieves the expected knowledge base files.

---

## Current Test Status

Latest validated results:

```text
Retrieval test suite: 3/3 passed
Sample alert retrieval test suite: 9/9 passed
Sample prompt generation: 9 prompts generated
```

---

## Example Workflow

```text
1. Analyst enters an alert.
2. Query builder enriches the alert text.
3. Retriever finds relevant knowledge base files.
4. Context builder creates a source-based context.
5. Prompt builder creates a SOC Analyst Coach prompt.
6. LLM can use the prompt to generate a structured triage answer.
```

---

## Safety Boundaries

This project is defensive and educational.

The assistant does not:

- perform exploitation
- provide malware code
- steal credentials
- automatically block IP addresses
- automatically disable accounts
- delete files
- kill processes
- perform destructive remediation

It only provides triage guidance for a human analyst.

---

## Limitations

Current limitations:

- No real SIEM integration
- No real EDR integration
- No live log ingestion
- No automatic LLM call yet
- Retrieval is keyword and category based, not embedding based
- Scores are retrieval scores, not probability or severity scores
- Sample alerts are synthetic educational examples

---

## Roadmap

Planned improvements:

- Add local LLM integration
- Add optional Foundry Local / local model workflow
- Add richer output examples for low, medium, and high severity alerts
- Add more SOC playbooks
- Add more MITRE ATT&CK techniques
- Add more sample alerts
- Improve retrieval using embeddings
- Add structured JSON output mode
- Add a simple web UI
- Add exportable incident triage reports

---

## Status

```text
Sample final answer generator: working
Knowledge base design: done
Brute force knowledge line: done
Phishing knowledge line: done
Suspicious PowerShell knowledge line: done
NIST incident response summary: done
Sample alerts: done
Retriever: working
Category-aware retrieval: working
Context builder: working
Answer prompt builder: working
SOC Analyst Coach prompt format: done
Demo pipeline: working
Interactive CLI: working
Retrieval tests: passing
Sample alert tests: passing
Sample prompt generator: working
LLM integration: next step
```

---

## Disclaimer

This project is a learning and portfolio prototype for defensive cybersecurity.

It should not be used as a production SOC tool without proper validation, security review, logging, access control, and integration testing.