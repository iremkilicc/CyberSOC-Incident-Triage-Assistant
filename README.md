# CyberSOC Incident Triage Assistant

CyberSOC Incident Triage Assistant is an offline RAG-based cybersecurity assistant designed to support SOC analysts during initial alert triage.

The project takes a security alert, log snippet, or incident description, retrieves relevant knowledge base documents, and prepares a structured SOC triage answer prompt.

This project is built for educational and portfolio purposes.

---

## Project Goal

The goal is to help a human SOC analyst answer questions such as:

- What could this alert mean?
- Which MITRE ATT&CK technique could be related?
- What evidence supports this interpretation?
- What information is missing?
- What should be checked first?
- Could this be a false positive?

The assistant does not automatically block IP addresses, disable accounts, remove files, or perform remediation actions.

---

## Current Demo Scenario

The current working demo focuses on a brute force login alert.

Example alert:

```text
Multiple failed login attempts were detected for the admin user on the vpn-gateway.
There were 35 failed login attempts within 5 minutes.
After the failed attempts, a successful login was observed.
Source IP: 192.168.1.25
Severity: medium
```

The system retrieves relevant knowledge base documents and builds a SOC analyst answer prompt.

Expected retrieved sources:

```text
knowledge_base/investigation_notes/login_log_fields.md
knowledge_base/mitre/T1110_brute_force.md
knowledge_base/playbooks/brute_force_playbook.md
knowledge_base/nist/nist_incident_response_summary.md
```

---

## Supported Demo Scenarios

The first version supports three main cybersecurity triage scenarios:

1. Brute Force
2. Phishing
3. Suspicious PowerShell

Each scenario contains:

- MITRE ATT&CK summary
- SOC playbook
- Investigation field notes
- Sample alert data

---

## Project Structure

```text
CyberSOC-Incident-Triage-Assistant/
│
├── docs/
│   └── planning/
│       ├── part1_project_notes.md
│       └── part2_knowledge_base_plan.md
│
├── knowledge_base/
│   ├── mitre/
│   │   ├── T1110_brute_force.md
│   │   ├── T1566_phishing.md
│   │   └── T1059_command_and_scripting_interpreter.md
│   │
│   ├── nist/
│   │   └── nist_incident_response_summary.md
│   │
│   ├── playbooks/
│   │   ├── brute_force_playbook.md
│   │   ├── phishing_playbook.md
│   │   └── suspicious_powershell_playbook.md
│   │
│   ├── investigation_notes/
│   │   ├── login_log_fields.md
│   │   ├── email_investigation_fields.md
│   │   └── endpoint_investigation_fields.md
│   │
│   └── sample_alerts/
│       ├── brute_force_alert_01.json
│       ├── phishing_alert_01.json
│       └── powershell_alert_01.json
│
├── outputs/
│   ├── retrieved_context.txt
│   ├── answer_prompt.txt
│   └── sample_answer_bruteforce.md
│
├── src/
│   ├── load_knowledge_base.py
│   ├── simple_retriever.py
│   ├── build_context.py
│   ├── build_answer_prompt.py
│   ├── run_demo_pipeline.py
│   └── triage_cli.py
│
├── README.md
└── .gitignore
```

---

## How It Works

The project follows a simple RAG pipeline:

```text
Security Alert
      ↓
Retrieve relevant knowledge base documents
      ↓
Build retrieved context
      ↓
Build SOC analyst answer prompt
      ↓
Review structured triage response
```

### 1. Retrieve

The retriever searches the `knowledge_base` folder and finds documents related to the alert.

### 2. Build Context

The selected documents are read and combined into a context file:

```text
outputs/retrieved_context.txt
```

### 3. Build Answer Prompt

The alert and retrieved context are combined into a final SOC analyst prompt:

```text
outputs/answer_prompt.txt
```

### 4. Sample Answer

A manually prepared reference answer is provided here:

```text
outputs/sample_answer_bruteforce.md
```

This file shows the expected SOC triage response format for the brute force demo.

---

## Run Demo Pipeline

From the project root folder, run:

```bash
python src/run_demo_pipeline.py
```

Expected terminal flow:

```text
CyberSOC Incident Triage Assistant - Demo Pipeline

[1] Alert alındı
[2] Knowledge base içinde ilgili kaynaklar aranıyor
[3] Seçilen kaynaklar
[4] Context oluşturuluyor
[5] Answer prompt oluşturuluyor
[6] Demo tamamlandı
```

After running the demo, check:

```text
outputs/retrieved_context.txt
outputs/answer_prompt.txt
outputs/sample_answer_bruteforce.md
```

---

## Run Interactive CLI

You can also enter your own alert, log snippet, or incident description from the terminal.

Run:

```bash
python src/triage_cli.py
```

Example phishing input:

```text
A user reported a suspicious email with an urgent password reset subject.
The email contains an unknown link.
The user_clicked status is unknown.
The credentials_entered status is unknown.
```

After entering the alert, press Enter on an empty line.

The CLI will:

```text
1. Receive the alert text
2. Retrieve relevant knowledge base documents
3. Build retrieved context
4. Build the SOC analyst answer prompt
5. Save the result into outputs/answer_prompt.txt
```

Example source output:

```text
[3] İlgili bilgi kaynakları bulundu:

- T1566_phishing.md
  Yol: knowledge_base\mitre\T1566_phishing.md
  Tür: MITRE ATT&CK tekniği özeti
  Kaynak eşleşme skoru: 17

- email_investigation_fields.md
  Yol: knowledge_base\investigation_notes\email_investigation_fields.md
  Tür: Investigation notes / bakılacak alanlar
  Kaynak eşleşme skoru: 15
```

The displayed source score is not an attack probability. It is only a keyword-based source matching score between the alert text and the knowledge base documents.

---

## Example Answer Format

The final SOC triage response is expected to follow this structure:

```text
# Olay Özeti

# Olası Yorum / Hipotez

# MITRE ATT&CK Eşleşmesi

# Bu Yorumu Destekleyen Kanıtlar

# Eksik Bilgiler

# İlk Kontrol Adımları

# Önerilen İlk Müdahale

# False Positive İhtimali

# Kullanılan Kaynaklar

# Güven Düzeyi
```

---

## Current Limitations

This is an educational prototype.

Current limitations:

- The retriever uses simple keyword matching.
- The source score is not an attack probability.
- The project does not yet use embeddings or a vector database.
- LLM response generation is not fully automated yet.
- `sample_answer_bruteforce.md` is a manually prepared reference output.
- No real company logs or sensitive data are used.
- The project does not connect to SIEM, EDR, Wazuh, or a production SOC system.
- The assistant does not perform automatic remediation.

---

## Safety Notes

This project is defensive and educational.

It does not provide:

- Exploit code
- Malware code
- Credential theft instructions
- Automatic attack execution
- Real company incident data

All sample alerts are synthetic and safe for demo purposes.

---

## Data Sources and Attribution

This project uses simplified educational notes inspired by public cybersecurity knowledge sources such as:

- MITRE ATT&CK concepts
- NIST incident response concepts
- Custom SOC playbooks written for this project

MITRE ATT&CK is a knowledge base maintained by The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

---

## Roadmap

Planned improvements:

- Add automated local LLM response generation
- Improve the final output format into a SOC Analyst Coach style
- Add richer brute force knowledge base content
- Add richer phishing and PowerShell investigation content
- Add more sample alerts with low, medium, and high risk examples
- Improve retrieval with embeddings
- Add better scoring and source ranking
- Add a simple web UI
- Add more SOC playbooks and investigation notes

---

## Status

```text
Knowledge base design: done
Brute force knowledge line: done
Phishing knowledge line: done
Suspicious PowerShell knowledge line: done
Retriever: working
Context builder: working
Answer prompt builder: working
Demo pipeline: working
Interactive CLI: working
LLM integration: next step
```