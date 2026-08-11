# Knowledge Base Sources and Provenance

The Markdown documents in `knowledge_base/` are original educational summaries
written for this project. They are not verbatim copies of the official sources.
The summaries simplify incident-triage concepts for a junior SOC analyst and
must not be treated as authoritative replacements for the referenced material.

## Official References

| Local topic | Official reference | Local use |
| --- | --- | --- |
| Brute Force | [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/) | Technique context and triage vocabulary |
| Phishing | [MITRE ATT&CK T1566](https://attack.mitre.org/techniques/T1566/) | Technique context and email investigation vocabulary |
| Command and Scripting Interpreter | [MITRE ATT&CK T1059](https://attack.mitre.org/techniques/T1059/) | General script and command execution context |
| PowerShell | [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell-specific defensive context |
| Incident Response | [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) | General incident-response lifecycle and considerations |

## Project-authored Material

The following are project-authored educational material:

- `knowledge_base/playbooks/*.md`
- `knowledge_base/investigation_notes/*.md`
- `knowledge_base/sample_alerts/*.json`

Sample alerts use synthetic or documentation-reserved values and contain no
real organizational telemetry.

## Attribution and License Notes

- MITRE ATT&CK content is subject to MITRE's terms of use and ATT&CK licensing.
- NIST publications are United States government publications; consult the
  publication page for citation and use guidance.
- This repository should preserve links and attribution when the knowledge base
  is expanded or redistributed.

Last source review: 2026-07-12.
