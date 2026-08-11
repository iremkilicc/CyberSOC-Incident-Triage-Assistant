# CyberSOC QML — Official Frontend

Qt Quick / QML (PySide6) is the **official product UI** for CyberSOC.
This folder is the supported frontend; the older Tkinter shell is legacy
reference only.

## Stage 5 (current)

- `main.py` registers a `BackendBridge` QObject as `backend`
- Analyze runs `LocalRAGEngine` (Foundry Local + RAG)
- **Per-card prompts**: one retrieval, then six model calls
  (`card_prompts.py` / `card_analyzer.py`)
- Investigation history uses SQLite via `conversation_service`
- Regenerate replaces the last assistant message in the same investigation

## Cards

1. Key Evidence  
2. MITRE ATT&CK Mapping  
3. Analyst Actions  
4. AI Incident Analysis  
5. Correlated Sources (retrieval)  
6. Timeline  

## Start

Every run: `START_CYBERSOC.bat` — it installs `.venv-qml` on first use,
starts Foundry Local and opens the QML window.

Troubleshooting: `START_CYBERSOC.bat debug` — keeps a console open and prints
`qml_preview_error.log` on exit.

Wait for **RAG READY** before submitting an alert.
