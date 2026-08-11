# CyberSOC Incident Triage Assistant

CyberSOC is a native Windows desktop application for local, evidence-backed
SOC incident triage. It combines Microsoft Foundry Local models, a local
cybersecurity knowledge base, persistent SQLite investigation history, and a
structured analyst response.

The application runs locally and does not require a browser, cloud API, SIEM,
or EDR connection.

## Official frontend

**Qt Quick / QML (PySide6)** is the official product UI.

- Entry: `qml_preview/` via `START_CYBERSOC.bat`
- Marked SOC shell: sidebar, investigation history, supported scenarios
- Animated risk radar and English analyst workspace
- Six structured, independently scrollable analysis cards:
  - Key Evidence
  - MITRE ATT&CK Mapping
  - Analyst Actions
  - AI Incident Analysis
  - Correlated Sources
  - Timeline
- Brand assets (logo, incident icons, system icons) and Windows app icon
- Live Foundry Local RAG wired through `BackendBridge`
- Per-card prompts: one retrieval + six local model calls
- SQLite investigation history (create / rename / delete / reload) with the
  risk badge of each investigation restored from its stored analysis
- Knowledge-base and model status chips read real local state (indexed chunk
  count, model readiness) instead of fixed labels
- A running analysis can be cancelled between two card prompts

### Legacy UI (not official)

`desktop_app.py` / `ui_components.py` (Tkinter) remain as the earlier
RAG-connected desktop shell for reference and regression tests. New UI work
targets QML only.

## Supported scenarios

CyberSOC currently contains seven tested scenario families, and the QML sidebar
exposes exactly these seven as one-click scenarios:

1. Phishing
2. Brute Force
3. Suspicious PowerShell
4. OAuth Abuse
5. Business Email Compromise (BEC)
6. Data Exfiltration
7. Credential Dumping

Each family has a matching playbook under `knowledge_base/playbooks/`, so a
sidebar scenario always resolves to real retrieved guidance.

## Architecture

The official QML frontend runs one retrieval followed by six card prompts:

```text
Alert or follow-up finding
          |
          v
Qwen3 local query embedding
          |
          v
SQLite cosine retrieval ----> Local playbooks and investigation notes
          |
          v
Six Foundry Local card prompts (evidence, MITRE, actions,
analysis, sources, timeline) over the same retrieved context
          |
          v
Merged card payload + source references
          |
          v
Persistent investigation timeline
```

The legacy Tkinter shell and `scripts/chat_cli.py` use the older single
structured prompt in `src/rag_service.py` instead.

Core modules:

```text
qml_preview/main.py            Official QML app entry (PySide6)
qml_preview/backend_bridge.py  QObject bridge to RAG + SQLite
qml_preview/card_prompts.py    Per-card prompt lenses (6)
qml_preview/card_analyzer.py   Retrieve once + six card completions
qml_preview/card_mapper.py     Card JSON → QML payload
qml_preview/qml/               Qt Quick UI and components
src/database.py                SQLite schema and embedding serialization
src/conversation_service.py    Conversation and message persistence
src/ingest_knowledge_base.py   Markdown ingestion and chunking
src/local_rag_engine.py        Foundry model lifecycle and response pipeline
src/vector_retriever.py        Semantic retrieval
src/rag_service.py             Scenario logic and grounded response formatting
desktop_app.py                 Legacy Tkinter shell (reference)
ui_components.py               Legacy Tkinter radar/cards (reference)
```

## Requirements

### Official QML UI

- Windows 11
- Python 3.12+ (64-bit; 3.13 preferred)
- Microsoft Foundry Local
- Approximately 16 GB RAM recommended
- PySide6 + `foundry-local-sdk-winml` (`requirements-qml.txt`)

## Windows setup

Install 64-bit Python 3.12 or newer with the Python launcher enabled, then
install Microsoft Foundry Local:

Install Foundry Local:

```powershell
winget install Microsoft.FoundryLocal
```

### Legacy Tkinter shell (reference)

- Same Foundry Local requirement
- Uses `.venv` + `requirements.txt`

## First run

The first launch creates `.venv-qml`, installs pinned dependencies, starts
Foundry Local, and builds the knowledge index from Markdown when the sanitized
index is absent. Initial model downloads can take several minutes.

## START_CYBERSOC.bat usage

Official frontend:

```text
Double-click START_CYBERSOC.bat
```

The same script handles the first start and every later start: it verifies
Foundry Local, creates `.venv-qml` and installs `requirements-qml.txt` when
they are missing, starts the Foundry server, and opens the QML window.

Troubleshooting — run it with the `debug` argument to keep a console open and
print `qml_preview_error.log` when the app exits:

```powershell
.\START_CYBERSOC.bat debug
```

Wait for the QML footer / RAG chip to show **READY** before Analyze.
The first run may download local models.

Legacy Tkinter + RAG shell (reference only):

```text
Double-click KUR_VE_BASLAT.bat   (first start)
Double-click START_DESKTOP.bat   (later starts)
```

## Running tests

Official model-free QML/backend regression checks:

```powershell
.\.venv-qml\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv-qml\Scripts\python.exe -m pytest -q
```

The same suite runs without pytest via `python -m unittest discover -s tests`.
The Tkinter source check under `tests/legacy/` is not part of the official QML
regression suite.

Optional local-model checks:

```powershell
.\.venv\Scripts\python.exe scripts\test_vector_retrieval.py
.\.venv\Scripts\python.exe scripts\test_rag_pipeline.py
.\.venv\Scripts\python.exe scripts\test_rag_quality.py
```

## Local data and privacy

- CyberSOC provides defensive triage guidance only.
- It never automatically blocks an IP, disables an account, deletes a file,
  or terminates a process.
- Retrieved documents are treated as untrusted context.
- Models, embeddings, the knowledge base, and investigation history stay local.
- Investigation history is stored in
  `%LOCALAPPDATA%\CyberSOC\cybersoc_history.db` and is not included in clean
  repository or release artifacts.
- `data/knowledge_index.db` contains sanitized knowledge documents and
  embeddings only; it has no conversation or message tables.

## Database lifecycle

The per-user history schema is created automatically. Initialization never
clears an existing database. Older local installations are migrated by copying
history from `data/cybersoc.db`; that legacy database is not changed or deleted.
The knowledge index can be rebuilt from `knowledge_base/**/*.md` with
`python src\ingest_knowledge_base.py` while Foundry Local is available.

## Creating a clean release

```powershell
.\.venv-qml\Scripts\python.exe scripts\build_release.py dist\CyberSOC-clean.zip
```

The allowlist builder rejects virtual environments, caches, logs, `.env`,
runtime history databases, hardcoded user paths, and common embedded-secret
patterns. Only `data/knowledge_index.db` is permitted from the data directory.

## Scope

This is an educational and portfolio prototype. It is not a production SOC
decision engine and has no live SIEM/EDR integration, access-control layer, or
organization-specific approval workflow.
