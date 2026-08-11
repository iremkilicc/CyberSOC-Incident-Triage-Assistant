"""Python ↔ QML bridge for the official CyberSOC frontend."""

from __future__ import annotations

import json
import sys
import traceback
from datetime import datetime
from pathlib import Path
from threading import Event, Thread

from PySide6.QtCore import QObject, Property, Signal, Slot

QML_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = QML_DIR.parent
SRC_DIR = PROJECT_ROOT / "src"

for path in (QML_DIR, SRC_DIR):
    text = str(path)
    if text not in sys.path:
        sys.path.insert(0, text)

from card_analyzer import AnalysisCancelled, analyze_with_card_prompts  # noqa: E402
from card_mapper import load_assistant_payload  # noqa: E402
from conversation_service import (  # noqa: E402
    add_message,
    create_conversation,
    delete_conversation,
    get_messages,
    list_conversations_with_last_reply,
    rename_conversation,
    replace_last_assistant_message,
)
from database import get_connection, initialize_database  # noqa: E402
from local_rag_engine import LocalRAGEngine  # noqa: E402


RISK_DEFAULTS = {
    "CRITICAL": ("#ff3e52", 92),
    "HIGH": ("#ff7a3d", 81),
    "MEDIUM": ("#ffb22e", 64),
    "LOW": ("#52d889", 34),
}
PENDING_BADGE = {"risk": "PENDING", "riskColor": "#5f788e", "score": 0, "title": ""}


def _iso_short(value: str | None) -> str:
    if not value:
        return "—"
    return value.replace("T", " ")[:16]


def _kb_stats() -> tuple[int, int]:
    """Count indexed knowledge-base chunks and source documents."""
    connection = get_connection()
    try:
        initialize_database(connection)
        chunks = connection.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
        documents = connection.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
        return int(chunks), int(documents)
    finally:
        connection.close()


def _history_badge(last_reply: str | None) -> dict[str, object]:
    """Read the risk badge of a conversation from its stored assistant payload."""
    text = (last_reply or "").strip()
    if not text.startswith("{"):
        return dict(PENDING_BADGE)

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return dict(PENDING_BADGE)
    if not isinstance(payload, dict):
        return dict(PENDING_BADGE)

    risk = str(payload.get("activeRisk") or "").strip().upper()
    if risk not in RISK_DEFAULTS:
        return dict(PENDING_BADGE)

    default_color, default_score = RISK_DEFAULTS[risk]
    try:
        score = int(payload.get("activeScore", default_score))
    except (TypeError, ValueError):
        score = default_score

    return {
        "risk": risk,
        "riskColor": str(payload.get("activeRiskColor") or "").strip() or default_color,
        "score": max(0, min(100, score)),
        "title": str(payload.get("activeTitle") or "").strip(),
    }


def _risk_icon(title: str) -> str:
    lowered = title.lower()
    if "powershell" in lowered:
        return "icon_powershell.svg"
    if "phish" in lowered:
        return "icon_phishing.svg"
    if "lsass" in lowered or "credential dump" in lowered or "minidump" in lowered:
        return "icon_credential_dumping.svg"
    if "business email" in lowered or "mailbox" in lowered or "forwarding" in lowered:
        return "icon_bec.svg"
    if "brute" in lowered or "failed" in lowered or "login" in lowered:
        return "icon_bruteforce.svg"
    if "exfil" in lowered:
        return "icon_data_exfiltration.svg"
    if "oauth" in lowered:
        return "icon_oauth_abuse.svg"
    return "icon_bruteforce.svg"


class BackendBridge(QObject):
    modelsReadyChanged = Signal()
    modelStatusChanged = Signal()
    analysisRunningChanged = Signal()
    analysisStateChanged = Signal()
    historyJsonChanged = Signal()
    resultJsonChanged = Signal()
    activeConversationIdChanged = Signal()
    incidentMetaChanged = Signal()
    kbStatsChanged = Signal()
    errorOccurred = Signal(str)
    analysisCompleted = Signal()
    historyReloaded = Signal()

    # Internal marshaling from worker threads → GUI thread
    _uiModelStatus = Signal(str)
    _uiModelsReady = Signal(str)
    _uiModelsFailed = Signal(str)
    _uiAnalysisSuccess = Signal(str, str, str)
    _uiAnalysisFailure = Signal(str)
    _uiAnalysisCancelled = Signal()
    _uiAnalysisState = Signal(str)
    _uiKbStats = Signal(int, int)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._engine = LocalRAGEngine()
        self._models_ready = False
        self._model_status = "PREPARING LOCAL MODELS"
        self._analysis_running = False
        self._analysis_state = "WAITING FOR MODELS"
        self._history_json = "[]"
        self._result_json = "{}"
        self._active_conversation_id = ""
        self._incident_meta = "No active investigation"
        self._models_ready_event = Event()
        self._model_error: str | None = None
        self._last_query = ""
        self._cancel_requested = False
        self._kb_chunks = 0
        self._kb_status = "CHECKING"
        self._kb_subtitle = "Reading local index"

        self._uiModelStatus.connect(self._set_model_status)
        self._uiModelsReady.connect(self._on_models_ready)
        self._uiModelsFailed.connect(self._on_models_failed)
        self._uiAnalysisSuccess.connect(self._on_analysis_success)
        self._uiAnalysisFailure.connect(self._on_analysis_failure)
        self._uiAnalysisCancelled.connect(self._on_analysis_cancelled)
        self._uiAnalysisState.connect(self._set_analysis_state)
        self._uiKbStats.connect(self._on_kb_stats)

        # Defer warm-up slightly so QML Connections can attach
        from PySide6.QtCore import QTimer

        QTimer.singleShot(250, self.startWarmUp)

    def _get_models_ready(self) -> bool:
        return self._models_ready

    modelsReady = Property(bool, _get_models_ready, notify=modelsReadyChanged)

    def _get_model_status(self) -> str:
        return self._model_status

    modelStatus = Property(str, _get_model_status, notify=modelStatusChanged)

    def _get_analysis_running(self) -> bool:
        return self._analysis_running

    analysisRunning = Property(bool, _get_analysis_running, notify=analysisRunningChanged)

    def _get_analysis_state(self) -> str:
        return self._analysis_state

    analysisState = Property(str, _get_analysis_state, notify=analysisStateChanged)

    def _get_history_json(self) -> str:
        return self._history_json

    historyJson = Property(str, _get_history_json, notify=historyJsonChanged)

    def _get_result_json(self) -> str:
        return self._result_json

    resultJson = Property(str, _get_result_json, notify=resultJsonChanged)

    def _get_active_conversation_id(self) -> str:
        return self._active_conversation_id

    activeConversationId = Property(
        str,
        _get_active_conversation_id,
        notify=activeConversationIdChanged,
    )

    def _get_incident_meta(self) -> str:
        return self._incident_meta

    incidentMeta = Property(str, _get_incident_meta, notify=incidentMetaChanged)

    def _get_kb_status(self) -> str:
        return self._kb_status

    kbStatus = Property(str, _get_kb_status, notify=kbStatsChanged)

    def _get_kb_subtitle(self) -> str:
        return self._kb_subtitle

    kbSubtitle = Property(str, _get_kb_subtitle, notify=kbStatsChanged)

    def _get_kb_chunks(self) -> int:
        return self._kb_chunks

    kbChunks = Property(int, _get_kb_chunks, notify=kbStatsChanged)

    def _set_models_ready(self, value: bool) -> None:
        if self._models_ready != value:
            self._models_ready = value
            self.modelsReadyChanged.emit()

    @Slot(str)
    def _set_model_status(self, value: str) -> None:
        if self._model_status != value:
            self._model_status = value
            self.modelStatusChanged.emit()

    def _set_analysis_running(self, value: bool) -> None:
        if self._analysis_running != value:
            self._analysis_running = value
            self.analysisRunningChanged.emit()

    @Slot(str)
    def _set_analysis_state(self, value: str) -> None:
        if self._analysis_state != value:
            self._analysis_state = value
            self.analysisStateChanged.emit()

    def _set_history_json(self, value: str) -> None:
        self._history_json = value
        self.historyJsonChanged.emit()

    def _set_result_json(self, value: str) -> None:
        self._result_json = value
        self.resultJsonChanged.emit()

    def _set_active_conversation_id(self, value: str) -> None:
        if self._active_conversation_id != value:
            self._active_conversation_id = value
            self.activeConversationIdChanged.emit()

    def _set_incident_meta(self, value: str) -> None:
        if self._incident_meta != value:
            self._incident_meta = value
            self.incidentMetaChanged.emit()

    @Slot(int, int)
    def _on_kb_stats(self, chunks: int, documents: int) -> None:
        self._kb_chunks = chunks
        if chunks > 0:
            self._kb_status = f"{chunks} CHUNKS"
            self._kb_subtitle = f"{documents} documents indexed"
        else:
            self._kb_status = "EMPTY"
            self._kb_subtitle = "Run ingest_knowledge_base"
        self.kbStatsChanged.emit()

    @Slot()
    def startWarmUp(self) -> None:
        Thread(target=self._warm_models, daemon=True).start()
        self.reloadHistory()

    def _warm_models(self) -> None:
        try:
            self._uiKbStats.emit(*_kb_stats())
        except Exception:
            self._uiKbStats.emit(0, 0)

        try:

            def progress(message: str) -> None:
                self._uiModelStatus.emit(str(message))

            progress("1/2 · Preparing embedding model…")
            self._engine.warm_up(progress_callback=progress)
            alias = self._engine.active_chat_alias or "local model"
            self._uiModelsReady.emit(alias)
        except Exception as error:
            self._uiModelsFailed.emit(str(error))

    @Slot(str)
    def _on_models_ready(self, alias: str) -> None:
        self._model_error = None
        self._set_models_ready(True)
        self._set_model_status(f"RAG READY · {alias}")
        self._set_analysis_state("READY FOR INCIDENT INPUT")
        self._models_ready_event.set()

    @Slot(str)
    def _on_models_failed(self, details: str) -> None:
        self._model_error = details
        self._set_models_ready(False)
        self._set_model_status("MODEL PREPARATION FAILED")
        self._set_analysis_state("MODEL ERROR")
        self._models_ready_event.set()
        self.errorOccurred.emit(details)

    @Slot()
    def reloadHistory(self) -> None:
        try:
            conversations = list_conversations_with_last_reply(limit=40)
            payload = []
            for item in conversations:
                title = item.get("title") or "Investigation"
                badge = _history_badge(item.get("last_reply"))
                payload.append(
                    {
                        "id": item["id"],
                        "title": title,
                        "time": _iso_short(item.get("updated_at") or item.get("created_at")),
                        "risk": badge["risk"],
                        "riskColor": badge["riskColor"],
                        "score": badge["score"],
                        "icon": _risk_icon(str(badge["title"]) or title),
                    }
                )
            self._set_history_json(json.dumps(payload, ensure_ascii=False))
            self.historyReloaded.emit()
        except Exception as error:
            self.errorOccurred.emit(f"History load failed: {error}")

    @Slot(str)
    def selectConversation(self, conversation_id: str) -> None:
        conversation_id = (conversation_id or "").strip()
        if not conversation_id:
            return
        self._set_active_conversation_id(conversation_id)
        try:
            messages = get_messages(conversation_id)
            latest_user = next(
                (m["content"] for m in reversed(messages) if m.get("role") == "user"),
                "",
            )
            latest_assistant = next(
                (m["content"] for m in reversed(messages) if m.get("role") == "assistant"),
                "",
            )
            self._set_incident_meta(
                f"ID: {conversation_id[:12].upper()}   ·   MESSAGES: {len(messages)}"
            )
            if latest_assistant:
                mapped = load_assistant_payload(
                    latest_user or "Loaded investigation",
                    latest_assistant,
                )
                self._last_query = latest_user
                self._set_result_json(json.dumps(mapped, ensure_ascii=False))
                self.analysisCompleted.emit()
                self._set_analysis_state("LOADED FROM HISTORY")
            else:
                self._set_analysis_state("EMPTY INVESTIGATION")
        except Exception as error:
            self.errorOccurred.emit(f"Could not open investigation: {error}")

    @Slot()
    def newInvestigation(self) -> None:
        self._set_active_conversation_id("")
        self._last_query = ""
        self._set_incident_meta("New investigation · not saved until Analyze")
        self._set_result_json("{}")
        self._set_analysis_state("READY FOR INCIDENT INPUT")

    @Slot(str)
    def renameActive(self, title: str) -> None:
        conversation_id = self._active_conversation_id
        if not conversation_id:
            return
        try:
            rename_conversation(conversation_id, title)
            self.reloadHistory()
        except Exception as error:
            self.errorOccurred.emit(f"Rename failed: {error}")

    @Slot()
    def deleteActive(self) -> None:
        conversation_id = self._active_conversation_id
        if not conversation_id:
            return
        try:
            delete_conversation(conversation_id)
            self.newInvestigation()
            self.reloadHistory()
        except Exception as error:
            self.errorOccurred.emit(f"Delete failed: {error}")

    @Slot(str, bool)
    def analyze(self, text: str, attach_context: bool) -> None:
        query = " ".join((text or "").split())
        if not query:
            self.errorOccurred.emit("Enter an alert or incident finding to analyze.")
            return
        if len(query) > 6000:
            self.errorOccurred.emit("Query is too long (max 6000 characters).")
            return
        if self._analysis_running:
            return
        if self._model_error:
            self.errorOccurred.emit(self._model_error)
            return

        self._cancel_requested = False
        self._set_analysis_running(True)
        self._set_analysis_state("CORRELATING LOCAL EVIDENCE")
        Thread(
            target=self._analyze_worker,
            args=(query, attach_context, False),
            daemon=True,
        ).start()

    @Slot()
    def regenerate(self) -> None:
        if not self._last_query:
            self.errorOccurred.emit("Nothing to regenerate yet.")
            return
        if self._analysis_running:
            return
        self._cancel_requested = False
        self._set_analysis_running(True)
        self._set_analysis_state("REGENERATING ANALYSIS")
        Thread(
            target=self._analyze_worker,
            args=(self._last_query, True, True),
            daemon=True,
        ).start()

    @Slot()
    def cancelAnalysis(self) -> None:
        """Ask the worker to stop once the running card prompt returns."""
        if not self._analysis_running or self._cancel_requested:
            return
        self._cancel_requested = True
        self._set_analysis_state("CANCELLING AFTER CURRENT CARD")

    def _analyze_worker(
        self,
        query: str,
        attach_context: bool,
        replace_last: bool,
    ) -> None:
        try:
            self._models_ready_event.wait(timeout=600)
            if self._model_error:
                raise RuntimeError(self._model_error)
            if not self._models_ready:
                raise RuntimeError("Local models are still preparing.")

            conversation_id = self._active_conversation_id
            if not conversation_id:
                title = query[:72] + ("…" if len(query) > 72 else "")
                conversation_id = create_conversation(title)
                self._active_conversation_id = conversation_id

            history: list[dict[str, str]] = []
            if attach_context and conversation_id:
                history = get_messages(conversation_id, limit=20)

            if not replace_last:
                add_message(conversation_id, "user", query)

            def card_progress(message: str) -> None:
                self._uiAnalysisState.emit(str(message))

            mapped = analyze_with_card_prompts(
                self._engine,
                query,
                history=history,
                progress_callback=card_progress,
                should_cancel=lambda: self._cancel_requested,
            )
            answer = json.dumps(mapped, ensure_ascii=False)

            if replace_last:
                replaced = replace_last_assistant_message(conversation_id, answer)
                if not replaced:
                    add_message(conversation_id, "assistant", answer)
            else:
                add_message(conversation_id, "assistant", answer)

            meta = (
                f"ID: {conversation_id[:12].upper()}   ·   "
                f"UPDATED: {datetime.now().strftime('%d %b %Y, %H:%M')}"
            )
            self._uiAnalysisSuccess.emit(query, answer, meta)
        except AnalysisCancelled:
            self._uiAnalysisCancelled.emit()
        except Exception as error:
            details = str(error) or traceback.format_exc()
            self._uiAnalysisFailure.emit(details)

    @Slot()
    def _on_analysis_cancelled(self) -> None:
        self._cancel_requested = False
        self._set_analysis_running(False)
        self._set_analysis_state("ANALYSIS CANCELLED")
        self.reloadHistory()

    @Slot(str, str, str)
    def _on_analysis_success(self, query: str, payload: str, meta: str) -> None:
        self._cancel_requested = False
        self._last_query = query
        if self._active_conversation_id:
            self.activeConversationIdChanged.emit()
        self._set_result_json(payload)
        self._set_incident_meta(meta)
        self._set_analysis_running(False)
        self._set_analysis_state("6-CARD LOCAL ANALYSIS COMPLETE")
        self.reloadHistory()
        self.analysisCompleted.emit()

    @Slot(str)
    def _on_analysis_failure(self, details: str) -> None:
        self._cancel_requested = False
        self._set_analysis_running(False)
        self._set_analysis_state("ANALYSIS FAILED")
        self.errorOccurred.emit(details)
