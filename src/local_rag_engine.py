from __future__ import annotations

from dataclasses import dataclass
from threading import Lock

from foundry_local_sdk import Configuration, FoundryLocalManager

from database import get_connection, initialize_database
from rag_service import (
    FALLBACK_CHAT_MODEL_ALIAS,
    PRIMARY_CHAT_MODEL_ALIAS,
    RAGResponse,
    answer_meets_quality_bar,
    answer_respects_confirmed_facts,
    build_safe_fallback_response,
    detect_security_scenario,
    filter_results_by_scenario,
    generate_grounded_answer,
    resolve_security_scenario,
)
from vector_retriever import (
    DEFAULT_MIN_SIMILARITY,
    EMBEDDING_MODEL_ALIAS,
    VectorRetriever,
)


SCENARIO_MIN_SIMILARITY = 0.54


@dataclass(frozen=True)
class EngineResult:
    model_alias: str | None
    response: RAGResponse


class LocalRAGEngine:
    def __init__(
        self,
        app_name: str = "CyberSOC-Local-Assistant",
        primary_chat_alias: str = PRIMARY_CHAT_MODEL_ALIAS,
        fallback_chat_alias: str = FALLBACK_CHAT_MODEL_ALIAS,
    ) -> None:
        config = Configuration(app_name=app_name)
        FoundryLocalManager.initialize(config)
        self.manager = FoundryLocalManager.instance
        self._lock = Lock()
        self._embedding_model = None
        self._embedding_client = None
        self._chat_models: dict[str, tuple[object, object]] = {}
        self.primary_chat_alias = primary_chat_alias
        self.fallback_chat_alias = fallback_chat_alias
        self.active_chat_alias = primary_chat_alias

    def _ensure_embedding_model(self):
        if self._embedding_model is None:
            print(f"Embedding modeli hazırlanıyor: {EMBEDDING_MODEL_ALIAS}")
            model = self.manager.catalog.get_model(EMBEDDING_MODEL_ALIAS)
            model.download()
            model.load()
            self._embedding_model = model
            self._embedding_client = model.get_embedding_client()

        return self._embedding_client

    def _search(
        self,
        query: str,
        top_k: int,
        scenario: str | None = None,
    ) -> list:
        connection = get_connection()
        initialize_database(connection)

        try:
            retriever = VectorRetriever(
                connection,
                self._ensure_embedding_model(),
            )
            return retriever.search(
                query,
                top_k=top_k,
                min_similarity=None,
                scenario=(
                    scenario
                    if scenario not in {None, "general"}
                    else None
                ),
            )
        finally:
            connection.close()

    def _prepare_chat_model(self, alias: str):
        if alias not in self._chat_models:
            print(f"Chat modeli hazırlanıyor: {alias}")
            model = self.manager.catalog.get_model(alias)

            try:
                model.download()
                model.load()
                client = model.get_chat_client()
                client.settings.temperature = 0.0
                client.settings.max_tokens = 320
                self._chat_models[alias] = (model, client)
            except Exception:
                try:
                    model.unload()
                except Exception:
                    pass
                raise

        return self._chat_models[alias]

    @staticmethod
    def _is_retryable_format_error(error: Exception) -> bool:
        message = str(error).casefold()
        return "json" in message or "ayrıştırılamadı" in message

    def _generate_with_retry(
        self,
        query: str,
        search_results: list,
        chat_client,
        history: list[dict[str, str]],
    ) -> RAGResponse:
        return generate_grounded_answer(
            query,
            search_results,
            chat_client,
            history=history,
        )

    def _generate(
        self,
        query: str,
        search_results: list,
        history: list[dict[str, str]],
    ) -> EngineResult:
        active_alias = self.active_chat_alias
        _, client = self._prepare_chat_model(active_alias)

        try:
            response = self._generate_with_retry(
                query,
                search_results,
                client,
                history,
            )

            if not answer_meets_quality_bar(
                query,
                response.answer,
                history=history,
            ) or not answer_respects_confirmed_facts(
                query,
                response.answer,
                history=history,
            ):
                print(
                    "Model cevabı kalite veya doğrulanmış bilgi kontrolünü "
                    "geçemedi; bağlama duyarlı güvenli cevap oluşturuluyor."
                )
                response = build_safe_fallback_response(
                    query,
                    search_results,
                    history=history,
                )

            return EngineResult(active_alias, response)
        except Exception as error:
            message = str(error).casefold()

            if self._is_retryable_format_error(error):
                print(
                    "Model yapılandırılmış cevap veremedi; güvenli ve "
                    "kaynaklı yedek cevap oluşturuluyor."
                )
                return EngineResult(
                    active_alias,
                    build_safe_fallback_response(
                        query,
                        search_results,
                        history=history,
                    ),
                )

            if "cancel" not in message:
                raise

            print(
                f"{active_alias} cevap üretemedi; "
                f"{self.fallback_chat_alias} modeline geçiliyor."
            )

            if active_alias == self.fallback_chat_alias:
                return EngineResult(
                    active_alias,
                    build_safe_fallback_response(
                        query,
                        search_results,
                        history=history,
                    ),
                )

            _, fallback_client = self._prepare_chat_model(
                self.fallback_chat_alias
            )
            self.active_chat_alias = self.fallback_chat_alias

            try:
                response = self._generate_with_retry(
                    query,
                    search_results,
                    fallback_client,
                    history,
                )
            except Exception as fallback_error:
                if not self._is_retryable_format_error(fallback_error):
                    raise

                print(
                    "Fallback model yapılandırılmış cevap veremedi; "
                    "güvenli ve kaynaklı yedek cevap oluşturuluyor."
                )
                response = build_safe_fallback_response(
                    query,
                    search_results,
                    history=history,
                )

            return EngineResult(self.fallback_chat_alias, response)

    def warm_up(self, progress_callback=None) -> None:
        with self._lock:
            if progress_callback:
                progress_callback("1/2 • Embedding modeli hazırlanıyor…")

            self._ensure_embedding_model()

            aliases = list(
                dict.fromkeys(
                    [self.primary_chat_alias, self.fallback_chat_alias]
                )
            )
            errors: list[str] = []

            for index, alias in enumerate(aliases, start=1):
                if progress_callback:
                    suffix = "" if index == 1 else " • yedek model deneniyor"
                    progress_callback(
                        f"2/2 • {alias} chat modeli hazırlanıyor{suffix}…"
                    )

                try:
                    self._prepare_chat_model(alias)
                    self.active_chat_alias = alias
                    return
                except Exception as error:
                    errors.append(f"{alias}: {error}")
                    print(f"{alias} hazırlanamadı: {error}")

            raise RuntimeError(
                "Hiçbir yerel chat modeli hazırlanamadı. "
                + " | ".join(errors)
            )

    def shutdown(self) -> None:
        with self._lock:
            for model, _ in self._chat_models.values():
                model.unload()

            self._chat_models.clear()

            if self._embedding_model is not None:
                self._embedding_model.unload()
                self._embedding_model = None
                self._embedding_client = None

    def answer(
        self,
        query: str,
        *,
        history: list[dict[str, str]] | None = None,
        top_k: int = 3,
    ) -> EngineResult:
        clean_query = " ".join(query.split())

        if not clean_query:
            raise ValueError("Lütfen bir SOC alarmı veya güvenlik sorusu yazın.")

        if len(clean_query) > 6000:
            raise ValueError("Sorgu çok uzun. En fazla 6000 karakter kullanın.")

        recent_user_context = ""

        if history:
            recent_user_messages = [
                message.get("content", "")
                for message in history
                if message.get("role") == "user"
            ]

            if recent_user_messages:
                recent_user_context = recent_user_messages[-1]

        detected_scenario = resolve_security_scenario(clean_query, history)

        retrieval_query = clean_query

        if recent_user_context:
            retrieval_query = (
                f"Önceki olay bağlamı: {recent_user_context}\n"
                f"Takip sorusu: {clean_query}"
            )

        with self._lock:
            raw_results = self._search(
                retrieval_query,
                max(top_k, 8),
                scenario=detected_scenario,
            )
            scenario_results = filter_results_by_scenario(
                raw_results,
                detected_scenario,
            )
            similarity_threshold = (
                SCENARIO_MIN_SIMILARITY
                if detected_scenario not in {None, "general"}
                else DEFAULT_MIN_SIMILARITY
            )
            results = [
                item
                for item in scenario_results
                if item.similarity >= similarity_threshold
            ][:top_k]

            if not results:
                basic_scenario = detected_scenario

                if basic_scenario:
                    basic_results = [
                        item
                        for item in scenario_results
                        if basic_scenario == "general"
                        or item.scenario in {basic_scenario, "general"}
                    ][:top_k]

                    if basic_results:
                        print(
                            "Sorgu SOC alanıyla ilgili ancak ayrıntısı az; "
                            "temel yönlendirme oluşturuluyor."
                        )
                        return EngineResult(
                            None,
                            build_safe_fallback_response(
                                clean_query,
                                basic_results,
                                history=history,
                            ),
                        )

                return EngineResult(
                    None,
                    generate_grounded_answer(clean_query, [], None),
                )

            return self._generate(clean_query, results, history or [])

    def retrieve_chunks(
        self,
        query: str,
        *,
        history: list[dict[str, str]] | None = None,
        top_k: int = 3,
    ) -> list:
        """Public retrieval helper for per-card QML analysis."""
        clean_query = " ".join(query.split())
        if not clean_query:
            raise ValueError("Lütfen bir SOC alarmı veya güvenlik sorusu yazın.")
        if len(clean_query) > 6000:
            raise ValueError("Sorgu çok uzun. En fazla 6000 karakter kullanın.")

        recent_user_context = ""
        if history:
            recent_user_messages = [
                message.get("content", "")
                for message in history
                if message.get("role") == "user"
            ]
            if recent_user_messages:
                recent_user_context = recent_user_messages[-1]

        detected_scenario = resolve_security_scenario(clean_query, history)
        retrieval_query = clean_query
        if recent_user_context:
            retrieval_query = (
                f"Önceki olay bağlamı: {recent_user_context}\n"
                f"Takip sorusu: {clean_query}"
            )

        with self._lock:
            raw_results = self._search(
                retrieval_query,
                max(top_k, 8),
                scenario=detected_scenario,
            )
            scenario_results = filter_results_by_scenario(
                raw_results,
                detected_scenario,
            )
            similarity_threshold = (
                SCENARIO_MIN_SIMILARITY
                if detected_scenario not in {None, "general"}
                else DEFAULT_MIN_SIMILARITY
            )
            results = [
                item
                for item in scenario_results
                if item.similarity >= similarity_threshold
            ][:top_k]

            if results:
                return results

            if detected_scenario:
                return [
                    item
                    for item in scenario_results
                    if detected_scenario == "general"
                    or item.scenario in {detected_scenario, "general"}
                ][:top_k]

            return scenario_results[:top_k]

    def complete_chat_messages(self, messages: list[dict[str, str]]) -> str:
        """Run one chat completion for a card-specific prompt."""
        with self._lock:
            alias = self.active_chat_alias or self.primary_chat_alias
            _, client = self._prepare_chat_model(alias)
            previous_max = getattr(client.settings, "max_tokens", 320)
            try:
                client.settings.max_tokens = max(int(previous_max or 320), 420)
                response = client.complete_chat(messages)
            finally:
                client.settings.max_tokens = previous_max

            if not response.choices:
                raise RuntimeError("Chat modeli cevap seçeneği döndürmedi.")

            content = response.choices[0].message.content or ""
            if not content.strip():
                raise RuntimeError("Chat modeli boş cevap döndürdü.")
            return content

