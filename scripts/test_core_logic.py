from __future__ import annotations

import math
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from database import deserialize_embedding, serialize_embedding  # noqa: E402
from ingest_knowledge_base import chunk_markdown, detect_scenario as detect_document_scenario  # noqa: E402
from rag_service import (  # noqa: E402
    SourceReference,
    answer_meets_quality_bar,
    answer_respects_confirmed_facts,
    build_bec_case_state,
    build_brute_force_case_state,
    build_cloud_identity_case_state,
    build_credential_dumping_case_state,
    build_data_exfiltration_case_state,
    build_phishing_case_state,
    build_powershell_case_state,
    build_safe_fallback_response,
    detect_security_scenario,
    filter_results_by_scenario,
    find_missing_sections,
    format_history,
    parse_structured_payload,
    render_structured_answer,
    sanitize_action,
)
from vector_retriever import (  # noqa: E402
    RetrievedChunk,
    cosine_similarity,
    format_query_for_embedding,
)


def main() -> None:
    checks: dict[str, bool] = {}

    original_vector = [0.25, -0.5, 1.0]
    restored_vector = deserialize_embedding(
        serialize_embedding(original_vector),
        len(original_vector),
    )
    checks["embedding_round_trip"] = all(
        math.isclose(left, right, rel_tol=1e-6)
        for left, right in zip(original_vector, restored_vector)
    )
    checks["cosine_identity"] = math.isclose(
        cosine_similarity([1.0, 0.0], [1.0, 0.0]),
        1.0,
    )
    checks["query_instruction"] = format_query_for_embedding(
        "  suspicious   login  "
    ).endswith("Query: suspicious login")

    chunks = chunk_markdown(
        "# Test\n\nIntro text.\n\n## Evidence\n\nCollect process data."
    )
    checks["markdown_chunking"] = (
        len(chunks) == 2
        and chunks[0]["chunk_index"] == 0
        and chunks[1]["heading"] == "Evidence"
    )
    checks["cloud_document_scenario"] = (
        detect_document_scenario(Path("T1528_steal_application_access_token.md"))
        == "cloud_identity_oauth"
        and detect_document_scenario(Path("cloud_identity_oauth_playbook.md"))
        == "cloud_identity_oauth"
    )
    checks["bec_document_scenario"] = (
        detect_document_scenario(Path("T1114_003_email_forwarding_rule.md"))
        == "bec_mailbox"
        and detect_document_scenario(Path("T1657_financial_theft.md"))
        == "bec_mailbox"
        and detect_document_scenario(Path("bec_mailbox_rule_playbook.md"))
        == "bec_mailbox"
        and detect_document_scenario(Path("bec_mailbox_investigation_fields.md"))
        == "bec_mailbox"
    )
    checks["data_exfiltration_document_scenario"] = (
        detect_document_scenario(Path("T1530_data_from_cloud_storage.md"))
        == "data_exfiltration"
        and detect_document_scenario(
            Path("T1560_T1567_002_archive_and_cloud_exfiltration.md")
        )
        == "data_exfiltration"
        and detect_document_scenario(Path("cloud_data_exfiltration_playbook.md"))
        == "data_exfiltration"
        and detect_document_scenario(Path("data_exfiltration_investigation_fields.md"))
        == "data_exfiltration"
    )
    checks["credential_dumping_document_scenario"] = (
        detect_document_scenario(Path("T1003_001_lsass_memory.md"))
        == "credential_dumping"
        and detect_document_scenario(Path("credential_dumping_playbook.md"))
        == "credential_dumping"
        and detect_document_scenario(
            Path("credential_dumping_investigation_fields.md")
        )
        == "credential_dumping"
    )

    payload = parse_structured_payload(
        """```json
        {
          "assessment": "Endpoint üzerinde olay gözlemlendi. [K9]",
          "risk_level": "Orta",
          "risk_reason": "Ek doğrulama gerekiyor.",
          "evidence_to_collect": ["Process tree", "Command line"],
          "actions": ["Logları koru"],
          "questions": ["İşlemi kim başlattı?"]
        }
        ```"""
    )
    sources = [
        SourceReference(
            label="K1",
            source_path="knowledge_base/example.md",
            heading="Evidence",
            scenario="general",
            similarity=0.75,
        )
    ]
    rendered = render_structured_answer(payload, sources)
    checks["structured_sections"] = not find_missing_sections(rendered)
    checks["invalid_citation_removed"] = "[K9]" not in rendered
    checks["valid_source_note"] = "[K1]" in rendered
    checks["unsafe_action_rewritten"] = "yeniden çalıştırmadan" in (
        sanitize_action("Şüpheli PowerShell komutunu tekrar çalıştır.")
    )
    checks["controlled_action_requires_approval"] = "yetkili onayıyla" in (
        sanitize_action("Endpoint'teki PowerShell sürecini durdur.")
    )
    history = format_history(
        [
            {"role": "user", "content": "İlk alarm"},
            {"role": "assistant", "content": "İlk değerlendirme"},
        ]
    )
    checks["conversation_history"] = (
        "Kullanıcı: İlk alarm" in history
        and "Asistan: İlk değerlendirme" not in history
    )
    fallback_response = build_safe_fallback_response(
        "Çok sayıda şüpheli e-posta geliyor.",
        [
            RetrievedChunk(
                chunk_id=1,
                document_id=1,
                chunk_index=0,
                similarity=0.70,
                source_path="knowledge_base/playbooks/phishing_playbook.md",
                title="Phishing Playbook",
                source_type="playbook",
                scenario="phishing",
                heading="Kısa Özet",
                content="Şüpheli e-posta inceleme rehberi.",
            )
        ],
    )
    checks["safe_phishing_fallback"] = (
        fallback_response.grounded
        and "Message-ID" in fallback_response.answer
        and "yeniden çalıştır" not in fallback_response.answer
    )
    checks["fallback_quality_bar"] = answer_meets_quality_bar(
        "Çok sayıda şüpheli e-posta geliyor.",
        fallback_response.answer,
    )
    checks["template_leak_rejected"] = not answer_meets_quality_bar(
        "Şüpheli e-posta bağlantılarını triaj et.",
        """## Ön Değerlendirme
en fazla iki kısa cümle

## Risk ve Gerekçe
**Orta:** en fazla iki kısa cümle

## Toplanacak Kanıtlar
- URL ve ekler

## Önerilen Aksiyonlar
- eğer kullanıcı bağlantıya tıkladıysan
- eğer şüpheli giriş oluştuysan

## Eksik Bilgiler / Takip Soruları
- eğer kullanıcı bağlantıya tıkladıysan?
""",
    )
    checks["basic_email_intent"] = (
        detect_security_scenario("Kanka bana çok fazla mail geliyor")
        == "phishing"
    )
    checks["basic_powershell_intent"] = (
        detect_security_scenario("PowerShell neden alarm verdi?")
        == "suspicious_powershell"
    )
    checks["basic_cloud_identity_intent"] = (
        detect_security_scenario("Entra ID impossible travel alarmını triaj et")
        == "cloud_identity_oauth"
        and detect_security_scenario("Şüpheli OAuth consent grant görüldü")
        == "cloud_identity_oauth"
    )
    checks["basic_bec_intent"] = (
        detect_security_scenario(
            "Finans mailboxında invoice iletilerini hedefleyen şüpheli inbox rule var"
        )
        == "bec_mailbox"
        and detect_security_scenario(
            "Tedarikçiye yeni IBAN içeren sahte ödeme mesajı gönderildi"
        )
        == "bec_mailbox"
    )
    checks["basic_data_exfiltration_intent"] = (
        detect_security_scenario(
            "SharePoint üzerinde 1200 dosyalık anormal toplu indirme görüldü"
        )
        == "data_exfiltration"
        and detect_security_scenario(
            "Bir ZIP arşivi kurum dışı buluta yüklendi; veri sızdırma şüphesi var"
        )
        == "data_exfiltration"
    )
    checks["basic_credential_dumping_intent"] = (
        detect_security_scenario(
            "EDR rundll32.exe sürecinin LSASS belleğine eriştiğini bildirdi"
        )
        == "credential_dumping"
        and detect_security_scenario(
            "C:\\Windows\\Temp\\lsass.dmp dosyası oluşturuldu"
        )
        == "credential_dumping"
    )
    checks["non_security_intent_rejected"] = (
        detect_security_scenario("Çikolatalı kek tarifi ver") is None
    )
    follow_up_query = (
        "Kullanıcı bağlantıya tıkladığını ama kimlik bilgisi "
        "girmediğini söyledi. Risk nasıl değişir?"
    )
    follow_up_response = build_safe_fallback_response(
        follow_up_query,
        [
            RetrievedChunk(
                chunk_id=2,
                document_id=1,
                chunk_index=1,
                similarity=0.68,
                source_path="knowledge_base/playbooks/phishing_playbook.md",
                title="Phishing Playbook",
                source_type="playbook",
                scenario="phishing",
                heading="Kullanıcı Etkileşimi",
                content="Tıklama sonrası endpoint ve kimlik doğrulama loglarını inceleyin.",
            )
        ],
        history=[
            {
                "role": "user",
                "content": "Şüpheli e-postalarda sahte giriş URL'leri var.",
            }
        ],
    )
    checks["follow_up_changes_risk"] = (
        "**Orta:**" in follow_up_response.answer
        and "URL yönlendirme zincirini" in follow_up_response.answer
        and "kimlik bilgisi girmediği" in follow_up_response.answer
        and "kimlik bilgisi girdi" not in follow_up_response.answer.split(
            "## Eksik Bilgiler / Takip Soruları"
        )[-1]
    )
    checks["follow_up_fact_guard"] = answer_respects_confirmed_facts(
        follow_up_query,
        follow_up_response.answer,
    )
    checks["generic_follow_up_rejected"] = not answer_respects_confirmed_facts(
        follow_up_query,
        "## Risk ve Gerekçe\n**Belirsiz:** Etkileşim bilinmiyor.",
    )
    mixed_results = [
        RetrievedChunk(
            chunk_id=3,
            document_id=1,
            chunk_index=0,
            similarity=0.68,
            source_path="phishing.md",
            title="Phishing",
            source_type="playbook",
            scenario="phishing",
            heading="Tıklama",
            content="Phishing içeriği",
        ),
        RetrievedChunk(
            chunk_id=4,
            document_id=2,
            chunk_index=0,
            similarity=0.65,
            source_path="brute_force.md",
            title="Brute Force",
            source_type="playbook",
            scenario="brute_force",
            heading="Login",
            content="Brute force içeriği",
        ),
    ]
    filtered_results = filter_results_by_scenario(mixed_results, "phishing")
    checks["cross_scenario_source_removed"] = (
        len(filtered_results) == 1
        and filtered_results[0].scenario == "phishing"
    )

    professional_chunk = RetrievedChunk(
        chunk_id=5,
        document_id=3,
        chunk_index=0,
        similarity=0.64,
        source_path="knowledge_base/playbooks/phishing_playbook.md",
        title="Phishing Playbook",
        source_type="playbook",
        scenario="phishing",
        heading="Email Authentication",
        content=(
            "SPF, DKIM ve DMARC sonuçları ile URL ve Return-Path "
            "alanlarını birlikte değerlendirin."
        ),
    )
    initial_phishing_query = (
        "Bir kullanıcıya son 20 dakika içinde farklı gönderenlerden 40 "
        "şüpheli e-posta ulaştı. Mesajlarda Microsoft 365 giriş sayfasına "
        "benzeyen bağlantılar bulunuyor. Kullanıcının bağlantılara tıklayıp "
        "tıklamadığı henüz bilinmiyor. Olayı triaj et."
    )
    initial_professional = build_safe_fallback_response(
        initial_phishing_query,
        [professional_chunk],
    )
    checks["professional_initial_triage"] = (
        "## Olay Sınıflandırması" in initial_professional.answer
        and "Microsoft 365" in initial_professional.answer
        and "40 şüpheli" in initial_professional.answer
        and "**Belirsiz:**" in initial_professional.answer
    )
    evidence_update_query = (
        "Header incelemesinde SPF fail, DKIM none ve DMARC fail görüldü. "
        "Return-Path alanı notice@micr0soft-support.com. Bağlantı "
        "microsoft-login-security[.]com alan adına gidiyor. Bu yeni "
        "bilgilerle değerlendirmeyi güncelle."
    )
    case_history = [{"role": "user", "content": initial_phishing_query}]
    updated_professional = build_safe_fallback_response(
        evidence_update_query,
        [professional_chunk],
        history=case_history,
    )
    updated_answer = updated_professional.answer
    checks["email_evidence_updates_verdict"] = (
        "**Kategori:** Phishing" in updated_answer
        and "**Analitik güven:** Yüksek" in updated_answer
        and "**Orta:**" in updated_answer
        and all(term in updated_answer for term in ("SPF", "DKIM", "DMARC"))
        and "notice@micr0soft-support.com" in updated_answer
        and "microsoft-login-security[.]com" in updated_answer
    )
    checks["email_evidence_fact_guard"] = answer_respects_confirmed_facts(
        evidence_update_query,
        updated_answer,
        history=case_history,
    )
    extracted_state = build_phishing_case_state(
        evidence_update_query,
        case_history,
    )
    checks["phishing_case_state"] = (
        extracted_state.email_count == 40
        and extracted_state.email_auth_failures == ("SPF", "DKIM", "DMARC")
        and extracted_state.return_path == "notice@micr0soft-support.com"
        and extracted_state.url_domain == "microsoft-login-security[.]com"
        and extracted_state.confirmed_phishing_indicators >= 2
    )

    credential_update_query = (
        "Kullanıcı bağlantıya tıkladığını ve açılan sahte Microsoft 365 sayfasına "
        "kurumsal parolasını yazdığını söyledi. Dosya indirmediğini belirtiyor. "
        "Risk seviyesini ve kontrolleri güncelle."
    )
    credential_history = [{"role": "user", "content": initial_phishing_query}]
    credential_update = build_safe_fallback_response(
        credential_update_query,
        [professional_chunk],
        history=credential_history,
    )
    checks["credential_phishing_escalation"] = (
        "Başarılı credential phishing" in credential_update.answer
        and "**Yüksek:**" in credential_update.answer
        and "kimlik bilgisi yazdığı doğrulandı" in credential_update.answer
    )

    account_takeover_query = (
        "Entra ID loglarında parola girişinden beş dakika sonra kullanıcıya ait "
        "olmayan yabancı bir IP adresinden başarılı oturum açma görüldü. Ardından "
        "yeni bir inbox forwarding kuralı oluşturuldu. Aynı e-posta 12 kullanıcıya "
        "daha ulaşmış. Değerlendirmeyi tekrar güncelle."
    )
    account_takeover_history = [
        {"role": "user", "content": initial_phishing_query},
        {"role": "user", "content": credential_update_query},
    ]
    takeover_state = build_phishing_case_state(
        account_takeover_query,
        account_takeover_history,
    )
    account_takeover = build_safe_fallback_response(
        account_takeover_query,
        [professional_chunk],
        history=account_takeover_history,
    )
    takeover_answer = account_takeover.answer
    takeover_questions = takeover_answer.split(
        "## Eksik Bilgiler / Takip Soruları"
    )[-1].split("**Genel kaynak dayanağı:**")[0]
    checks["account_takeover_state"] = (
        takeover_state.suspicious_login
        and takeover_state.forwarding_rule
        and takeover_state.multiple_recipients
        and takeover_state.additional_recipient_count == 12
    )
    checks["account_takeover_escalation"] = (
        "**Kritik:**" in takeover_answer
        and "yabancı IP adresinden başarılı oturum" in takeover_answer
        and "yönlendirme kuralı" in takeover_answer
        and "12 ek kullanıcıya" in takeover_answer
    )
    checks["known_facts_not_reasked"] = (
        "başka kullanıcılara da teslim edildi mi" not in takeover_questions
        and "yeni oturum, MFA bildirimi" not in takeover_questions
        and "Yabancı IP oturumunun cihaz kimliği" in takeover_questions
    )

    brute_chunk = RetrievedChunk(
        chunk_id=6,
        document_id=4,
        chunk_index=0,
        similarity=0.69,
        source_path="knowledge_base/playbooks/brute_force_playbook.md",
        title="Brute Force Playbook",
        source_type="playbook",
        scenario="brute_force",
        heading="Başarılı Login Sonrası Kontroller",
        content="Başarısız denemeleri başarılı oturum ve MFA kayıtlarıyla korele edin.",
    )
    brute_initial_query = (
        "Bir hesapta 10 dakika içinde 250 başarısız giriş görüldü. Denemeler "
        "18 farklı IP adresinden geldi. Başarılı giriş görülmedi. Olayı triaj et."
    )
    brute_initial = build_safe_fallback_response(
        brute_initial_query,
        [brute_chunk],
    )
    checks["professional_brute_force_initial"] = (
        "Olası brute force saldırısı" in brute_initial.answer
        and "250 başarısız giriş" in brute_initial.answer
        and "18 farklı kaynak IP" in brute_initial.answer
        and "**Orta:**" in brute_initial.answer
        and "Başarılı oturum görülmediği bildirildi" in brute_initial.answer
        and "başarılı bir oturum oluştu mu" not in brute_initial.answer
    )
    brute_escalation_query = (
        "Beş dakika sonra kullanıcıya ait olmayan yabancı IP adresinden başarılı "
        "oturum görüldü. Kullanıcı beklenmeyen MFA isteğini onayladığını söyledi. "
        "Değerlendirmeyi güncelle."
    )
    brute_history = [{"role": "user", "content": brute_initial_query}]
    brute_state = build_brute_force_case_state(
        brute_escalation_query,
        brute_history,
    )
    brute_escalation = build_safe_fallback_response(
        brute_escalation_query,
        [brute_chunk],
        history=brute_history,
    )
    checks["brute_force_state_memory"] = (
        brute_state.failed_attempts == 250
        and brute_state.time_window_minutes == 10
        and brute_state.source_ip_count == 18
        and brute_state.successful_login is True
        and brute_state.foreign_source
        and brute_state.mfa_approved is True
    )
    checks["brute_force_critical_escalation"] = (
        "Yüksek olasılıklı hesap ele geçirme" in brute_escalation.answer
        and "**Kritik:**" in brute_escalation.answer
        and "yabancı" in brute_escalation.answer.casefold()
        and "MFA isteğini onayladığı" in brute_escalation.answer
    )

    powershell_chunk = RetrievedChunk(
        chunk_id=7,
        document_id=5,
        chunk_index=0,
        similarity=0.72,
        source_path="knowledge_base/playbooks/suspicious_powershell_playbook.md",
        title="Suspicious PowerShell Playbook",
        source_type="playbook",
        scenario="suspicious_powershell",
        heading="EncodedCommand ve Ağ Davranışı",
        content="Komut, parent process, ağ, payload ve kalıcılık bulgularını korele edin.",
    )
    powershell_initial_query = (
        "WINWORD.EXE tarafından başlatılan powershell.exe -EncodedCommand komutu "
        "dış bir IP adresine bağlantı kurdu. Olayı triaj et."
    )
    powershell_initial = build_safe_fallback_response(
        powershell_initial_query,
        [powershell_chunk],
    )
    checks["professional_powershell_initial"] = (
        "Şüpheli PowerShell yürütmesi" in powershell_initial.answer
        and "**Yüksek:**" in powershell_initial.answer
        and "winword.exe" in powershell_initial.answer.casefold()
        and "kodlanmış" in powershell_initial.answer.casefold()
    )
    powershell_escalation_query = (
        "EDR sürecin payload indirdiğini ve rundll32 child process oluşturduğunu "
        "tespit etti. Ardından scheduled task ile kalıcılık oluşturuldu. Kullanıcı "
        "işlemi reddetti. Değerlendirmeyi güncelle."
    )
    powershell_history = [{"role": "user", "content": powershell_initial_query}]
    powershell_state = build_powershell_case_state(
        powershell_escalation_query,
        powershell_history,
    )
    powershell_escalation = build_safe_fallback_response(
        powershell_escalation_query,
        [powershell_chunk],
        history=powershell_history,
    )
    checks["powershell_state_memory"] = (
        powershell_state.encoded_command
        and powershell_state.suspicious_parent == "winword.exe"
        and powershell_state.external_connection
        and powershell_state.downloaded_payload
        and powershell_state.suspicious_child_process
        and powershell_state.persistence
        and powershell_state.security_detection
        and powershell_state.authorized_activity is False
    )
    checks["powershell_critical_escalation"] = (
        "Yüksek güvenli kötü amaçlı PowerShell etkinliği" in powershell_escalation.answer
        and "**Kritik:**" in powershell_escalation.answer
        and "kalıcılık" in powershell_escalation.answer.casefold()
        and "işlemi doğrulamadığı" in powershell_escalation.answer
    )

    powershell_user_update = (
        "Kullanıcı Word belgesini e-postadan açtığını ancak PowerShell komutu "
        "çalıştırmadığını söyledi. Bu yeni bilgiyle değerlendirmeyi güncelle."
    )
    powershell_payload_update = (
        "EDR telemetrisinde PowerShell sürecinin uzak sunucudan payload indirdiği "
        "ve ardından rundll32.exe child process oluşturduğu görüldü. Risk "
        "seviyesini ve kontrolleri güncelle."
    )
    powershell_persistence_update = (
        "İnceleme sırasında aynı endpoint üzerinde yeni bir scheduled task "
        "oluşturulduğu ve AMSI tarafından zararlı davranış tespiti üretildiği "
        "görüldü. Değerlendirmeyi tekrar güncelle."
    )
    powershell_scope_update = (
        "İndirilen dosyanın SHA256 değeri biliniyor ve aynı hash başka iki "
        "endpoint üzerinde daha tespit edildi. C2 bağlantıları da aynı dış IP "
        "adresine gidiyor. Olayın kapsamını ve öncelikli SOC aksiyonlarını güncelle."
    )
    powershell_full_history = [
        {"role": "user", "content": powershell_initial_query},
        {"role": "user", "content": powershell_user_update},
        {"role": "user", "content": powershell_payload_update},
        {"role": "user", "content": powershell_persistence_update},
    ]
    powershell_scope_state = build_powershell_case_state(
        powershell_scope_update,
        powershell_full_history,
    )
    powershell_scope_response = build_safe_fallback_response(
        powershell_scope_update,
        [powershell_chunk],
        history=powershell_full_history,
    )
    scope_answer = powershell_scope_response.answer
    scope_questions = scope_answer.split(
        "## Eksik Bilgiler / Takip Soruları"
    )[-1].split("**Genel kaynak dayanağı:**")[0]
    checks["powershell_campaign_state"] = (
        powershell_scope_state.authorized_activity is False
        and powershell_scope_state.document_from_email
        and powershell_scope_state.artifact_hash_known
        and powershell_scope_state.additional_endpoint_count == 2
        and powershell_scope_state.shared_c2_target
    )
    checks["powershell_campaign_scope"] = (
        "Çoklu endpointi etkileyen kötü amaçlı PowerShell kampanyası" in scope_answer
        and "en az 3 endpointte" in scope_answer
        and "2 ek endpoint" in scope_answer
        and "ortak C2" in scope_answer
    )
    checks["powershell_known_facts_not_reasked"] = (
        "işlemi doğruluyor mu" not in scope_questions
        and "Parent process'in belge" not in scope_questions
        and "Dış bağlantının hedefi" not in scope_questions
    )

    cloud_chunk = RetrievedChunk(
        chunk_id=8,
        document_id=6,
        chunk_index=0,
        similarity=0.74,
        source_path="knowledge_base/playbooks/cloud_identity_oauth_playbook.md",
        title="Cloud Identity and OAuth Playbook",
        source_type="playbook",
        scenario="cloud_identity_oauth",
        heading="Impossible Travel ve OAuth Consent",
        content=(
            "Konum anomalisi, consent grant, uygulama izinleri, token ve kaynak "
            "erişimini tek olay zaman çizelgesinde korele edin."
        ),
    )
    cloud_initial_query = (
        "Entra ID, İstanbul ve Amsterdam konumlarından 12 dakika arayla iki "
        "başarılı oturum için impossible travel alarmı üretti. Kullanıcının "
        "seyahat veya VPN durumu henüz bilinmiyor. Olayı triaj et."
    )
    cloud_initial = build_safe_fallback_response(
        cloud_initial_query,
        [cloud_chunk],
    )
    checks["professional_cloud_identity_initial"] = (
        "Olası impossible travel / kimlik anomalisi" in cloud_initial.answer
        and "12 dakika" in cloud_initial.answer
        and "**Orta:**" in cloud_initial.answer
        and "OAuth consent" in cloud_initial.answer
    )
    cloud_consent_query = (
        "Kullanıcı seyahat etmediğini ve VPN kullanmadığını söyledi. Entra audit "
        "loglarında yayıncısı doğrulanmamış \"Cloud Docs Sync\" adlı OAuth "
        "uygulamasına Mail.Read, Files.ReadWrite.All ve offline_access izinleri "
        "verildiği görüldü. Değerlendirmeyi güncelle."
    )
    cloud_initial_history = [{"role": "user", "content": cloud_initial_query}]
    cloud_consent_state = build_cloud_identity_case_state(
        cloud_consent_query,
        cloud_initial_history,
    )
    cloud_consent = build_safe_fallback_response(
        cloud_consent_query,
        [cloud_chunk],
        history=cloud_initial_history,
    )
    checks["cloud_oauth_consent_state"] = (
        cloud_consent_state.impossible_travel
        and cloud_consent_state.travel_window_minutes == 12
        and cloud_consent_state.user_confirmed_activity is False
        and cloud_consent_state.oauth_consent
        and cloud_consent_state.app_name == "Cloud Docs Sync"
        and cloud_consent_state.unverified_publisher
        and cloud_consent_state.risky_permissions
        == ("Files.ReadWrite.All", "Mail.Read")
        and cloud_consent_state.offline_access
    )
    checks["cloud_oauth_high_escalation"] = (
        "Şüpheli OAuth consent grant" in cloud_consent.answer
        and "**Yüksek:**" in cloud_consent.answer
        and "Cloud Docs Sync" in cloud_consent.answer
        and "Mail.Read" in cloud_consent.answer
        and "Files.ReadWrite.All" in cloud_consent.answer
        and "offline_access" in cloud_consent.answer
    )
    cloud_token_query = (
        "Uygulamanın refresh token kullanarak aynı yabancı IP adresinden 80 "
        "e-posta ve 25 dosyaya eriştiği doğrulandı. Risk seviyesini, olay "
        "kapsamını ve öncelikli aksiyonları güncelle."
    )
    cloud_full_history = [
        {"role": "user", "content": cloud_initial_query},
        {"role": "user", "content": cloud_consent_query},
    ]
    cloud_token_state = build_cloud_identity_case_state(
        cloud_token_query,
        cloud_full_history,
    )
    cloud_token_response = build_safe_fallback_response(
        cloud_token_query,
        [cloud_chunk],
        history=cloud_full_history,
    )
    cloud_answer = cloud_token_response.answer
    cloud_questions = cloud_answer.split(
        "## Eksik Bilgiler / Takip Soruları"
    )[-1].split("**Genel kaynak dayanağı:**")[0]
    checks["cloud_token_compromise_state"] = (
        cloud_token_state.oauth_consent
        and cloud_token_state.token_used
        and cloud_token_state.foreign_source
        and cloud_token_state.mail_access_count == 80
        and cloud_token_state.file_access_count == 25
    )
    checks["cloud_token_critical_escalation"] = (
        "OAuth consent abuse ile yüksek olasılıklı cloud account compromise"
        in cloud_answer
        and "**Kritik:**" in cloud_answer
        and "80 e-posta" in cloud_answer
        and "25 dosya" in cloud_answer
        and "refresh token" in cloud_answer.casefold()
    )
    checks["cloud_known_facts_not_reasked"] = (
        "seyahati veya kurumsal VPN kullanımını doğruluyor mu" not in cloud_questions
        and "Consent sonrasında refresh token" not in cloud_questions
        and "Mail.Read" not in cloud_questions
        and "Files.ReadWrite.All" not in cloud_questions
    )
    checks["cloud_fallback_quality_bar"] = answer_meets_quality_bar(
        cloud_token_query,
        cloud_answer,
        history=cloud_full_history,
    )
    checks["cloud_confirmed_fact_guard"] = answer_respects_confirmed_facts(
        cloud_token_query,
        cloud_answer,
        history=cloud_full_history,
    )

    exact_cloud_queries = [
        (
            "Aynı kullanıcı hesabında İstanbul ve Amsterdam kaynaklı iki başarılı "
            "oturum arasında yalnızca 8 dakika bulunuyor. Kullanıcı henüz bu "
            "oturumları doğrulamadı. Olayı triaj et."
        ),
        (
            "İncelemede kullanıcının doğrulanmamış “Cloud Docs Sync” adlı OAuth "
            "uygulamasına Mail.Read, Files.ReadWrite.All ve offline_access izinlerini "
            "verdiği görüldü. Değerlendirmeyi güncelle."
        ),
        (
            "Uygulamaya ait tokenın kullanıcıya ait olmayan yabancı IP adresinden "
            "kullanıldığı, 80 e-postaya eriştiği ve 25 dosya indirdiği doğrulandı. "
            "Kullanıcı uygulamayı tanımadığını söyledi. Değerlendirmeyi güncelle."
        ),
        (
            "Şimdiye kadar doğrulanan bulguları, olayın kapsamını ve öncelikli SOC "
            "aksiyonlarını tekrar özetle. Bildiğin bilgileri yeniden soru olarak sorma."
        ),
    ]
    exact_history: list[dict[str, str]] = []
    exact_responses = []

    for exact_query in exact_cloud_queries:
        exact_responses.append(
            build_safe_fallback_response(
                exact_query,
                [cloud_chunk],
                history=exact_history,
            )
        )
        exact_history.extend(
            [
                {"role": "user", "content": exact_query},
                {"role": "assistant", "content": exact_responses[-1].answer},
            ]
        )

    exact_summary = exact_responses[-1].answer
    exact_summary_questions = exact_summary.split(
        "## Eksik Bilgiler / Takip Soruları"
    )[-1].split("**Genel kaynak dayanağı:**")[0]
    checks["cloud_exact_initial_detection"] = (
        detect_security_scenario(exact_cloud_queries[0]) == "cloud_identity_oauth"
        and "**Orta:**" in exact_responses[0].answer
        and "8 dakika" in exact_responses[0].answer
    )
    checks["cloud_exact_consent_detection"] = (
        "**Yüksek:**" in exact_responses[1].answer
        and "Cloud Docs Sync" in exact_responses[1].answer
        and "Mail.Read" in exact_responses[1].answer
        and "Files.ReadWrite.All" in exact_responses[1].answer
        and "offline_access" in exact_responses[1].answer
    )
    checks["cloud_exact_token_detection"] = (
        detect_security_scenario(exact_cloud_queries[2]) == "cloud_identity_oauth"
        and "**Kritik:**" in exact_responses[2].answer
        and "80 e-posta" in exact_responses[2].answer
        and "25 dosya" in exact_responses[2].answer
        and "dosya indirme" in exact_responses[2].answer
        and "tanımadığını" in exact_responses[2].answer
    )
    checks["cloud_exact_summary_memory"] = (
        "**Kritik:**" in exact_summary
        and "8 dakika" in exact_summary
        and "İstanbul" in exact_summary
        and "Amsterdam" in exact_summary
        and "Cloud Docs Sync" in exact_summary
        and "Mail.Read" in exact_summary
        and "Files.ReadWrite.All" in exact_summary
        and "offline_access" in exact_summary
        and "80 e-posta" in exact_summary
        and "25 dosya" in exact_summary
        and "dosya indirme" in exact_summary
        and "tanımadığını" in exact_summary
        and "Anormal oturum çevresinde yeni OAuth consent" not in exact_summary_questions
        and "Consent sonrasında refresh token" not in exact_summary_questions
    )

    bec_chunk = RetrievedChunk(
        chunk_id=30,
        document_id=30,
        chunk_index=0,
        similarity=0.75,
        source_path="knowledge_base/playbooks/bec_mailbox_rule_playbook.md",
        title="BEC ve Yetkisiz Mailbox Rule Playbook",
        source_type="playbook",
        scenario="bec_mailbox",
        heading="Aşama 1 — Şüpheli Inbox Manipulation Rule",
        content=(
            "Finans anahtar kelimelerini hedefleyen inbox rule, dış yönlendirme, "
            "MailItemsAccessed ve sahte ödeme gönderimleri aynı BEC zaman "
            "çizelgesinde incelenmelidir."
        ),
    )
    exact_bec_queries = [
        (
            "Bir kullanıcının posta kutusunda “RSS Sync” adlı yeni bir inbox rule "
            "tespit edildi. Kural, konusu invoice veya payment içeren mesajları "
            "RSS Feeds klasörüne taşıyor. Kullanıcı kuralı henüz doğrulamadı. "
            "Olayı triaj et."
        ),
        (
            "İncelemede aynı kuralın eşleşen e-postaları kullanıcının tanımadığı "
            "finance.archive@external-example.com adresine otomatik yönlendirdiği "
            "doğrulandı. Değerlendirmeyi güncelle."
        ),
        (
            "Audit kayıtlarında saldırganın 18 finans yazışmasına eriştiği ve bu "
            "konuşmaları taklit ederek tedarikçilere banka hesabı değişikliği "
            "isteyen 3 sahte ödeme mesajı gönderdiği doğrulandı. Kullanıcı bu "
            "işlemleri yapmadığını söyledi. Değerlendirmeyi güncelle."
        ),
        (
            "Aynı “RSS Sync” kuralı ve dış yönlendirme adresi iki farklı posta "
            "kutusunda daha tespit edildi. Toplam 3 posta kutusu etkilenmiş "
            "durumda. Şimdiye kadar doğrulanan bulguları, kampanyanın kapsamını "
            "ve öncelikli SOC aksiyonlarını özetle. Bildiğin bilgileri yeniden "
            "soru olarak sorma."
        ),
    ]
    bec_history: list[dict[str, str]] = []
    bec_responses = []

    for bec_query in exact_bec_queries:
        bec_responses.append(
            build_safe_fallback_response(
                bec_query,
                [bec_chunk],
                history=bec_history,
            )
        )
        bec_history.extend(
            [
                {"role": "user", "content": bec_query},
                {"role": "assistant", "content": bec_responses[-1].answer},
            ]
        )

    bec_initial_state = build_bec_case_state(exact_bec_queries[0])
    bec_forwarding_state = build_bec_case_state(
        exact_bec_queries[1],
        bec_history[:2],
    )
    bec_full_state = build_bec_case_state(
        exact_bec_queries[3],
        bec_history[:6],
    )
    bec_summary = bec_responses[-1].answer
    bec_summary_questions = bec_summary.split(
        "## Eksik Bilgiler / Takip Soruları"
    )[-1].split("**Genel kaynak dayanağı:**")[0]
    checks["bec_initial_state"] = (
        bec_initial_state.suspicious_rule
        and bec_initial_state.rule_name == "RSS Sync"
        and bec_initial_state.rule_hides_messages
        and bec_initial_state.watched_terms == ("invoice", "payment")
    )
    checks["bec_initial_medium"] = (
        detect_security_scenario(exact_bec_queries[0]) == "bec_mailbox"
        and "Şüpheli finans odaklı mailbox kuralı" in bec_responses[0].answer
        and "**Orta:**" in bec_responses[0].answer
        and "RSS Sync" in bec_responses[0].answer
        and "invoice" in bec_responses[0].answer
        and "payment" in bec_responses[0].answer
    )
    checks["bec_external_forwarding_state"] = (
        bec_forwarding_state.external_forwarding
        and bec_forwarding_state.forwarding_address
        == "finance.archive@external-example.com"
        and bec_forwarding_state.user_recognized_forwarding_target is False
    )
    checks["bec_external_forwarding_high"] = (
        "Şüpheli dış e-posta yönlendirmesi / olası BEC"
        in bec_responses[1].answer
        and "**Yüksek:**" in bec_responses[1].answer
        and "finance.archive@external-example.com" in bec_responses[1].answer
        and "tanımadığını" in bec_responses[1].answer
    )
    checks["bec_financial_abuse_critical"] = (
        "Doğrulanmış BEC ve sahte ödeme girişimi" in bec_responses[2].answer
        and "**Kritik:**" in bec_responses[2].answer
        and "18 finans yazışmasına" in bec_responses[2].answer
        and "3 sahte ödeme mesajı" in bec_responses[2].answer
        and "banka hesabı değişikliği" in bec_responses[2].answer
        and "tedarikçi" in bec_responses[2].answer
        and "işlemleri kendisinin yapmadığını" in bec_responses[2].answer
    )
    checks["bec_campaign_scope_state"] = (
        bec_full_state.financial_mail_count == 18
        and bec_full_state.fraudulent_message_count == 3
        and bec_full_state.additional_mailbox_count == 2
        and bec_full_state.reported_total_mailbox_count == 3
        and bec_full_state.total_affected_mailboxes == 3
    )
    checks["bec_campaign_summary_memory"] = (
        "Birden fazla posta kutusunu etkileyen BEC kampanyası"
        in bec_summary
        and "**Kritik:**" in bec_summary
        and "RSS Sync" in bec_summary
        and "invoice" in bec_summary
        and "payment" in bec_summary
        and "finance.archive@external-example.com" in bec_summary
        and "18 finans yazışmasına" in bec_summary
        and "3 sahte ödeme mesajı" in bec_summary
        and "2 başka posta kutusunda" in bec_summary
        and "toplam 3 posta kutusunun" in bec_summary
        and "işlemleri kendisinin yapmadığını" in bec_summary
        and "kuralı, koşullarını ve hedef klasörü" not in bec_summary_questions
        and "ForwardTo, RedirectTo" not in bec_summary_questions
        and "MailItemsAccessed, Send, SendAs" not in bec_summary_questions
    )
    checks["bec_fallback_quality_bar"] = answer_meets_quality_bar(
        exact_bec_queries[3],
        bec_summary,
        history=bec_history[:6],
    )
    checks["bec_confirmed_fact_guard"] = answer_respects_confirmed_facts(
        exact_bec_queries[3],
        bec_summary,
        history=bec_history[:6],
    )

    exfil_chunk = RetrievedChunk(
        chunk_id=40,
        document_id=40,
        chunk_index=0,
        similarity=0.78,
        source_path=(
            "knowledge_base/playbooks/cloud_data_exfiltration_playbook.md"
        ),
        title="Cloud Data Exfiltration ve Toplu İndirme Playbook",
        source_type="playbook",
        scenario="data_exfiltration",
        heading="Aşama 1 — Anormal Toplu İndirme",
        content=(
            "SharePoint ve OneDrive FileDownloaded olayları; hassas dosya "
            "arşivleme, endpoint ve harici bulut yükleme telemetrisiyle aynı "
            "zaman çizelgesinde incelenmelidir."
        ),
    )
    exact_exfil_queries = [
        (
            "Microsoft 365 alarmında bir kullanıcının SharePoint ve OneDrive’dan "
            "35 dakika içinde 1.240 dosya indirdiği görüldü. Etkinlik yönetilmeyen "
            "bir Windows cihazından gerçekleşti; kullanıcı işlemi henüz "
            "doğrulamadı. Olayı triaj et."
        ),
        (
            "İndirilen dosyaların 73’ünün “Gizli” hassasiyet etiketli olduğu ve "
            "endpoint üzerinde 3,8 GB boyutunda research_export.zip adlı arşiv "
            "oluşturulduğu doğrulandı. Değerlendirmeyi güncelle."
        ),
        (
            "Proxy ve tarayıcı kayıtları aynı cihazdan research_export.zip "
            "arşivinin kullanıcının tanımadığı personal-dropbox.example hedefine "
            "yüklendiğini ve 3,8 GB aktarımın başarıyla tamamlandığını doğruladı. "
            "Kullanıcı bu işlemi yapmadığını söyledi. Değerlendirmeyi güncelle."
        ),
        (
            "Aynı personal-dropbox.example hedefi ve arşivleme davranışı iki "
            "farklı kullanıcıda daha tespit edildi. Toplam 3 kullanıcı ve 3 cihaz "
            "etkilenmiş durumda; toplam dışarı aktarılan veri 8,6 GB. Şimdiye kadar "
            "doğrulanan bulguları, olayın kapsamını ve öncelikli SOC aksiyonlarını "
            "özetle. Bildiğin bilgileri yeniden soru olarak sorma."
        ),
    ]
    exfil_history: list[dict[str, str]] = []
    exfil_responses = []

    for exfil_query in exact_exfil_queries:
        exfil_responses.append(
            build_safe_fallback_response(
                exfil_query,
                [exfil_chunk],
                history=exfil_history,
            )
        )
        exfil_history.extend(
            [
                {"role": "user", "content": exfil_query},
                {"role": "assistant", "content": exfil_responses[-1].answer},
            ]
        )

    exfil_initial_state = build_data_exfiltration_case_state(
        exact_exfil_queries[0]
    )
    exfil_sensitive_state = build_data_exfiltration_case_state(
        exact_exfil_queries[1],
        exfil_history[:2],
    )
    exfil_upload_state = build_data_exfiltration_case_state(
        exact_exfil_queries[2],
        exfil_history[:4],
    )
    exfil_full_state = build_data_exfiltration_case_state(
        exact_exfil_queries[3],
        exfil_history[:6],
    )
    exfil_summary = exfil_responses[-1].answer
    exfil_summary_questions = exfil_summary.split(
        "## Eksik Bilgiler / Takip Soruları"
    )[-1].split("**Genel kaynak dayanağı:**")[0]
    checks["data_exfiltration_initial_state"] = (
        exfil_initial_state.mass_download
        and exfil_initial_state.download_count == 1240
        and exfil_initial_state.download_window_minutes == 35
        and exfil_initial_state.cloud_sources == ("SharePoint", "OneDrive")
        and exfil_initial_state.unmanaged_device
        and exfil_initial_state.user_confirmed_activity is None
    )
    checks["data_exfiltration_initial_medium"] = (
        detect_security_scenario(exact_exfil_queries[0])
        == "data_exfiltration"
        and "Anormal SharePoint/OneDrive toplu dosya indirme"
        in exfil_responses[0].answer
        and "**Orta:**" in exfil_responses[0].answer
        and "1.240 dosya" in exfil_responses[0].answer
        and "35 dakika" in exfil_responses[0].answer
        and "yönetilmeyen bir cihaz" in exfil_responses[0].answer
    )
    checks["data_exfiltration_sensitive_state"] = (
        exfil_sensitive_state.sensitive_files
        and exfil_sensitive_state.sensitive_file_count == 73
        and exfil_sensitive_state.sensitivity_label == "Gizli"
        and exfil_sensitive_state.archive_created
        and exfil_sensitive_state.archive_name == "research_export.zip"
        and exfil_sensitive_state.archive_size == "3,8 GB"
    )
    checks["data_exfiltration_sensitive_high"] = (
        "Hassas veri toplama ve arşivleme şüphesi"
        in exfil_responses[1].answer
        and "**Yüksek:**" in exfil_responses[1].answer
        and "73 dosyanın" in exfil_responses[1].answer
        and "Gizli" in exfil_responses[1].answer
        and "research_export.zip" in exfil_responses[1].answer
        and "3,8 GB" in exfil_responses[1].answer
    )
    checks["data_exfiltration_upload_state"] = (
        exfil_upload_state.external_upload
        and exfil_upload_state.external_destination
        == "personal-dropbox.example"
        and exfil_upload_state.upload_completed
        and exfil_upload_state.user_denied_activity
        and exfil_upload_state.user_confirmed_activity is False
    )
    checks["data_exfiltration_upload_critical"] = (
        "Doğrulanmış harici bulut veri sızdırma"
        in exfil_responses[2].answer
        and "**Kritik:**" in exfil_responses[2].answer
        and "personal-dropbox.example" in exfil_responses[2].answer
        and "aktarım başarıyla tamamlandı" in exfil_responses[2].answer
        and "işlemi kendisinin yapmadığını" in exfil_responses[2].answer
    )
    checks["data_exfiltration_campaign_state"] = (
        exfil_full_state.additional_user_count == 2
        and exfil_full_state.reported_total_user_count == 3
        and exfil_full_state.total_affected_users == 3
        and exfil_full_state.reported_total_device_count == 3
        and exfil_full_state.reported_total_exfil_size == "8,6 GB"
    )
    checks["data_exfiltration_campaign_summary_memory"] = (
        "Birden fazla kullanıcıyı etkileyen veri sızdırma kampanyası"
        in exfil_summary
        and "**Kritik:**" in exfil_summary
        and "SharePoint" in exfil_summary
        and "OneDrive" in exfil_summary
        and "1.240 dosya" in exfil_summary
        and "35 dakika" in exfil_summary
        and "yönetilmeyen bir cihaz" in exfil_summary
        and "73 dosyanın" in exfil_summary
        and "Gizli" in exfil_summary
        and "research_export.zip" in exfil_summary
        and "3,8 GB" in exfil_summary
        and "personal-dropbox.example" in exfil_summary
        and "işlemi kendisinin yapmadığını" in exfil_summary
        and "2 başka kullanıcıda" in exfil_summary
        and "toplam 3 kullanıcı" in exfil_summary
        and "3 cihaz" in exfil_summary
        and "8,6 GB" in exfil_summary
        and "toplu indirmeyi ve kullanılan cihazı" not in exfil_summary_questions
        and "kurum dışı yükleme görüldü mü" not in exfil_summary_questions
        and "başarıyla tamamlandı mı" not in exfil_summary_questions
    )
    checks["data_exfiltration_fallback_quality_bar"] = answer_meets_quality_bar(
        exact_exfil_queries[3],
        exfil_summary,
        history=exfil_history[:6],
    )
    checks["data_exfiltration_confirmed_fact_guard"] = (
        answer_respects_confirmed_facts(
            exact_exfil_queries[3],
            exfil_summary,
            history=exfil_history[:6],
        )
    )

    credential_chunk = RetrievedChunk(
        chunk_id=50,
        document_id=50,
        chunk_index=0,
        similarity=0.81,
        source_path="knowledge_base/playbooks/credential_dumping_playbook.md",
        title="Credential Dumping / LSASS Bellek Erişimi SOC Playbook",
        source_type="playbook",
        scenario="credential_dumping",
        heading="Aşama 1 — Şüpheli LSASS Süreç Erişimi",
        content=(
            "LSASS ProcessAccess olayları süreç, dump dosyası ve sonraki "
            "ayrıcalıklı hesap kullanımıyla aynı zaman çizelgesinde incelenmelidir."
        ),
    )
    exact_credential_queries = [
        (
            "EDR alarmında WIN-OPS-17 endpointinde rundll32.exe işleminin "
            "LSASS sürecine PROCESS_VM_READ erişimi istediği görüldü. İşlem "
            "daha önce bu cihazda görülmemiş; imza ve allowlist sonucu henüz "
            "doğrulanmadı. Olayı triaj et."
        ),
        (
            "İncelemede rundll32.exe işleminin comsvcs.dll MiniDump "
            "davranışıyla C:\\Windows\\Temp\\lsass.dmp dosyasını oluşturduğu "
            "ve dosyanın 420 MB olduğu doğrulandı. Değerlendirmeyi güncelle."
        ),
        (
            "Kimlik doğrulama kayıtlarında kısa süre sonra aynı WIN-OPS-17 "
            "cihazından ayrıcalıklı svc_backup hesabıyla etki alanı "
            "denetleyicisine başarılı oturum açıldığı görüldü. Hesabın sahibi "
            "bu oturumu yapmadığını söyledi. Değerlendirmeyi güncelle."
        ),
        (
            "Aynı LSASS erişimi ve dump oluşturma davranışı iki endpointte daha "
            "tespit edildi. Toplam 3 endpoint ve 5 ayrıcalıklı hesap etkilenmiş "
            "durumda. Şimdiye kadar doğrulanan bulguları, olayın kapsamını ve "
            "öncelikli SOC aksiyonlarını özetle. Bildiğin bilgileri yeniden soru "
            "olarak sorma."
        ),
    ]
    credential_history: list[dict[str, str]] = []
    credential_responses = []

    for credential_query in exact_credential_queries:
        credential_responses.append(
            build_safe_fallback_response(
                credential_query,
                [credential_chunk],
                history=credential_history,
            )
        )
        credential_history.extend(
            [
                {"role": "user", "content": credential_query},
                {
                    "role": "assistant",
                    "content": credential_responses[-1].answer,
                },
            ]
        )

    credential_initial_state = build_credential_dumping_case_state(
        exact_credential_queries[0]
    )
    credential_dump_state = build_credential_dumping_case_state(
        exact_credential_queries[1],
        credential_history[:2],
    )
    credential_misuse_state = build_credential_dumping_case_state(
        exact_credential_queries[2],
        credential_history[:4],
    )
    credential_full_state = build_credential_dumping_case_state(
        exact_credential_queries[3],
        credential_history[:6],
    )
    credential_summary = credential_responses[-1].answer
    credential_summary_questions = credential_summary.split(
        "## Eksik Bilgiler / Takip Soruları"
    )[-1].split("**Genel kaynak dayanağı:**")[0]
    checks["credential_dumping_initial_state"] = (
        credential_initial_state.suspicious_lsass_access
        and credential_initial_state.source_process == "rundll32.exe"
        and credential_initial_state.target_process == "lsass.exe"
        and credential_initial_state.access_right == "PROCESS_VM_READ"
        and credential_initial_state.endpoint_name == "WIN-OPS-17"
        and not credential_initial_state.dump_created
    )
    checks["credential_dumping_initial_medium"] = (
        detect_security_scenario(exact_credential_queries[0])
        == "credential_dumping"
        and "Şüpheli LSASS süreç erişimi" in credential_responses[0].answer
        and "**Orta:**" in credential_responses[0].answer
        and "WIN-OPS-17" in credential_responses[0].answer
        and "rundll32.exe" in credential_responses[0].answer
        and "PROCESS_VM_READ" in credential_responses[0].answer
    )
    checks["credential_dumping_dump_state"] = (
        credential_dump_state.dump_created
        and credential_dump_state.dump_method == "comsvcs.dll MiniDump"
        and credential_dump_state.dump_path
        == "C:\\Windows\\Temp\\lsass.dmp"
        and credential_dump_state.dump_size == "420 MB"
    )
    checks["credential_dumping_dump_high"] = (
        "Doğrulanmış LSASS bellek dökümü / olası credential dumping"
        in credential_responses[1].answer
        and "**Yüksek:**" in credential_responses[1].answer
        and "comsvcs.dll MiniDump" in credential_responses[1].answer
        and "C:\\Windows\\Temp\\lsass.dmp" in credential_responses[1].answer
        and "420 MB" in credential_responses[1].answer
    )
    checks["credential_dumping_misuse_state"] = (
        credential_misuse_state.privileged_login
        and credential_misuse_state.privileged_account == "svc_backup"
        and credential_misuse_state.destination_system
        == "etki alanı denetleyicisi"
        and credential_misuse_state.account_owner_denied_activity
    )
    checks["credential_dumping_misuse_critical"] = (
        "Doğrulanmış credential dumping ve ayrıcalıklı hesap kötüye kullanımı"
        in credential_responses[2].answer
        and "**Kritik:**" in credential_responses[2].answer
        and "svc_backup" in credential_responses[2].answer
        and "etki alanı denetleyicisi" in credential_responses[2].answer
        and "hesap sahibi oturumu kendisinin açmadığını" in credential_responses[2].answer
    )
    checks["credential_dumping_campaign_state"] = (
        credential_full_state.additional_endpoint_count == 2
        and credential_full_state.reported_total_endpoint_count == 3
        and credential_full_state.total_affected_endpoints == 3
        and credential_full_state.reported_privileged_account_count == 5
    )
    checks["credential_dumping_campaign_summary_memory"] = (
        "Birden fazla endpointi etkileyen credential dumping kampanyası"
        in credential_summary
        and "**Kritik:**" in credential_summary
        and "WIN-OPS-17" in credential_summary
        and "rundll32.exe" in credential_summary
        and "lsass.exe" in credential_summary
        and "PROCESS_VM_READ" in credential_summary
        and "comsvcs.dll MiniDump" in credential_summary
        and "C:\\Windows\\Temp\\lsass.dmp" in credential_summary
        and "420 MB" in credential_summary
        and "svc_backup" in credential_summary
        and "etki alanı denetleyicisi" in credential_summary
        and "hesap sahibi oturumu kendisinin açmadığını" in credential_summary
        and "2 endpointte daha" in credential_summary
        and "toplam 3 endpoint" in credential_summary
        and "5 ayrıcalıklı hesap" in credential_summary
        and "hash'i, dijital imzası" not in credential_summary_questions
        and "olağandışı başarılı oturum görüldü mü" not in credential_summary_questions
        and "başka endpointlerde görüldü mü" not in credential_summary_questions
    )
    checks["credential_dumping_fallback_quality_bar"] = answer_meets_quality_bar(
        exact_credential_queries[3],
        credential_summary,
        history=credential_history[:6],
    )
    checks["credential_dumping_confirmed_fact_guard"] = (
        answer_respects_confirmed_facts(
            exact_credential_queries[3],
            credential_summary,
            history=credential_history[:6],
        )
    )

    for name, passed in checks.items():
        print(f"{name}: {'OK' if passed else 'FAIL'}")

    if not all(checks.values()):
        raise SystemExit(1)

    print("\nTÜM CORE LOGIC TESTLERİ BAŞARILI.")


if __name__ == "__main__":
    main()
