import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "components"

ApplicationWindow {
    id: window
    width: 1600
    height: 960
    minimumWidth: 1320
    minimumHeight: 820
    visible: true
    title: "CyberSOC — Incident Triage Assistant"
    color: "#020812"

    property int selectedIncident: 0
    property string activeTitle: "NEW SOC INVESTIGATION"
    property string activeRisk: "LOW"
    property color activeRiskColor: "#52d889"
    property int activeScore: 0
    property bool analysisRunning: false
    property bool contextAttached: false
    property string analysisStateText: "WAITING FOR MODELS"
    property string incidentMetaText: "No active investigation"
    property string modelStatusText: "PREPARING LOCAL MODELS"
    property string ragChipValue: "WARMING UP"
    property string ragChipSubtitle: "Local vector search"
    property string kbStatusText: "CHECKING"
    property string kbSubtitleText: "Reading local index"
    property int kbChunkCount: 0
    property bool modelsOnline: false
    property string bannerMessage: ""
    property int degradedCount: 0

    property int analysisRevision: 0
    property var evidenceRows: []
    property var techniqueRows: []
    property var actionRows: []
    property var sourceRows: []
    property var timelineRows: []
    property string incidentSummary: "Submit an alert to generate a local, evidence-backed triage summary."
    property string incidentAssessment: "The local RAG engine will fill this panel after Analyze."
    property string likelyAttackPath: "Attack-path narrative appears here from the shared model response."
    property string missingInformation: "Follow-up questions and missing fields appear here after analysis."

    function startAnalysis() {
        if (incidentInput.text.trim().length === 0 || analysisRunning)
            return
        if (typeof backend === "undefined" || backend === null) {
            analysisStateText = "BACKEND UNAVAILABLE"
            return
        }
        backend.analyze(incidentInput.text, contextAttached)
    }

    function cancelAnalysis() {
        if (typeof backend === "undefined" || backend === null)
            return
        backend.cancelAnalysis()
    }

    function refreshRagChip() {
        if (typeof backend === "undefined" || backend === null)
            return
        if (backend.modelsReady) {
            ragChipValue = kbChunkCount > 0 ? "READY" : "NO INDEX"
            ragChipSubtitle = kbChunkCount > 0
                ? "Vector search over " + kbChunkCount + " chunks"
                : "Index empty · run ingest"
        } else if (backend.modelStatus.indexOf("FAILED") >= 0) {
            ragChipValue = "ERROR"
            ragChipSubtitle = "Check Foundry Local"
        } else {
            ragChipValue = "WARMING UP"
            ragChipSubtitle = backend.modelStatus
        }
    }

    function applyHistory(jsonStr) {
        historyModel.clear()
        try {
            const items = JSON.parse(jsonStr || "[]")
            for (let i = 0; i < items.length; i++) {
                const item = items[i]
                historyModel.append({
                    conversationId: item.id || "",
                    title: item.title || "Investigation",
                    time: item.time || "",
                    risk: item.risk || "PENDING",
                    riskColor: item.riskColor || "#5f788e",
                    score: item.score || 0,
                    icon: item.icon || "icon_bruteforce.svg"
                })
            }
            if (historyModel.count === 0) {
                selectedIncident = 0
                return
            }
            if (selectedIncident >= historyModel.count)
                selectedIncident = 0
        } catch (error) {
            console.log("history parse error", error)
        }
    }

    function applyBackendResult(jsonStr) {
        if (!jsonStr || jsonStr === "{}")
            return
        try {
            const data = JSON.parse(jsonStr)
            activeTitle = data.activeTitle || activeTitle
            activeRisk = data.activeRisk || activeRisk
            activeRiskColor = data.activeRiskColor || activeRiskColor
            activeScore = data.activeScore || 0
            evidenceRows = data.evidenceRows || []
            techniqueRows = data.techniqueRows || []
            actionRows = data.actionRows || []
            sourceRows = data.sourceRows || []
            timelineRows = data.timelineRows || []
            incidentSummary = data.incidentSummary || incidentSummary
            incidentAssessment = data.incidentAssessment || incidentAssessment
            likelyAttackPath = data.likelyAttackPath || likelyAttackPath
            missingInformation = data.missingInformation || missingInformation
            degradedCount = (data.degradedCards || []).length
            analysisRevision += 1
        } catch (error) {
            console.log("result parse error", error)
        }
    }

    function syncActiveFromSelection() {
        if (historyModel.count <= 0 || selectedIncident < 0 || selectedIncident >= historyModel.count) {
            activeTitle = "NEW SOC INVESTIGATION"
            activeRisk = "LOW"
            activeRiskColor = "#52d889"
            activeScore = 0
            return
        }
        const selected = historyModel.get(selectedIncident)
        activeTitle = selected.title.toUpperCase()
        activeRisk = selected.risk
        activeRiskColor = selected.riskColor
        activeScore = selected.score
    }

    Connections {
        target: typeof backend !== "undefined" ? backend : null
        enabled: typeof backend !== "undefined" && backend !== null

        function onAnalysisRunningChanged() {
            window.analysisRunning = backend.analysisRunning
        }
        function onAnalysisStateChanged() {
            window.analysisStateText = backend.analysisState
        }
        function onModelStatusChanged() {
            window.modelStatusText = backend.modelStatus
            window.refreshRagChip()
        }
        function onModelsReadyChanged() {
            window.modelsOnline = backend.modelsReady
            window.refreshRagChip()
            if (backend.modelsReady && window.analysisStateText === "WAITING FOR MODELS")
                window.analysisStateText = "READY FOR INCIDENT INPUT"
        }
        function onKbStatsChanged() {
            window.kbStatusText = backend.kbStatus
            window.kbSubtitleText = backend.kbSubtitle
            window.kbChunkCount = backend.kbChunks
            window.refreshRagChip()
        }
        function onIncidentMetaChanged() {
            window.incidentMetaText = backend.incidentMeta
        }
        function onAnalysisCompleted() {
            window.applyBackendResult(backend.resultJson)
        }
        function onHistoryReloaded() {
            window.applyHistory(backend.historyJson)
        }
        function onErrorOccurred(message) {
            window.analysisStateText = "ERROR"
            window.bannerMessage = message
            bannerTimer.restart()
            console.log("CyberSOC backend error:", message)
        }
    }

    ListModel {
        id: historyModel
    }

    Timer {
        id: bannerTimer
        interval: 9000
        onTriggered: window.bannerMessage = ""
    }

    Rectangle {
        id: errorBanner
        z: 200
        visible: window.bannerMessage.length > 0
        anchors.top: parent.top
        anchors.topMargin: 16
        anchors.horizontalCenter: parent.horizontalCenter
        width: Math.min(780, window.width - 90)
        height: bannerText.implicitHeight + 26
        radius: 9
        color: "#2a0d14"
        border.width: 1
        border.color: "#a3324a"

        Rectangle {
            id: bannerDot
            width: 8
            height: 8
            radius: 4
            color: "#ff4358"
            anchors.left: parent.left
            anchors.leftMargin: 13
            anchors.verticalCenter: parent.verticalCenter
        }

        Text {
            id: bannerText
            anchors.left: bannerDot.right
            anchors.leftMargin: 10
            anchors.right: bannerClose.left
            anchors.rightMargin: 10
            anchors.verticalCenter: parent.verticalCenter
            text: window.bannerMessage
            color: "#ffd9df"
            font.family: "Segoe UI Variable"
            font.pixelSize: 10
            wrapMode: Text.WordWrap
            maximumLineCount: 4
            elide: Text.ElideRight
        }

        Rectangle {
            id: bannerClose
            width: 24
            height: 24
            radius: 6
            anchors.right: parent.right
            anchors.rightMargin: 9
            anchors.verticalCenter: parent.verticalCenter
            color: closeArea.containsMouse ? "#4a1622" : "transparent"

            Text {
                anchors.centerIn: parent
                text: "✕"
                color: closeArea.containsMouse ? "#ffe3e8" : "#c98d99"
                font.pixelSize: 11
                font.bold: true
            }

            MouseArea {
                id: closeArea
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: {
                    bannerTimer.stop()
                    window.bannerMessage = ""
                }
            }
        }
    }

    Dialog {
        id: renameDialog
        modal: true
        width: 390
        x: Math.round((window.width - width) / 2)
        y: Math.round((window.height - height) / 2)
        title: "Rename investigation"
        standardButtons: Dialog.Ok | Dialog.Cancel

        contentItem: TextField {
            id: renameField
            width: 340
            selectByMouse: true
            color: "#eaf4ff"
            placeholderText: "Investigation name"
            background: Rectangle {
                radius: 8
                color: "#071827"
                border.width: 1
                border.color: renameField.activeFocus ? "#20d7ff" : "#173c59"
            }
        }

        onAccepted: {
            const cleanName = renameField.text.trim()
            if (cleanName.length > 0 && typeof backend !== "undefined" && backend !== null) {
                backend.renameActive(cleanName)
                window.activeTitle = cleanName.toUpperCase()
            }
        }
    }

    Dialog {
        id: deleteDialog
        modal: true
        width: 400
        x: Math.round((window.width - width) / 2)
        y: Math.round((window.height - height) / 2)
        title: "Delete investigation"
        standardButtons: Dialog.Yes | Dialog.No

        contentItem: Text {
            width: 350
            wrapMode: Text.WordWrap
            color: "#dcecff"
            text: "Delete the selected investigation from local history?"
        }

        onAccepted: {
            if (typeof backend !== "undefined" && backend !== null)
                backend.deleteActive()
        }
    }

    Rectangle {
        anchors.fill: parent
        color: "#020812"

        Canvas {
            anchors.fill: parent
            opacity: 0.20
            onPaint: {
                const ctx = getContext("2d")
                ctx.reset()
                ctx.strokeStyle = "rgba(34,122,180,0.14)"
                ctx.lineWidth = 1
                for (let x = 0; x < width; x += 48) {
                    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke()
                }
                for (let y = 0; y < height; y += 48) {
                    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke()
                }
            }
        }

        RowLayout {
            anchors.fill: parent
            anchors.margins: 10
            spacing: 10

            Sidebar {
                id: sidebar
                Layout.preferredWidth: 310
                Layout.fillHeight: true
                incidentModel: historyModel
                selectedIndex: window.selectedIncident
                modelsOnline: window.modelsOnline
                modelStateText: window.modelStatusText

                onIncidentSelected: function(index) {
                    window.selectedIncident = index
                    if (index >= 0 && index < historyModel.count) {
                        const item = historyModel.get(index)
                        if (item.conversationId && typeof backend !== "undefined" && backend !== null)
                            backend.selectConversation(item.conversationId)
                        else
                            window.syncActiveFromSelection()
                    }
                }

                onNewInvestigationRequested: {
                    incidentInput.text = ""
                    window.activeTitle = "NEW SOC INVESTIGATION"
                    window.activeRisk = "LOW"
                    window.activeRiskColor = "#52d889"
                    window.activeScore = 0
                    window.evidenceRows = []
                    window.techniqueRows = []
                    window.actionRows = []
                    window.sourceRows = []
                    window.timelineRows = []
                    if (typeof backend !== "undefined" && backend !== null)
                        backend.newInvestigation()
                }

                onRenameRequested: {
                    if (historyModel.count > 0 && window.selectedIncident >= 0) {
                        renameField.text = historyModel.get(window.selectedIncident).title
                        renameField.selectAll()
                        renameDialog.open()
                    }
                }

                onDeleteRequested: {
                    if (historyModel.count > 0 && window.selectedIncident >= 0)
                        deleteDialog.open()
                }

                onScenarioSelected: function(prompt) {
                    incidentInput.text = prompt
                }
            }

            ColumnLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                spacing: 10

                GlowPanel {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 94
                    panelColor: "#04101c"
                    borderColor: "#12324c"
                    glowOpacity: 0.06
                    radiusValue: 12

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 14
                        spacing: 10

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2
                            Text {
                                text: "ACTIVE INVESTIGATION"
                                color: "#30cfff"
                                font.family: "Segoe UI"
                                font.pixelSize: 10
                                font.bold: true
                            }
                            RowLayout {
                                spacing: 10
                                Text {
                                    text: window.activeTitle
                                    color: "#eef7ff"
                                    font.family: "Bahnschrift SemiCondensed"
                                    font.pixelSize: 24
                                    font.bold: true
                                }
                                RiskBadge { label: window.activeRisk; accent: window.activeRiskColor }
                                RiskBadge { label: window.activeRisk === "CRITICAL" ? "P1" : "P2"; accent: window.activeRiskColor }
                            }
                            Text {
                                text: window.incidentMetaText
                                color: "#718da5"
                                font.family: "Segoe UI"
                                font.pixelSize: 9
                            }
                        }

                        StatusChip { title: "AI MODEL"; value: window.modelStatusText.indexOf("READY") >= 0 ? "LOCAL LLM" : "LOADING"; subtitle: window.modelStatusText; iconSource: Qt.resolvedUrl("../assets/brand/system_icons/icon_ai_model.svg"); accent: "#20d7ff" }
                        StatusChip { title: "KNOWLEDGE BASE"; value: window.kbStatusText; subtitle: window.kbSubtitleText; iconSource: Qt.resolvedUrl("../assets/brand/system_icons/icon_knowledge_base.svg"); accent: window.kbChunkCount > 0 ? "#69df77" : "#ffb22e" }
                        StatusChip { title: "RAG SYSTEM"; value: window.ragChipValue; subtitle: window.ragChipSubtitle; iconSource: Qt.resolvedUrl("../assets/brand/system_icons/icon_rag_system.svg"); accent: "#25cfff" }
                        StatusChip { title: "ANALYST"; value: "LOCAL SESSION"; subtitle: "Single-user desktop"; iconSource: Qt.resolvedUrl("../assets/brand/system_icons/icon_analyst.svg"); accent: "#4c8dff" }
                    }
                }

                ScrollView {
                    id: workspaceScroll
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true
                    contentWidth: availableWidth
                    ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
                    ScrollBar.vertical: ScrollBar {
                        width: 8
                        policy: ScrollBar.AsNeeded
                        contentItem: Rectangle {
                            implicitWidth: 6
                            radius: 3
                            color: parent.pressed ? "#28cfff" : "#24506d"
                            opacity: parent.active ? 0.9 : 0.48
                        }
                        background: Rectangle { color: "transparent" }
                    }

                    Column {
                        id: workspaceContent
                        width: Math.max(0, workspaceScroll.availableWidth - 5)
                        spacing: 10

                RowLayout {
                    id: stageThreeWorkspace
                    width: workspaceContent.width
                    height: Math.max(430, Math.min(500, window.height * 0.51))
                    spacing: 10

                    GlowPanel {
                        id: incidentComposerPanel
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        Layout.preferredWidth: 58
                        Layout.minimumWidth: 570
                        panelColor: "#061320"
                        borderColor: incidentInput.activeFocus ? "#1d8fd3" : "#17466a"
                        glowColor: "#168bff"
                        glowOpacity: incidentInput.activeFocus ? 0.17 : 0.07
                        radiusValue: 12

                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 16
                            spacing: 9

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: 9

                                Rectangle {
                                    width: 36
                                    height: 36
                                    radius: 8
                                    color: "#071827"
                                    border.width: 1
                                    border.color: "#1b6f9e"
                                    Image {
                                        anchors.centerIn: parent
                                        width: 31
                                        height: 31
                                        source: Qt.resolvedUrl("../assets/brand/system_icons/icon_evidence.svg")
                                        fillMode: Image.PreserveAspectFit
                                        smooth: true
                                        mipmap: true
                                    }
                                }

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 1
                                    Text {
                                        text: "DESCRIBE THE ALERT / INCIDENT"
                                        color: "#edf7ff"
                                        font.family: "Bahnschrift SemiCondensed"
                                        font.pixelSize: 19
                                        font.bold: true
                                    }
                                    Text {
                                        text: "Provide an alert, suspicious process, login anomaly or endpoint finding."
                                        color: "#829bb0"
                                        font.family: "Segoe UI Variable"
                                        font.pixelSize: 9
                                    }
                                }

                                Rectangle {
                                    radius: 7
                                    implicitWidth: characterCount.implicitWidth + 18
                                    implicitHeight: 25
                                    color: incidentInput.length > 6000 ? "#2a1119" : "#071827"
                                    border.width: 1
                                    border.color: incidentInput.length > 6000 ? "#ff4055" : "#173c59"
                                    Text {
                                        id: characterCount
                                        anchors.centerIn: parent
                                        text: incidentInput.length + " / 6000"
                                        color: incidentInput.length > 6000 ? "#ff6272" : "#6f8ca4"
                                        font.family: "Cascadia Mono"
                                        font.pixelSize: 8
                                    }
                                }
                            }

                            Rectangle {
                                id: inputSurface
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                Layout.minimumHeight: 205
                                radius: 10
                                color: "#04101b"
                                border.width: incidentInput.activeFocus ? 2 : 1
                                border.color: incidentInput.activeFocus ? "#24bdf2" : "#17415f"

                                Rectangle {
                                    anchors.fill: parent
                                    anchors.margins: 3
                                    radius: 7
                                    color: "transparent"
                                    border.width: 1
                                    border.color: Qt.rgba(0.13, 0.65, 1.0, incidentInput.activeFocus ? 0.14 : 0.04)
                                }

                                ScrollView {
                                    anchors.fill: parent
                                    anchors.margins: 2
                                    clip: true
                                    ScrollBar.vertical.policy: ScrollBar.AsNeeded

                                    TextArea {
                                        id: incidentInput
                                        wrapMode: TextEdit.Wrap
                                        selectByMouse: true
                                        color: "#dcecff"
                                        placeholderText: "e.g. powershell.exe executed an encoded command with WINWORD.EXE as parent and contacted an external IP..."
                                        placeholderTextColor: "#5f788e"
                                        font.family: "Segoe UI Variable"
                                        font.pixelSize: 12
                                        leftPadding: 15
                                        rightPadding: 15
                                        topPadding: 14
                                        bottomPadding: 14
                                        background: null
                                    }
                                }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: 9

                                NeonButton {
                                    text: window.contextAttached ? "✓  CONTEXT READY" : "＋  ADD CONTEXT"
                                    accent: window.contextAttached ? "#49d79b" : "#276b9a"
                                    Layout.preferredWidth: 154
                                    onClicked: window.contextAttached = !window.contextAttached
                                }

                                Rectangle {
                                    visible: window.contextAttached
                                    Layout.preferredWidth: contextText.implicitWidth + 24
                                    Layout.preferredHeight: 30
                                    radius: 7
                                    color: "#09241f"
                                    border.width: 1
                                    border.color: "#2a8467"
                                    Text {
                                        id: contextText
                                        anchors.centerIn: parent
                                        text: "LOCAL CONTEXT SLOT ACTIVE"
                                        color: "#61dfae"
                                        font.pixelSize: 8
                                        font.bold: true
                                    }
                                }

                                Item { Layout.fillWidth: true }

                                Text {
                                    text: window.analysisStateText
                                    color: window.analysisRunning ? "#31d6ff" : "#66869f"
                                    font.family: "Cascadia Mono"
                                    font.pixelSize: 8
                                    font.bold: true
                                }

                                NeonButton {
                                    text: window.analysisRunning ? "CANCEL ANALYSIS   ✕" : "ANALYZE INCIDENT   ➤"
                                    Layout.preferredWidth: 230
                                    accent: window.analysisRunning ? "#d33d52" : "#1b83ff"
                                    enabled: window.analysisRunning || (incidentInput.text.trim().length > 0 && incidentInput.length <= 6000 && (typeof backend === "undefined" || backend.modelsReady))
                                    opacity: enabled ? 1.0 : 0.55
                                    onClicked: {
                                        if (window.analysisRunning)
                                            window.cancelAnalysis()
                                        else
                                            window.startAnalysis()
                                    }
                                }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                Text {
                                    text: "QUICK SCENARIOS"
                                    color: "#6f8da4"
                                    font.family: "Segoe UI Variable"
                                    font.pixelSize: 9
                                    font.bold: true
                                }
                                Rectangle { Layout.fillWidth: true; height: 1; color: "#123149" }
                                Text {
                                    text: "LOAD A SAMPLE INCIDENT"
                                    color: "#4f6e86"
                                    font.pixelSize: 7
                                    font.bold: true
                                }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: 8

                                QuickScenarioCard {
                                    Layout.fillWidth: true
                                    title: "BRUTE FORCE"
                                    subtitle: "Login anomaly"
                                    accent: "#ff4358"
                                    iconSource: Qt.resolvedUrl("../assets/brand/incident_icons/icon_bruteforce.svg")
                                    onClicked: incidentInput.text = "A user account received 86 failed sign-in attempts from multiple external IP addresses within ten minutes."
                                }
                                QuickScenarioCard {
                                    Layout.fillWidth: true
                                    title: "PHISHING LINK"
                                    subtitle: "Email / URL"
                                    accent: "#a65cff"
                                    iconSource: Qt.resolvedUrl("../assets/brand/incident_icons/icon_phishing.svg")
                                    onClicked: incidentInput.text = "A user received a suspicious Microsoft 365 password-expiry email containing an external login link."
                                }
                                QuickScenarioCard {
                                    Layout.fillWidth: true
                                    title: "POWERSHELL ABUSE"
                                    subtitle: "Command execution"
                                    accent: "#20d7ff"
                                    iconSource: Qt.resolvedUrl("../assets/brand/incident_icons/icon_powershell.svg")
                                    onClicked: incidentInput.text = "powershell.exe executed an encoded command with WINWORD.EXE as parent and contacted an external IP."
                                }
                                QuickScenarioCard {
                                    Layout.fillWidth: true
                                    title: "MALICIOUS FILE"
                                    subtitle: "File execution"
                                    accent: "#4bd58d"
                                    iconSource: Qt.resolvedUrl("../assets/brand/incident_icons/icon_malicious_file.svg")
                                    onClicked: incidentInput.text = "A newly downloaded executable launched from the user's temporary directory and created a scheduled task."
                                }
                            }
                        }
                    }

                    GlowPanel {
                        id: threatRadarPanel
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        Layout.preferredWidth: 42
                        Layout.minimumWidth: 410
                        panelColor: "#061320"
                        borderColor: window.analysisRunning ? "#1a94c9" : "#17466a"
                        glowColor: window.analysisRunning ? "#2edcff" : window.activeRiskColor
                        glowOpacity: window.analysisRunning ? 0.18 : 0.08
                        radiusValue: 12

                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 14
                            spacing: 8

                            RowLayout {
                                Layout.fillWidth: true
                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 1
                                    Text {
                                        text: "THREAT RADAR"
                                        color: "#edf7ff"
                                        font.family: "Bahnschrift SemiCondensed"
                                        font.pixelSize: 19
                                        font.bold: true
                                    }
                                    Text {
                                        text: window.analysisRunning ? "Scanning local indicators and incident context" : "Visual risk posture and correlated indicators"
                                        color: "#7892a8"
                                        font.pixelSize: 8
                                    }
                                }
                                Rectangle {
                                    radius: 7
                                    implicitWidth: radarModeText.implicitWidth + 20
                                    implicitHeight: 26
                                    color: window.analysisRunning ? "#082634" : "#071827"
                                    border.width: 1
                                    border.color: window.analysisRunning ? "#20cce8" : "#1c4966"
                                    Text {
                                        id: radarModeText
                                        anchors.centerIn: parent
                                        text: window.analysisRunning ? "LIVE SCAN" : (window.activeScore > 0 ? "RISK PROFILE" : "STANDBY")
                                        color: window.analysisRunning ? "#5de7f6" : "#7999b0"
                                        font.pixelSize: 8
                                        font.bold: true
                                    }
                                }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                spacing: 8

                                Radar {
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    Layout.minimumWidth: 260
                                    score: window.activeScore
                                    riskLabel: window.activeRisk
                                    riskColor: window.activeRiskColor
                                    scanning: window.analysisRunning
                                }

                                ColumnLayout {
                                    Layout.preferredWidth: 136
                                    Layout.maximumWidth: 146
                                    spacing: 7

                                    RadarMetric {
                                        Layout.fillWidth: true
                                        title: "CONFIDENCE"
                                        value: window.activeScore > 0 ? Math.min(98, 70 + Math.round(window.activeScore * 0.28)) + "%" : "--"
                                        subtitle: "Model estimate"
                                        iconSource: Qt.resolvedUrl("../assets/brand/system_icons/icon_analysis.svg")
                                        accent: "#24d9ff"
                                    }
                                    RadarMetric {
                                        Layout.fillWidth: true
                                        title: "TECHNIQUES"
                                        value: window.activeScore >= 80 ? "3" : (window.activeScore > 0 ? "2" : "--")
                                        subtitle: "Mapped patterns"
                                        iconSource: Qt.resolvedUrl("../assets/brand/system_icons/icon_mitre.svg")
                                        accent: "#4c8dff"
                                    }
                                    RadarMetric {
                                        Layout.fillWidth: true
                                        title: "INDICATORS"
                                        value: window.activeScore >= 80 ? "6" : (window.activeScore > 0 ? "4" : "--")
                                        subtitle: "Observed signals"
                                        iconSource: Qt.resolvedUrl("../assets/brand/system_icons/icon_evidence.svg")
                                        accent: "#20d7ff"
                                    }
                                    RadarMetric {
                                        Layout.fillWidth: true
                                        title: "PRIORITY"
                                        value: window.activeScore > 0 ? (window.activeRisk === "CRITICAL" ? "P1" : "P2") : "--"
                                        subtitle: "Triage queue"
                                        iconSource: Qt.resolvedUrl("../assets/brand/system_icons/icon_actions.svg")
                                        accent: window.activeScore > 0 ? window.activeRiskColor : "#6f8ca4"
                                    }
                                }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                Item { Layout.fillWidth: true }
                                Repeater {
                                    model: [
                                        ["CRITICAL", "#ff4055"],
                                        ["HIGH", "#ff8238"],
                                        ["MEDIUM", "#ffb52c"],
                                        ["LOW", "#2edcff"]
                                    ]
                                    delegate: Row {
                                        spacing: 5
                                        Rectangle { width: 7; height: 7; radius: 4; color: modelData[1]; anchors.verticalCenter: parent.verticalCenter }
                                        Text { text: modelData[0]; color: "#7893a8"; font.pixelSize: 7; font.bold: true }
                                    }
                                }
                                Item { Layout.fillWidth: true }
                            }
                        }
                    }
                }

                        GlowPanel {
                            width: workspaceContent.width
                            height: 62
                            panelColor: "#04101c"
                            borderColor: "#153c5a"
                            glowColor: "#20d7ff"
                            glowOpacity: 0.05
                            radiusValue: 10

                            RowLayout {
                                anchors.fill: parent
                                anchors.margins: 12
                                spacing: 10

                                Image {
                                    width: 36
                                    height: 36
                                    source: Qt.resolvedUrl("../assets/brand/system_icons/icon_analysis.svg")
                                    fillMode: Image.PreserveAspectFit
                                    smooth: true
                                    mipmap: true
                                }
                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 1
                                    Text { text: "STRUCTURED INCIDENT ANALYSIS"; color: "#edf7ff"; font.family: "Bahnschrift SemiCondensed"; font.pixelSize: 17; font.bold: true }
                                    Text { text: "Scrollable analysis cards · One retrieval + six per-card local model prompts"; color: "#718da3"; font.pixelSize: 8 }
                                }
                                Rectangle {
                                    radius: 7
                                    implicitWidth: stateText.implicitWidth + 18
                                    implicitHeight: 27
                                    color: window.analysisRunning ? "#082634" : "#071827"
                                    border.width: 1
                                    border.color: window.analysisRunning ? "#20d7ff" : "#1b4a68"
                                    Text { id: stateText; anchors.centerIn: parent; text: window.analysisStateText; color: window.analysisRunning ? "#5de7f6" : "#7898af"; font.pixelSize: 8; font.bold: true }
                                }
                            }
                        }

                        GridLayout {
                            width: workspaceContent.width
                            height: 720
                            columns: 3
                            columnSpacing: 10
                            rowSpacing: 10

                            AnalysisCard {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                Layout.minimumHeight: 330
                                stepNumber: "1"
                                titleText: "KEY EVIDENCE"
                                subtitleText: "Confirmed indicators and correlated findings"
                                iconSource: Qt.resolvedUrl("../assets/brand/system_icons/icon_evidence.svg")
                                accent: "#24d9ff"
                                Rectangle {
                                    width: parent.width
                                    height: 28
                                    radius: 6
                                    color: "#091c2b"
                                    border.width: 1
                                    border.color: "#15374f"
                                    RowLayout {
                                        anchors.fill: parent
                                        anchors.leftMargin: 10
                                        anchors.rightMargin: 10
                                        Text { Layout.preferredWidth: 82; text: "TYPE"; color: "#64839a"; font.pixelSize: 7; font.bold: true }
                                        Text { Layout.fillWidth: true; text: "INDICATOR / FINDING"; color: "#64839a"; font.pixelSize: 7; font.bold: true }
                                        Text { text: "SEVERITY"; color: "#64839a"; font.pixelSize: 7; font.bold: true }
                                    }
                                }

                                Repeater {
                                    model: window.evidenceRows
                                    delegate: EvidenceRow {
                                        kindText: modelData.kind
                                        indicatorText: modelData.indicator
                                        detailText: modelData.detail
                                        severityText: modelData.severity
                                        severityColor: modelData.color
                                        accent: modelData.accent
                                    }
                                }
                            }

                            AnalysisCard {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                Layout.minimumHeight: 330
                                stepNumber: "2"
                                titleText: "MITRE ATT&CK MAPPING"
                                subtitleText: "Techniques associated with this activity"
                                iconSource: Qt.resolvedUrl("../assets/brand/system_icons/icon_mitre.svg")
                                accent: "#398dff"
                                Repeater {
                                    model: window.techniqueRows
                                    delegate: TechniqueRow {
                                        techniqueId: modelData.id
                                        techniqueName: modelData.name
                                        tacticName: modelData.tactic
                                        riskText: modelData.risk
                                        riskColor: modelData.color
                                    }
                                }
                            }

                            AnalysisCard {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                Layout.minimumHeight: 330
                                stepNumber: "3"
                                titleText: "ANALYST ACTIONS"
                                subtitleText: "Prioritized response recommendations"
                                iconSource: Qt.resolvedUrl("../assets/brand/system_icons/icon_actions.svg")
                                accent: "#ff8a3d"
                                Repeater {
                                    model: window.actionRows
                                    delegate: ActionRow {
                                        priorityText: modelData.p
                                        actionTitle: modelData.title
                                        actionDetail: modelData.detail
                                    }
                                }
                            }

                            AnalysisCard {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                Layout.minimumHeight: 330
                                stepNumber: "4"
                                titleText: "AI INCIDENT ANALYSIS"
                                subtitleText: "Summary generated by the local AI model"
                                iconSource: Qt.resolvedUrl("../assets/brand/system_icons/icon_analysis.svg")
                                accent: "#a45cff"
                                footerText: "REGENERATE ANALYSIS   ↻"
                                onFooterClicked: {
                                    if (typeof backend !== "undefined" && backend !== null)
                                        backend.regenerate()
                                }

                                Rectangle {
                                    width: parent.width
                                    height: summaryText.implicitHeight + 24
                                    radius: 8
                                    color: "#0a1828"
                                    border.width: 1
                                    border.color: "#273252"
                                    Column {
                                        anchors.fill: parent
                                        anchors.margins: 11
                                        spacing: 5
                                        Text { text: "INCIDENT SUMMARY"; color: "#b58aff"; font.pixelSize: 8; font.bold: true }
                                        Text { id: summaryText; width: parent.width; text: window.incidentSummary; color: "#dce8f3"; font.pixelSize: 9; wrapMode: Text.WordWrap; lineHeight: 1.28 }
                                    }
                                }

                                Rectangle {
                                    width: parent.width
                                    height: assessmentText.implicitHeight + 24
                                    radius: 8
                                    color: "#071827"
                                    border.width: 1
                                    border.color: "#15364e"
                                    Column {
                                        anchors.fill: parent
                                        anchors.margins: 11
                                        spacing: 5
                                        Text { text: "ASSESSMENT"; color: "#20d7ff"; font.pixelSize: 8; font.bold: true }
                                        Text { id: assessmentText; width: parent.width; text: window.incidentAssessment; color: "#b9cada"; font.pixelSize: 9; wrapMode: Text.WordWrap; lineHeight: 1.25 }
                                    }
                                }

                                Rectangle {
                                    width: parent.width
                                    height: pathText.implicitHeight + 24
                                    radius: 8
                                    color: "#071827"
                                    border.width: 1
                                    border.color: "#15364e"
                                    Column {
                                        anchors.fill: parent
                                        anchors.margins: 11
                                        spacing: 5
                                        Text { text: "LIKELY ATTACK PATH"; color: "#ff9d55"; font.pixelSize: 8; font.bold: true }
                                        Text { id: pathText; width: parent.width; text: window.likelyAttackPath; color: "#b9cada"; font.pixelSize: 9; wrapMode: Text.WordWrap; lineHeight: 1.25 }
                                    }
                                }

                                MetricBar { labelText: "Confidence Score"; valueText: Math.min(98, 70 + Math.round(window.activeScore * 0.28)) + "%"; progressValue: Math.min(0.98, 0.70 + window.activeScore * 0.0028); accent: "#20d7ff" }
                                MetricBar { labelText: "Severity Assessment"; valueText: window.activeRisk; progressValue: Math.max(0.20, window.activeScore / 100); accent: window.activeRiskColor }
                                MetricBar { labelText: "Scope Impact"; valueText: window.activeScore >= 80 ? "HIGH" : window.activeScore >= 55 ? "MEDIUM" : "LOW"; progressValue: window.activeScore >= 80 ? 0.82 : window.activeScore >= 55 ? 0.58 : 0.32; accent: window.activeScore >= 80 ? "#ff7a3d" : "#ffb22e" }

                                Rectangle {
                                    width: parent.width
                                    height: missingText.implicitHeight + 24
                                    radius: 8
                                    color: "#151326"
                                    border.width: 1
                                    border.color: "#503769"
                                    Column {
                                        anchors.fill: parent
                                        anchors.margins: 11
                                        spacing: 5
                                        Text { text: "MISSING INFORMATION"; color: "#d397ff"; font.pixelSize: 8; font.bold: true }
                                        Text { id: missingText; width: parent.width; text: window.missingInformation; color: "#b9cada"; font.pixelSize: 9; wrapMode: Text.WordWrap; lineHeight: 1.25 }
                                    }
                                }
                            }

                            AnalysisCard {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                Layout.minimumHeight: 330
                                stepNumber: "5"
                                titleText: "CORRELATED SOURCES"
                                subtitleText: "Retrieved knowledge and supporting context"
                                iconSource: Qt.resolvedUrl("../assets/brand/system_icons/icon_sources.svg")
                                accent: "#25d9ff"
                                Repeater {
                                    model: window.sourceRows
                                    delegate: SourceRow {
                                        sourceName: modelData.name
                                        sourceMeta: modelData.meta
                                        relevance: modelData.relevance
                                        accent: modelData.color
                                    }
                                }

                                Rectangle {
                                    width: parent.width
                                    height: 48
                                    radius: 8
                                    color: "#071827"
                                    border.width: 1
                                    border.color: "#15364e"
                                    RowLayout {
                                        anchors.fill: parent
                                        anchors.margins: 9
                                        Text { text: "RETRIEVAL MODE"; color: "#64839a"; font.pixelSize: 7; font.bold: true }
                                        Item { Layout.fillWidth: true }
                                        Text { text: "LOCAL VECTOR SEARCH"; color: "#52d889"; font.pixelSize: 8; font.bold: true }
                                    }
                                }
                            }

                            AnalysisCard {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                Layout.minimumHeight: 330
                                stepNumber: "6"
                                titleText: "TIMELINE"
                                subtitleText: "Chronological event reconstruction"
                                iconSource: Qt.resolvedUrl("../assets/brand/system_icons/icon_timeline.svg")
                                accent: "#3d9cff"
                                Repeater {
                                    model: window.timelineRows
                                    delegate: TimelineRow {
                                        timeText: modelData.time
                                        eventTitle: modelData.title
                                        eventDetail: modelData.detail
                                        accent: modelData.color
                                        lastItem: index === window.timelineRows.length - 1
                                    }
                                }
                            }
                        }

                        GlowPanel {
                            width: workspaceContent.width
                            height: 46
                            panelColor: "#04101c"
                            borderColor: "#12324c"
                            glowOpacity: 0.04
                            radiusValue: 10

                            RowLayout {
                                anchors.fill: parent
                                anchors.margins: 11
                                Text { text: "LOCAL RAG · PER-CARD PROMPTS (6 CALLS)"; color: "#6f8ca4"; font.pixelSize: 9; font.bold: true }
                                Item { Layout.fillWidth: true }
                                Text {
                                    visible: window.degradedCount > 0
                                    text: window.degradedCount + "/6 CARDS DEGRADED"
                                    color: "#ffb22e"
                                    font.pixelSize: 9
                                    font.bold: true
                                    rightPadding: 12
                                }
                                Rectangle { width: 9; height: 9; radius: 5; color: window.ragChipValue === "READY" ? "#32df98" : "#ffb22e" }
                                Text { text: window.ragChipValue === "READY" ? "RAG READY" : window.ragChipValue; color: window.ragChipValue === "READY" ? "#67e3ad" : "#ffb22e"; font.pixelSize: 9; font.bold: true }
                            }
                        }
                    }
                }
            }
        }
    }
}
