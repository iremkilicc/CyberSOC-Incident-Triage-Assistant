import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

GlowPanel {
    id: root

    property var incidentModel
    property int selectedIndex: 0
    property bool modelsOnline: false
    property string modelStateText: "PREPARING LOCAL MODELS"

    signal incidentSelected(int index)
    signal newInvestigationRequested()
    signal renameRequested()
    signal deleteRequested()
    signal scenarioSelected(string prompt)

    panelColor: "#04101c"
    borderColor: "#113a58"
    glowOpacity: 0.12
    radiusValue: 13

    ListModel {
        id: scenariosModel
        ListElement {
            title: "Brute Force"
            subtitle: "Credential Stuffing"
            icon: "icon_bruteforce.svg"
            accent: "#ff4358"
            prompt: "A user account received 86 failed sign-in attempts from multiple external IP addresses within ten minutes."
        }
        ListElement {
            title: "Phishing"
            subtitle: "Email / Malicious Link"
            icon: "icon_phishing.svg"
            accent: "#a65cff"
            prompt: "A user received a suspicious Microsoft 365 password-expiry email containing an external login link."
        }
        ListElement {
            title: "Suspicious PowerShell"
            subtitle: "Encoded Command"
            icon: "icon_powershell.svg"
            accent: "#27cfff"
            prompt: "powershell.exe executed an encoded command with WINWORD.EXE as parent and contacted an external IP."
        }
        ListElement {
            title: "Business Email Compromise"
            subtitle: "Mailbox Rule / Payment Fraud"
            icon: "icon_bec.svg"
            accent: "#35d6c8"
            prompt: "A finance user's mailbox has an external forwarding rule to an unknown address and MailItemsAccessed events show invoice and payment threads were opened."
        }
        ListElement {
            title: "Data Exfiltration"
            subtitle: "Cloud Storage"
            icon: "icon_data_exfiltration.svg"
            accent: "#55df89"
            prompt: "A user downloaded 1,240 files from SharePoint and OneDrive within 35 minutes from an unmanaged device."
        }
        ListElement {
            title: "OAuth Abuse"
            subtitle: "Risky Consent Grant"
            icon: "icon_oauth_abuse.svg"
            accent: "#ffb52c"
            prompt: "A user granted Mail.Read, Files.ReadWrite.All and offline_access permissions to an unknown OAuth application."
        }
        ListElement {
            title: "Credential Dumping"
            subtitle: "LSASS Memory Access"
            icon: "icon_credential_dumping.svg"
            accent: "#5ce08f"
            prompt: "comsvcs.dll was used to create an LSASS minidump on a workstation and the process accessed lsass.exe memory."
        }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 14
        spacing: 10

        Item {
            Layout.fillWidth: true
            Layout.preferredHeight: 106

            Canvas {
                anchors.fill: parent
                opacity: 0.24
                onPaint: {
                    const ctx = getContext("2d")
                    ctx.reset()
                    ctx.strokeStyle = "rgba(32,215,255,0.22)"
                    ctx.lineWidth = 1
                    for (let y = 10; y < height; y += 18) {
                        ctx.beginPath()
                        ctx.moveTo(width * 0.57, y)
                        ctx.lineTo(width * 0.72, y)
                        ctx.lineTo(width * 0.77, y + 7)
                        ctx.lineTo(width - 8, y + 7)
                        ctx.stroke()
                    }
                }
            }

            Image {
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.bottom: parent.bottom
                anchors.leftMargin: 0
                anchors.rightMargin: 0
                anchors.topMargin: 4
                anchors.bottomMargin: 4
                source: Qt.resolvedUrl("../../assets/brand/logos/cybersoc_full_logo_1024x239.png")
                fillMode: Image.PreserveAspectFit
                horizontalAlignment: Image.AlignLeft
                verticalAlignment: Image.AlignVCenter
                smooth: true
                mipmap: true
                asynchronous: true
                sourceSize.width: 1024
                sourceSize.height: 239
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            color: "#15364f"
        }

        ScrollView {
            id: bodyScroll
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
            ScrollBar.vertical.policy: ScrollBar.AsNeeded


            Column {
                width: bodyScroll.availableWidth - 4
                spacing: 9

                Text {
                    text: "CONVERSATIONS"
                    color: "#7db0ce"
                    font.family: "Segoe UI Variable"
                    font.pixelSize: 10
                    font.bold: true
                }

                NeonButton {
                    width: parent.width
                    text: "+   NEW INVESTIGATION"
                    onClicked: root.newInvestigationRequested()
                }

                Item { width: 1; height: 3 }

                Text {
                    text: "INVESTIGATION HISTORY"
                    color: "#7898af"
                    font.family: "Segoe UI Variable"
                    font.pixelSize: 10
                    font.bold: true
                }

                Rectangle {
                    width: parent.width
                    height: emptyHistoryText.implicitHeight + 22
                    radius: 8
                    visible: !root.incidentModel || root.incidentModel.count === 0
                    color: "#061421"
                    border.width: 1
                    border.color: "#102d44"

                    Text {
                        id: emptyHistoryText
                        anchors.fill: parent
                        anchors.margins: 11
                        text: "No investigations yet — paste an alert and run Analyze."
                        color: "#6d8ba1"
                        font.family: "Segoe UI Variable"
                        font.pixelSize: 9
                        wrapMode: Text.WordWrap
                        verticalAlignment: Text.AlignVCenter
                    }
                }

                Repeater {
                    model: root.incidentModel

                    delegate: HistoryCard {
                        width: parent.width
                        incidentTitle: model.title
                        timeText: model.time
                        riskLabel: model.risk
                        riskColor: model.riskColor
                        iconSource: Qt.resolvedUrl("../../assets/brand/incident_icons/" + model.icon)
                        selected: index === root.selectedIndex

                        onClicked: {
                            root.selectedIndex = index
                            root.incidentSelected(index)
                        }

                        onMenuClicked: {
                            root.selectedIndex = index
                            root.incidentSelected(index)
                        }
                    }
                }

                Item { width: 1; height: 3 }

                Text {
                    text: "CONVERSATION CONTROLS"
                    color: "#7898af"
                    font.family: "Segoe UI Variable"
                    font.pixelSize: 10
                    font.bold: true
                }

                Row {
                    width: parent.width
                    spacing: 7

                    NeonButton {
                        width: (parent.width - 7) / 2
                        height: 40
                        text: "✎  RENAME"
                        accent: "#287db5"
                        onClicked: root.renameRequested()
                    }
                    NeonButton {
                        width: (parent.width - 7) / 2
                        height: 40
                        text: "⌫  DELETE"
                        accent: "#d33d52"
                        onClicked: root.deleteRequested()
                    }
                }

                Rectangle {
                    width: parent.width
                    height: 1
                    color: "#15364f"
                }

                Text {
                    text: "SUPPORTED SCENARIOS"
                    color: "#7898af"
                    font.family: "Segoe UI Variable"
                    font.pixelSize: 10
                    font.bold: true
                }

                Repeater {
                    model: scenariosModel

                    delegate: ScenarioItem {
                        width: parent.width
                        title: model.title
                        subtitle: model.subtitle
                        iconSource: Qt.resolvedUrl("../../assets/brand/incident_icons/" + model.icon)
                        accent: model.accent
                        onClicked: root.scenarioSelected(model.prompt)
                    }
                }

                Item { width: 1; height: 4 }
            }
        }

        GlowPanel {
            Layout.fillWidth: true
            Layout.preferredHeight: 62
            panelColor: root.modelsOnline ? "#071c1b" : "#1a0f12"
            borderColor: root.modelsOnline ? "#165047" : "#5a2130"
            glowOpacity: 0.06
            radiusValue: 9

            Row {
                anchors.fill: parent
                anchors.margins: 9
                spacing: 9

                Rectangle {
                    width: 40
                    height: 40
                    radius: 9
                    color: "#071827"
                    border.width: 1
                    border.color: root.modelsOnline ? "#176a5a" : "#7d3040"
                    anchors.verticalCenter: parent.verticalCenter

                    Image {
                        anchors.centerIn: parent
                        width: 36
                        height: 36
                        source: Qt.resolvedUrl("../../assets/brand/system_icons/icon_ai_model.svg")
                        fillMode: Image.PreserveAspectFit
                        smooth: true
                        mipmap: true
                    }

                    Rectangle {
                        width: 9
                        height: 9
                        radius: 5
                        color: root.modelsOnline ? "#35e39a" : "#ff4358"
                        anchors.right: parent.right
                        anchors.bottom: parent.bottom
                        border.width: 1
                        border.color: root.modelsOnline ? "#071c1b" : "#1a0f12"
                        SequentialAnimation on opacity {
                            loops: Animation.Infinite
                            NumberAnimation { to: 0.45; duration: 900 }
                            NumberAnimation { to: 1.0; duration: 900 }
                        }
                    }
                }

                Column {
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: 1
                    Text {
                        text: root.modelsOnline ? "LOCAL AI MODEL" : "LOCAL AI MODEL · OFFLINE"
                        color: root.modelsOnline ? "#dcf8e9" : "#ffd0d6"
                        font.family: "Segoe UI Variable"
                        font.pixelSize: 10
                        font.bold: true
                    }
                    Text {
                        width: 200
                        text: root.modelsOnline ? "FOUNDRY LOCAL · ON-DEVICE" : root.modelStateText
                        color: root.modelsOnline ? "#61a48f" : "#c98d99"
                        font.family: "Segoe UI Variable"
                        font.pixelSize: 8
                        elide: Text.ElideRight
                    }
                }
            }
        }
    }

}
