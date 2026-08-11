import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

GlowPanel {
    id: root

    property string stepNumber: "1"
    property string titleText: "ANALYSIS CARD"
    property string subtitleText: "Structured incident data"
    property url iconSource: ""
    property color accent: "#20d7ff"
    property string footerText: ""
    property bool footerVisible: footerText.length > 0
    property int bodySpacing: 8
    signal footerClicked()

    default property alias bodyData: bodyColumn.data

    panelColor: "#061320"
    borderColor: "#153c5a"
    glowColor: accent
    glowOpacity: 0.055
    radiusValue: 11

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 12
        spacing: 8

        RowLayout {
            Layout.fillWidth: true
            spacing: 9

            Item {
                width: 42
                height: 42

                Rectangle {
                    anchors.fill: parent
                    radius: 9
                    color: "#071827"
                    border.width: 1
                    border.color: Qt.rgba(root.accent.r, root.accent.g, root.accent.b, 0.46)
                }

                Image {
                    anchors.centerIn: parent
                    width: 38
                    height: 38
                    source: root.iconSource
                    fillMode: Image.PreserveAspectFit
                    smooth: true
                    mipmap: true
                    asynchronous: true
                }

                Rectangle {
                    width: 18
                    height: 18
                    radius: 5
                    anchors.right: parent.right
                    anchors.top: parent.top
                    color: "#0b2136"
                    border.width: 1
                    border.color: root.accent

                    Text {
                        anchors.centerIn: parent
                        text: root.stepNumber
                        color: root.accent
                        font.pixelSize: 8
                        font.bold: true
                    }
                }
            }

            ColumnLayout {
                Layout.fillWidth: true
                spacing: 1

                Text {
                    Layout.fillWidth: true
                    text: root.titleText
                    color: "#edf7ff"
                    font.family: "Bahnschrift SemiCondensed"
                    font.pixelSize: 16
                    font.bold: true
                    elide: Text.ElideRight
                }

                Text {
                    Layout.fillWidth: true
                    text: root.subtitleText
                    color: "#718da3"
                    font.family: "Segoe UI Variable"
                    font.pixelSize: 8
                    elide: Text.ElideRight
                }
            }

            Rectangle {
                width: 7
                height: 7
                radius: 4
                color: root.accent
                opacity: 0.9
            }
        }

        Rectangle {
            Layout.fillWidth: true
            height: 1
            color: "#14334b"
        }

        ScrollView {
            id: bodyScroll
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentWidth: availableWidth
            ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
            ScrollBar.vertical: ScrollBar {
                width: 7
                policy: ScrollBar.AsNeeded
                contentItem: Rectangle {
                    implicitWidth: 5
                    radius: 3
                    color: parent.pressed ? root.accent : "#24506d"
                    opacity: parent.active ? 0.9 : 0.45
                }
                background: Rectangle { color: "transparent" }
            }

            Column {
                id: bodyColumn
                width: Math.max(0, bodyScroll.availableWidth - 4)
                spacing: root.bodySpacing
            }
        }

        NeonButton {
            Layout.fillWidth: true
            Layout.preferredHeight: 36
            visible: root.footerVisible
            text: root.footerText
            accent: root.accent
            onClicked: root.footerClicked()
        }
    }
}
