import QtQuick
import QtQuick.Layouts

Rectangle {
    id: root
    property string sourceName: "MITRE ATT&CK"
    property string sourceMeta: "T1059.001 PowerShell"
    property int relevance: 96
    property color accent: "#20d7ff"

    width: parent ? parent.width : 320
    height: 68
    radius: 8
    color: "#071827"
    border.width: 1
    border.color: "#14354e"

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 9
        spacing: 5

        RowLayout {
            Layout.fillWidth: true
            spacing: 8
            Rectangle { width: 8; height: 8; radius: 4; color: root.accent }
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 1
                Text { Layout.fillWidth: true; text: root.sourceName; color: "#edf7ff"; font.pixelSize: 10; font.bold: true; elide: Text.ElideRight }
                Text { Layout.fillWidth: true; text: root.sourceMeta; color: "#6f8ba1"; font.pixelSize: 8; elide: Text.ElideRight }
            }
            Text { text: root.relevance + "%"; color: root.accent; font.pixelSize: 9; font.bold: true }
        }

        Rectangle {
            Layout.fillWidth: true
            height: 5
            radius: 3
            color: "#0a2234"
            Rectangle { width: parent.width * Math.max(0, Math.min(1, root.relevance / 100)); height: parent.height; radius: parent.radius; color: root.accent }
        }
    }
}
