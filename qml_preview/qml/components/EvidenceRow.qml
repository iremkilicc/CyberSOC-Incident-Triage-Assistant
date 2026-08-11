import QtQuick
import QtQuick.Layouts

Rectangle {
    id: root
    property string kindText: "PROCESS"
    property string indicatorText: "powershell.exe"
    property string detailText: "Observed process"
    property string severityText: "HIGH"
    property color accent: "#20d7ff"
    property color severityColor: "#ff7a3d"

    width: parent ? parent.width : 320
    height: 62
    radius: 8
    color: "#071827"
    border.width: 1
    border.color: mouseArea.containsMouse ? Qt.rgba(accent.r, accent.g, accent.b, 0.72) : "#12334b"

    RowLayout {
        anchors.fill: parent
        anchors.margins: 9
        spacing: 9

        Rectangle {
            width: 8
            height: 34
            radius: 4
            color: root.accent
            opacity: 0.82
        }

        ColumnLayout {
            Layout.preferredWidth: 78
            spacing: 2
            Text { text: root.kindText; color: root.accent; font.family: "Cascadia Mono"; font.pixelSize: 7; font.bold: true }
            Text { text: "INDICATOR"; color: "#526e84"; font.pixelSize: 7 }
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 2
            Text { Layout.fillWidth: true; text: root.indicatorText; color: "#edf7ff"; font.pixelSize: 10; font.bold: true; elide: Text.ElideRight }
            Text { Layout.fillWidth: true; text: root.detailText; color: "#7893aa"; font.pixelSize: 8; elide: Text.ElideRight }
        }

        Rectangle {
            implicitWidth: severityLabel.implicitWidth + 14
            implicitHeight: 24
            radius: 6
            color: Qt.rgba(root.severityColor.r, root.severityColor.g, root.severityColor.b, 0.10)
            border.width: 1
            border.color: root.severityColor
            Text { id: severityLabel; anchors.centerIn: parent; text: root.severityText; color: root.severityColor; font.pixelSize: 7; font.bold: true }
        }
    }

    MouseArea { id: mouseArea; anchors.fill: parent; hoverEnabled: true }
}
