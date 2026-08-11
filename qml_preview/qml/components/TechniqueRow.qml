import QtQuick
import QtQuick.Layouts

Rectangle {
    id: root
    property string techniqueId: "T1059.001"
    property string techniqueName: "PowerShell"
    property string tacticName: "Execution"
    property string riskText: "HIGH"
    property color accent: "#398dff"
    property color riskColor: "#ff7a3d"

    width: parent ? parent.width : 320
    height: 72
    radius: 8
    color: "#071827"
    border.width: 1
    border.color: "#153b56"

    Rectangle { width: 3; radius: 2; color: root.accent; anchors.left: parent.left; anchors.top: parent.top; anchors.bottom: parent.bottom; anchors.margins: 7 }

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: 17
        anchors.rightMargin: 9
        anchors.topMargin: 8
        anchors.bottomMargin: 8
        spacing: 9

        Rectangle {
            width: 46
            height: 46
            radius: 9
            color: "#0a2033"
            border.width: 1
            border.color: Qt.rgba(root.accent.r, root.accent.g, root.accent.b, 0.55)
            Text { anchors.centerIn: parent; text: root.techniqueId; color: "#8fc4ff"; font.family: "Cascadia Mono"; font.pixelSize: 7; font.bold: true }
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 2
            Text { Layout.fillWidth: true; text: root.techniqueName; color: "#edf7ff"; font.pixelSize: 10; font.bold: true; elide: Text.ElideRight }
            Text { Layout.fillWidth: true; text: root.tacticName; color: "#7290a7"; font.pixelSize: 8; elide: Text.ElideRight }
        }

        Rectangle {
            implicitWidth: riskLabel.implicitWidth + 14
            implicitHeight: 23
            radius: 6
            color: Qt.rgba(root.riskColor.r, root.riskColor.g, root.riskColor.b, 0.10)
            border.width: 1
            border.color: root.riskColor
            Text { id: riskLabel; anchors.centerIn: parent; text: root.riskText; color: root.riskColor; font.pixelSize: 7; font.bold: true }
        }
    }
}
