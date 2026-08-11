import QtQuick
import QtQuick.Layouts

ColumnLayout {
    id: root
    property string labelText: "Confidence"
    property string valueText: "94%"
    property real progressValue: 0.94
    property color accent: "#20d7ff"
    width: parent ? parent.width : 300
    spacing: 4

    RowLayout {
        Layout.fillWidth: true
        Text { text: root.labelText; color: "#7892a8"; font.pixelSize: 8 }
        Item { Layout.fillWidth: true }
        Text { text: root.valueText; color: root.accent; font.pixelSize: 8; font.bold: true }
    }
    Rectangle {
        Layout.fillWidth: true
        height: 5
        radius: 3
        color: "#0a2234"
        Rectangle { width: parent.width * Math.max(0, Math.min(1, root.progressValue)); height: parent.height; radius: parent.radius; color: root.accent }
    }
}
