import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: root
    property string priorityText: "P1"
    property string actionTitle: "Isolate affected endpoint"
    property string actionDetail: "Prevent further compromise"
    property color accent: priorityText === "P1" ? "#ff4055" : priorityText === "P2" ? "#2a9cff" : "#27d7d0"
    property bool completed: false

    width: parent ? parent.width : 320
    height: 66
    radius: 8
    color: completed ? "#07211f" : "#071827"
    border.width: 1
    border.color: completed ? "#1d7a68" : "#15364e"

    RowLayout {
        anchors.fill: parent
        anchors.margins: 9
        spacing: 9

        Rectangle {
            width: 36
            height: 36
            radius: 8
            color: Qt.rgba(root.accent.r, root.accent.g, root.accent.b, 0.11)
            border.width: 1
            border.color: root.accent
            Text { anchors.centerIn: parent; text: root.priorityText; color: root.accent; font.pixelSize: 9; font.bold: true }
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 2
            Text { Layout.fillWidth: true; text: root.actionTitle; color: root.completed ? "#8bcdbd" : "#edf7ff"; font.pixelSize: 10; font.bold: true; elide: Text.ElideRight; font.strikeout: root.completed }
            Text { Layout.fillWidth: true; text: root.actionDetail; color: "#748fa5"; font.pixelSize: 8; elide: Text.ElideRight }
        }

        CheckBox {
            checked: root.completed
            onToggled: root.completed = checked
            indicator: Rectangle {
                implicitWidth: 22
                implicitHeight: 22
                radius: 5
                color: parent.checked ? "#123d35" : "#06131f"
                border.width: 1
                border.color: parent.checked ? "#41dfa7" : "#345269"
                Text { anchors.centerIn: parent; visible: parent.parent.checked; text: "✓"; color: "#63efb7"; font.pixelSize: 12; font.bold: true }
            }
            contentItem: Item {}
        }
    }
}
