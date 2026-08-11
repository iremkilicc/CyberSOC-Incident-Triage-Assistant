import QtQuick
import QtQuick.Layouts

Item {
    id: root
    property string timeText: "14:32:11"
    property string eventTitle: "Alert received"
    property string eventDetail: "Security event submitted for triage"
    property color accent: "#20d7ff"
    property bool lastItem: false

    width: parent ? parent.width : 320
    height: 66

    Rectangle {
        width: 2
        anchors.horizontalCenter: marker.horizontalCenter
        anchors.top: marker.verticalCenter
        anchors.bottom: parent.bottom
        color: "#1c4c6b"
        visible: !root.lastItem
    }

    Rectangle {
        id: marker
        width: 12
        height: 12
        radius: 6
        x: 5
        y: 15
        color: "#06131f"
        border.width: 2
        border.color: root.accent
        Rectangle { anchors.centerIn: parent; width: 4; height: 4; radius: 2; color: root.accent }
    }

    RowLayout {
        anchors.left: marker.right
        anchors.leftMargin: 11
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        spacing: 10

        Text { Layout.preferredWidth: 58; text: root.timeText; color: root.accent; font.family: "Cascadia Mono"; font.pixelSize: 8; font.bold: true }
        ColumnLayout {
            Layout.fillWidth: true
            spacing: 2
            Text { Layout.fillWidth: true; text: root.eventTitle; color: "#edf7ff"; font.pixelSize: 10; font.bold: true; elide: Text.ElideRight }
            Text { Layout.fillWidth: true; text: root.eventDetail; color: "#718da3"; font.pixelSize: 8; elide: Text.ElideRight }
        }
    }
}
