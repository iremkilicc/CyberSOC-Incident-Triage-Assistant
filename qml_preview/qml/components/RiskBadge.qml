import QtQuick

Rectangle {
    id: root
    property string label: "HIGH"
    property color accent: "#ff6a3d"

    implicitWidth: label.length > 7 ? 78 : 62
    implicitHeight: 24
    radius: 5
    color: Qt.rgba(accent.r, accent.g, accent.b, 0.10)
    border.width: 1
    border.color: Qt.rgba(accent.r, accent.g, accent.b, 0.75)

    Text {
        anchors.centerIn: parent
        text: root.label
        color: root.accent
        font.pixelSize: 9
        font.family: "Segoe UI"
        font.bold: true
    }
}
