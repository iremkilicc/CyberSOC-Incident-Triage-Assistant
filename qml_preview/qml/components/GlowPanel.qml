import QtQuick

Rectangle {
    id: root
    property color panelColor: "#071320"
    property color borderColor: "#153b59"
    property color glowColor: "#0d86c7"
    property real glowOpacity: 0.18
    property int radiusValue: 12

    color: panelColor
    radius: radiusValue
    border.width: 1
    border.color: borderColor

    Rectangle {
        anchors.fill: parent
        anchors.margins: 1
        radius: Math.max(0, root.radius - 1)
        color: "transparent"
        border.width: 1
        border.color: Qt.rgba(0.10, 0.58, 0.95, root.glowOpacity)
        opacity: root.glowOpacity > 0 ? 1 : 0
    }
}
