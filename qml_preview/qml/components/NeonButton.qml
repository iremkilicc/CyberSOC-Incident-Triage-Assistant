import QtQuick
import QtQuick.Controls

Button {
    id: control
    property color accent: "#148dff"
    property color textColor: "#eef8ff"

    implicitHeight: 42
    leftPadding: 16
    rightPadding: 16

    contentItem: Text {
        text: control.text
        color: control.textColor
        font.pixelSize: 12
        font.family: "Segoe UI"
        font.bold: true
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
    }

    background: Rectangle {
        radius: 8
        color: control.down ? "#0d4676" : control.hovered ? "#0d5ea0" : "#0a3965"
        border.width: 1
        border.color: control.hovered ? "#31bdff" : Qt.rgba(control.accent.r, control.accent.g, control.accent.b, 0.9)

        Rectangle {
            anchors.fill: parent
            anchors.margins: 2
            radius: 6
            color: "transparent"
            border.width: 1
            border.color: Qt.rgba(0.18, 0.72, 1.0, control.hovered ? 0.35 : 0.14)
        }
    }
}
