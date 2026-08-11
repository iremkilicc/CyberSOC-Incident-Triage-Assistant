import QtQuick
import QtQuick.Controls

Rectangle {
    id: root
    property string title: "Brute Force"
    property string subtitle: "Credential Stuffing"
    property url iconSource: ""
    property color accent: "#25cfff"
    signal clicked()

    implicitHeight: 50
    radius: 8
    color: mouseArea.containsMouse ? "#0a2136" : "#061522"
    border.width: 1
    border.color: mouseArea.containsMouse
                 ? Qt.rgba(root.accent.r, root.accent.g, root.accent.b, 0.65)
                 : "#102f48"

    Rectangle {
        width: 3
        radius: 2
        color: root.accent
        opacity: mouseArea.containsMouse ? 1.0 : 0.58
        anchors.left: parent.left
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        anchors.margins: 7
    }

    Image {
        id: icon
        anchors.left: parent.left
        anchors.leftMargin: 13
        anchors.verticalCenter: parent.verticalCenter
        width: 36
        height: 36
        source: root.iconSource
        fillMode: Image.PreserveAspectFit
        smooth: true
        mipmap: true
    }

    Column {
        anchors.left: icon.right
        anchors.leftMargin: 9
        anchors.right: arrow.left
        anchors.rightMargin: 6
        anchors.verticalCenter: parent.verticalCenter
        spacing: 2

        Text {
            width: parent.width
            text: root.title
            color: "#e7f3ff"
            font.family: "Segoe UI Variable"
            font.pixelSize: 10
            font.bold: true
            elide: Text.ElideRight
        }
        Text {
            width: parent.width
            text: root.subtitle
            color: "#6f8ca4"
            font.family: "Segoe UI Variable"
            font.pixelSize: 8
            elide: Text.ElideRight
        }
    }

    Text {
        id: arrow
        anchors.right: parent.right
        anchors.rightMargin: 11
        anchors.verticalCenter: parent.verticalCenter
        text: "›"
        color: mouseArea.containsMouse ? root.accent : "#4f6d84"
        font.pixelSize: 19
    }

    MouseArea {
        id: mouseArea
        anchors.fill: parent
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: root.clicked()
    }
}
