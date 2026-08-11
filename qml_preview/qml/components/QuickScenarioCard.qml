import QtQuick
import QtQuick.Controls

Rectangle {
    id: root

    property string title: "SCENARIO"
    property string subtitle: "Description"
    property url iconSource: ""
    property color accent: "#20d7ff"
    signal clicked()

    implicitHeight: 68
    radius: 10
    color: mouseArea.pressed ? "#0b2236" : mouseArea.containsMouse ? "#0a1d30" : "#071724"
    border.width: 1
    border.color: mouseArea.containsMouse
                  ? Qt.rgba(accent.r, accent.g, accent.b, 0.95)
                  : Qt.rgba(accent.r, accent.g, accent.b, 0.48)

    Behavior on color { ColorAnimation { duration: 130 } }
    Behavior on border.color { ColorAnimation { duration: 130 } }

    Rectangle {
        anchors.fill: parent
        anchors.margins: 2
        radius: 8
        color: "transparent"
        border.width: 1
        border.color: Qt.rgba(root.accent.r, root.accent.g, root.accent.b,
                              mouseArea.containsMouse ? 0.20 : 0.07)
    }

    Rectangle {
        width: 3
        height: parent.height - 18
        radius: 2
        anchors.left: parent.left
        anchors.leftMargin: 6
        anchors.verticalCenter: parent.verticalCenter
        color: root.accent
        opacity: mouseArea.containsMouse ? 1.0 : 0.72
    }

    Row {
        anchors.fill: parent
        anchors.leftMargin: 15
        anchors.rightMargin: 12
        spacing: 10

        Item {
            width: 46
            height: parent.height

            Rectangle {
                width: 40
                height: 40
                radius: 9
                anchors.centerIn: parent
                color: "#061420"
                border.width: 1
                border.color: Qt.rgba(root.accent.r, root.accent.g, root.accent.b, 0.45)

                Image {
                    anchors.centerIn: parent
                    width: 36
                    height: 36
                    source: root.iconSource
                    fillMode: Image.PreserveAspectFit
                    smooth: true
                    mipmap: true
                    asynchronous: true
                }
            }
        }

        Column {
            width: parent.width - 86
            anchors.verticalCenter: parent.verticalCenter
            spacing: 2

            Text {
                width: parent.width
                text: root.title
                color: "#edf7ff"
                font.family: "Bahnschrift SemiCondensed"
                font.pixelSize: 13
                font.bold: true
                elide: Text.ElideRight
            }
            Text {
                width: parent.width
                text: root.subtitle
                color: "#7792a8"
                font.family: "Segoe UI Variable"
                font.pixelSize: 9
                elide: Text.ElideRight
            }
        }

        Text {
            width: 16
            height: parent.height
            text: "›"
            color: root.accent
            font.pixelSize: 18
            font.bold: true
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
            opacity: mouseArea.containsMouse ? 1 : 0.65
        }
    }

    MouseArea {
        id: mouseArea
        anchors.fill: parent
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: root.clicked()
    }
}
