import QtQuick

Rectangle {
    id: root

    property string title: "METRIC"
    property string value: "--"
    property string subtitle: ""
    property url iconSource: ""
    property color accent: "#20d7ff"

    implicitWidth: 136
    implicitHeight: 66
    radius: 9
    color: "#071724"
    border.width: 1
    border.color: Qt.rgba(accent.r, accent.g, accent.b, 0.30)

    Row {
        anchors.fill: parent
        anchors.margins: 8
        spacing: 8

        Rectangle {
            width: 36
            height: 36
            radius: 8
            anchors.verticalCenter: parent.verticalCenter
            color: "#06131f"
            border.width: 1
            border.color: Qt.rgba(root.accent.r, root.accent.g, root.accent.b, 0.45)

            Image {
                anchors.centerIn: parent
                width: 31
                height: 31
                source: root.iconSource
                fillMode: Image.PreserveAspectFit
                smooth: true
                mipmap: true
                asynchronous: true
            }
        }

        Column {
            width: parent.width - 44
            anchors.verticalCenter: parent.verticalCenter
            spacing: 0

            Text {
                width: parent.width
                text: root.title
                color: "#718da4"
                font.family: "Segoe UI Variable"
                font.pixelSize: 7
                font.bold: true
                elide: Text.ElideRight
            }
            Text {
                width: parent.width
                text: root.value
                color: root.accent
                font.family: "Bahnschrift SemiCondensed"
                font.pixelSize: 16
                font.bold: true
                elide: Text.ElideRight
            }
            Text {
                width: parent.width
                visible: root.subtitle.length > 0
                text: root.subtitle
                color: "#526f86"
                font.pixelSize: 7
                elide: Text.ElideRight
            }
        }
    }
}
