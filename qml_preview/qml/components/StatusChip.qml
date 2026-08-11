import QtQuick

GlowPanel {
    id: root

    property url iconSource: ""
    property string iconText: "●"
    property string title: "STATUS"
    property string value: "READY"
    property string subtitle: ""
    property color accent: "#25e6a4"

    implicitWidth: 158
    implicitHeight: 66
    panelColor: "#06101b"
    borderColor: "#12324d"
    glowColor: accent
    glowOpacity: 0.08
    radiusValue: 9

    Row {
        anchors.fill: parent
        anchors.margins: 9
        spacing: 9

        Rectangle {
            width: 42
            height: 42
            radius: 9
            color: "#071827"
            border.width: 1
            border.color: Qt.rgba(root.accent.r, root.accent.g, root.accent.b, 0.48)
            anchors.verticalCenter: parent.verticalCenter

            Image {
                anchors.centerIn: parent
                width: 38
                height: 38
                source: root.iconSource
                visible: root.iconSource.toString().length > 0
                fillMode: Image.PreserveAspectFit
                smooth: true
                mipmap: true
                asynchronous: true
            }

            Text {
                anchors.centerIn: parent
                visible: root.iconSource.toString().length === 0
                text: root.iconText
                color: root.accent
                font.pixelSize: 14
                font.bold: true
            }
        }

        Column {
            width: parent.width - 51
            anchors.verticalCenter: parent.verticalCenter
            spacing: 1

            Text {
                width: parent.width
                text: root.title
                color: "#839bb0"
                font.pixelSize: 8
                font.family: "Segoe UI Variable"
                font.bold: true
                elide: Text.ElideRight
            }
            Text {
                width: parent.width
                text: root.value
                color: root.accent
                font.pixelSize: 11
                font.family: "Segoe UI Variable"
                font.bold: true
                elide: Text.ElideRight
            }
            Text {
                width: parent.width
                visible: root.subtitle.length > 0
                text: root.subtitle
                color: "#607c92"
                font.pixelSize: 7
                font.family: "Segoe UI Variable"
                elide: Text.ElideRight
            }
        }
    }
}
