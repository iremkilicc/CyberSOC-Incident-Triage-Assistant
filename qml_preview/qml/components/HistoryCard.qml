import QtQuick
import QtQuick.Controls

Rectangle {
    id: root
    property string incidentTitle: "Suspicious PowerShell"
    property string timeText: "Yesterday · 16:28"
    property string riskLabel: "HIGH"
    property color riskColor: "#ff7043"
    property url iconSource: ""
    property bool selected: false
    signal clicked()
    signal menuClicked(real globalX, real globalY)

    implicitHeight: 82
    radius: 9
    color: selected ? "#082744" : mouseArea.containsMouse ? "#081d30" : "#061421"
    border.width: selected ? 1.4 : 1
    border.color: selected ? "#19a7ff" : mouseArea.containsMouse ? "#18557b" : "#102d44"

    Rectangle {
        id: glowLayer
        anchors.fill: parent
        anchors.margins: 2
        radius: 7
        color: "transparent"
        border.width: selected ? 1 : 0
        border.color: selected ? Qt.rgba(0.12, 0.70, 1.0, 0.30) : "transparent"
    }

    Rectangle {
        width: 3
        radius: 2
        color: root.riskColor
        anchors.left: parent.left
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        anchors.margins: 7
    }

    Item {
        id: iconBox
        width: 54
        height: 54
        anchors.left: parent.left
        anchors.leftMargin: 13
        anchors.verticalCenter: parent.verticalCenter

        Rectangle {
            anchors.fill: parent
            radius: 9
            color: "#071727"
            border.width: 1
            border.color: Qt.rgba(root.riskColor.r, root.riskColor.g, root.riskColor.b, 0.28)
        }

        Image {
            anchors.centerIn: parent
            width: 49
            height: 49
            source: root.iconSource
            fillMode: Image.PreserveAspectFit
            smooth: true
            mipmap: true
        }
    }

    Column {
        anchors.left: iconBox.right
        anchors.leftMargin: 10
        anchors.right: riskBadge.left
        anchors.rightMargin: 8
        anchors.verticalCenter: parent.verticalCenter
        spacing: 5

        Text {
            width: parent.width
            text: root.incidentTitle
            color: "#edf7ff"
            font.family: "Segoe UI Variable"
            font.pixelSize: 11
            font.bold: true
            elide: Text.ElideRight
        }
        Text {
            text: root.timeText
            color: "#7894ab"
            font.family: "Segoe UI Variable"
            font.pixelSize: 9
        }
    }

    RiskBadge {
        id: riskBadge
        anchors.right: parent.right
        anchors.rightMargin: 11
        anchors.top: parent.top
        anchors.topMargin: 10
        label: root.riskLabel
        accent: root.riskColor
        scale: 0.83
        transformOrigin: Item.TopRight
    }

    Text {
        anchors.right: menuButton.left
        anchors.rightMargin: 7
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 9
        text: "▢"
        color: root.selected ? "#36cfff" : "#527188"
        font.pixelSize: 10
    }

    ToolButton {
        id: menuButton
        width: 24
        height: 24
        anchors.right: parent.right
        anchors.rightMargin: 6
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 4
        text: "⋮"
        hoverEnabled: true

        contentItem: Text {
            text: menuButton.text
            color: menuButton.hovered ? "#d9f3ff" : "#66839a"
            font.pixelSize: 16
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
        }
        background: Rectangle {
            radius: 6
            color: menuButton.hovered ? "#102b42" : "transparent"
        }
        onClicked: {
            const point = mapToItem(null, width / 2, height)
            root.menuClicked(point.x, point.y)
        }
    }

    MouseArea {
        id: mouseArea
        anchors.fill: parent
        anchors.rightMargin: 30
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: root.clicked()
    }
}
