import QtQuick

Item {
    id: root

    property int score: 0
    property string riskLabel: score > 0 ? "MEDIUM" : "AWAITING"
    property color riskColor: "#20d7ff"
    property bool scanning: false
    property real sweepAngle: -38
    property real pulse: 0

    Canvas {
        id: canvas
        anchors.fill: parent
        antialiasing: true

        onPaint: {
            const ctx = getContext("2d")
            const w = width
            const h = height
            const cx = w / 2
            const cy = h / 2
            const r = Math.min(w, h) * 0.405
            ctx.reset()

            // Wide atmospheric halo.
            const halo = ctx.createRadialGradient(cx, cy, r * 0.12, cx, cy, r * 1.30)
            halo.addColorStop(0, "rgba(0,122,255,0.12)")
            halo.addColorStop(0.62, "rgba(0,126,255,0.055)")
            halo.addColorStop(1, "rgba(0,0,0,0)")
            ctx.fillStyle = halo
            ctx.fillRect(0, 0, w, h)

            // Outer rings.
            ctx.lineWidth = 1
            for (let i = 1; i <= 6; i++) {
                ctx.beginPath()
                ctx.arc(cx, cy, r * i / 6, 0, Math.PI * 2)
                ctx.strokeStyle = i === 6
                    ? "rgba(28,181,255,0.92)"
                    : (i % 2 === 0 ? "rgba(20,119,184,0.46)" : "rgba(18,83,132,0.38)")
                ctx.stroke()
            }

            // Dashed outer guide.
            ctx.setLineDash([3, 6])
            ctx.beginPath()
            ctx.arc(cx, cy, r * 1.10, 0, Math.PI * 2)
            ctx.strokeStyle = "rgba(34,148,215,0.42)"
            ctx.stroke()
            ctx.setLineDash([])

            // Radial grid and edge ticks.
            for (let deg = 0; deg < 360; deg += 15) {
                const a = deg * Math.PI / 180
                const major = deg % 30 === 0
                if (major) {
                    ctx.beginPath()
                    ctx.moveTo(cx, cy)
                    ctx.lineTo(cx + Math.cos(a) * r, cy + Math.sin(a) * r)
                    ctx.strokeStyle = "rgba(17,84,131,0.44)"
                    ctx.stroke()
                }
                ctx.beginPath()
                ctx.moveTo(cx + Math.cos(a) * r * 1.02, cy + Math.sin(a) * r * 1.02)
                ctx.lineTo(cx + Math.cos(a) * r * (major ? 1.09 : 1.06), cy + Math.sin(a) * r * (major ? 1.09 : 1.06))
                ctx.strokeStyle = major ? "rgba(53,187,255,0.75)" : "rgba(30,116,174,0.45)"
                ctx.stroke()
            }

            // Scanner wedge. Active analysis rotates; resting state stays at a premium angle.
            const sweep = root.sweepAngle * Math.PI / 180
            const wedge = ctx.createRadialGradient(cx, cy, 0, cx, cy, r)
            wedge.addColorStop(0, root.scanning ? "rgba(57,204,255,0.38)" : "rgba(45,181,255,0.25)")
            wedge.addColorStop(0.65, "rgba(24,153,255,0.12)")
            wedge.addColorStop(1, "rgba(20,130,255,0)")
            ctx.beginPath()
            ctx.moveTo(cx, cy)
            ctx.arc(cx, cy, r, sweep - 0.55, sweep)
            ctx.closePath()
            ctx.fillStyle = wedge
            ctx.fill()

            ctx.beginPath()
            ctx.moveTo(cx, cy)
            ctx.lineTo(cx + Math.cos(sweep) * r, cy + Math.sin(sweep) * r)
            ctx.lineWidth = 2
            ctx.strokeStyle = root.scanning ? "rgba(93,229,255,1)" : "rgba(65,196,255,0.88)"
            ctx.stroke()

            // Blips. They remain visible for historical incidents and pulse during a new scan.
            if (root.score > 0 || root.scanning) {
                const points = [
                    [0.72, -38, "#ff4055"],
                    [0.58, 12, "#2edcff"],
                    [0.67, 54, "#ff8b38"],
                    [0.77, 116, "#2edcff"],
                    [0.53, 179, "#ff9b35"],
                    [0.79, 229, "#ff4055"],
                    [0.49, 301, "#2edcff"]
                ]
                points.forEach(function(p, idx) {
                    const a = p[1] * Math.PI / 180
                    const x = cx + Math.cos(a) * r * p[0]
                    const y = cy + Math.sin(a) * r * p[0]
                    const wave = 7 + ((root.pulse + idx * 0.18) % 1) * 7

                    ctx.beginPath()
                    ctx.arc(x, y, wave, 0, Math.PI * 2)
                    ctx.fillStyle = p[2] === "#2edcff" ? "rgba(46,220,255,0.08)" : "rgba(255,68,72,0.09)"
                    ctx.fill()

                    ctx.beginPath()
                    ctx.arc(x, y, 4.0, 0, Math.PI * 2)
                    ctx.fillStyle = p[2]
                    ctx.fill()

                    ctx.beginPath()
                    ctx.arc(x, y, 6.4, 0, Math.PI * 2)
                    ctx.strokeStyle = p[2] === "#2edcff" ? "rgba(46,220,255,0.42)" : "rgba(255,72,72,0.48)"
                    ctx.stroke()
                })
            }
        }

        Connections {
            target: root
            function onSweepAngleChanged() { canvas.requestPaint() }
            function onScoreChanged() { canvas.requestPaint() }
            function onScanningChanged() { canvas.requestPaint() }
            function onPulseChanged() { canvas.requestPaint() }
        }
    }

    NumberAnimation on sweepAngle {
        from: 0
        to: 360
        duration: 4200
        loops: Animation.Infinite
        running: root.scanning
    }

    NumberAnimation on pulse {
        from: 0
        to: 1
        duration: 1700
        loops: Animation.Infinite
        running: root.scanning || root.score > 0
    }

    Rectangle {
        id: centerDisc
        width: Math.max(94, Math.min(parent.width, parent.height) * 0.27)
        height: width
        radius: width / 2
        anchors.centerIn: parent
        color: "#061421"
        border.width: 2
        border.color: root.score > 0 ? root.riskColor : "#1aa7ed"

        Rectangle {
            anchors.fill: parent
            anchors.margins: 7
            radius: width / 2
            color: "transparent"
            border.width: 1
            border.color: Qt.rgba(root.riskColor.r, root.riskColor.g, root.riskColor.b, 0.22)
        }

        Column {
            anchors.centerIn: parent
            spacing: -1

            Text {
                anchors.horizontalCenter: parent.horizontalCenter
                text: root.score > 0 ? root.score : "--"
                color: "#edf8ff"
                font.pixelSize: root.score > 0 ? 36 : 30
                font.family: "Bahnschrift SemiCondensed"
                font.bold: true
            }
            Text {
                anchors.horizontalCenter: parent.horizontalCenter
                text: root.scanning ? "SCANNING" : (root.score > 0 ? root.riskLabel : "AWAITING")
                color: root.scanning ? "#32dbff" : (root.score > 0 ? root.riskColor : "#6f92aa")
                font.pixelSize: 11
                font.family: "Segoe UI Variable"
                font.bold: true
            }
        }
    }
}
