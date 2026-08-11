from __future__ import annotations

import ctypes
import os
import sys
import traceback
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QUrl, qInstallMessageHandler
from PySide6.QtGui import QGuiApplication, QIcon
from PySide6.QtQml import QQmlApplicationEngine

ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parent
QML_FILE = ROOT / "qml" / "Main.qml"
LOG_FILE = PROJECT_ROOT / "qml_preview_error.log"
APP_ICON = ROOT / "assets" / "brand" / "cybersoc_app.ico"

# Local imports (bridge + card mapper live beside this file)
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from backend_bridge import BackendBridge  # noqa: E402


def write_log(message: str) -> None:
    try:
        with LOG_FILE.open("a", encoding="utf-8") as handle:
            handle.write(message.rstrip() + "\n")
    except OSError:
        pass


def show_native_error(message: str) -> None:
    if sys.platform == "win32":
        try:
            ctypes.windll.user32.MessageBoxW(
                0,
                message,
                "CyberSOC QML startup error",
                0x10,
            )
            return
        except Exception:
            pass
    print(message, file=sys.stderr)


def qt_message_handler(mode, context, message) -> None:  # noqa: ANN001
    location = ""
    if context is not None and getattr(context, "file", None):
        location = f" [{context.file}:{getattr(context, 'line', 0)}]"
    write_log(f"QT {mode}{location}: {message}")


def main() -> int:
    try:
        LOG_FILE.unlink(missing_ok=True)
        write_log(f"CyberSOC QML launch: {datetime.now().isoformat(timespec='seconds')}")
        write_log(f"Python: {sys.version}")
        write_log(f"QML: {QML_FILE}")

        os.environ.setdefault("QT_QUICK_CONTROLS_STYLE", "Basic")
        os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")
        qInstallMessageHandler(qt_message_handler)

        app = QGuiApplication(sys.argv)
        app.setApplicationName("CyberSOC")
        app.setOrganizationName("CyberSOC")
        if APP_ICON.exists():
            app.setWindowIcon(QIcon(str(APP_ICON)))

        bridge = BackendBridge()
        engine = QQmlApplicationEngine()
        engine.rootContext().setContextProperty("backend", bridge)
        engine.load(QUrl.fromLocalFile(str(QML_FILE)))

        if not engine.rootObjects():
            message = (
                "The CyberSOC QML interface could not be loaded.\n\n"
                f"Error details were saved to:\n{LOG_FILE}"
            )
            write_log("FATAL: QQmlApplicationEngine returned no root object.")
            show_native_error(message)
            return 1

        write_log("QML root object loaded successfully.")
        write_log("BackendBridge registered as context property 'backend'.")
        return app.exec()
    except Exception as error:
        write_log("FATAL PYTHON EXCEPTION:")
        write_log(traceback.format_exc())
        show_native_error(
            f"CyberSOC could not start.\n\n{error}\n\n"
            f"Details were saved to:\n{LOG_FILE}"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
