"""Launch Argus as a local Windows desktop app.

Starts the Argus server (SIEM + threat intel) on a private loopback port
and shows the dashboard in a desktop window (Edge WebView2, via pywebview).
No browser and no manual API key entry: on first run the launcher creates
a private key and stores it with the SQLite databases under
%LOCALAPPDATA%\\Argus, then hands it to the dashboard through the URL
fragment (which the browser never sends to the server).

Build a double-clickable exe with build_windows.bat (PyInstaller).
Run from source with:  python desktop_app.py

The desktop app does not start the honeypot or the simulator.
"""

import os
import secrets
import socket
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path


def resource_root() -> Path:
    """Repo root when run from source, bundle dir when frozen by PyInstaller."""
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent


def data_dir() -> Path:
    """Private per-user storage for databases and the generated API key."""
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        base = Path(local_app_data)
    elif os.name == "nt":
        base = Path.home() / "AppData" / "Local"
    else:
        base = Path.home() / ".local" / "share"
    path = base / "Argus"
    path.mkdir(parents=True, exist_ok=True)
    return path


def load_or_create_key(path: Path) -> str:
    """Reuse the stored private key, or create one on first run."""
    if path.is_file():
        key = path.read_text(encoding="utf-8").strip()
        if key:
            return key
    key = secrets.token_urlsafe(32)
    path.write_text(key + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows has no POSIX modes; the folder is per-user anyway
    return key


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def start_server(port: int):
    """Run the unified Argus app in a background thread; return the server."""
    import uvicorn

    root = resource_root()
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    config = uvicorn.Config(
        "server.argus_app:app",
        host="127.0.0.1",
        port=port,
        log_level="warning",
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True, name="argus-server")
    thread.start()
    return server, thread


def wait_ready(port: int, timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    url = f"http://127.0.0.1:{port}/api/argus/health"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.25)
    return False


def show_fallback(url: str) -> None:
    """pywebview is missing or failed: tell the user the manual URL."""
    message = (
        "Argus is running, but the desktop window could not open.\n\n"
        f"Open this address in your browser:\n{url}\n\n"
        "The server stops when you close this message."
    )
    try:
        from tkinter import Tk, messagebox

        root = Tk()
        root.withdraw()
        messagebox.showinfo("Argus", message)
        root.destroy()
    except Exception:
        print(message)
        try:
            input("Press Enter to stop Argus...")
        except EOFError:
            pass


def main() -> int:
    try:
        data = data_dir()
        key = load_or_create_key(data / "api_key.txt")
        # The launcher owns storage for its own process: databases and key
        # live in the per-user data dir, never in the install folder.
        os.environ["ARGUS_API_KEY"] = key
        os.environ["ARGUS_DB"] = str(data / "argus.db")
        os.environ["ARGUS_TI_DB"] = str(data / "argus-ti.db")

        port = free_port()
        server, thread = start_server(port)
        if not wait_ready(port):
            print("Argus server did not start in time.", file=sys.stderr)
            server.should_exit = True
            return 1

        url = f"http://127.0.0.1:{port}/#api_key={key}"
        try:
            import webview

            webview.create_window("Argus", url, width=1280, height=800)
            webview.start()
        except Exception:
            traceback.print_exc()
            show_fallback(url)
        server.should_exit = True
        thread.join(timeout=10)
        return 0
    except Exception:
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
