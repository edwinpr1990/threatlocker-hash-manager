"""Frozen Windows entry point. Starts only a localhost dashboard, never a deletion."""
import argparse
import os
from pathlib import Path
import socket
import sys
import threading
import time
import urllib.request
import webbrowser


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8511)
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    root = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent))
    data = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'ThreatLockerHashManager'
    data.mkdir(parents=True, exist_ok=True)
    os.environ['TL_HASH_DATA_DIR'] = str(data)
    # Windowed executables have no stdout/stderr. Keep local startup diagnostics.
    if sys.stdout is None:
        sys.stdout = (data / 'startup.log').open('a', encoding='utf-8', buffering=1)
    if sys.stderr is None:
        sys.stderr = sys.stdout
    with socket.socket() as probe:
        try:
            probe.bind(('127.0.0.1', args.port))
        except OSError:
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, f'Port {args.port} is in use. Close the existing dashboard or launch with --port 8512.', 'ThreatLocker Hash Manager', 0x10)
            return 1
    url = f'http://127.0.0.1:{args.port}'
    if not args.no_browser:
        def open_when_ready():
            for _ in range(120):
                try:
                    with urllib.request.urlopen(url + '/_stcore/health', timeout=1) as response:
                        if response.status == 200:
                            webbrowser.open(url)
                            return
                except OSError:
                    pass
                time.sleep(0.5)
        threading.Thread(target=open_when_ready, daemon=True).start()
    # Do not load unrelated Streamlit project configuration from the launch directory.
    os.chdir(root)
    from streamlit.web import cli
    sys.argv = ['streamlit', 'run', str(root / 'app.py'),
                '--server.address', '127.0.0.1', '--server.port', str(args.port),
                '--server.headless', 'true', '--server.fileWatcherType', 'none',
                '--server.maxUploadSize', '512', '--browser.gatherUsageStats', 'false',
                '--global.developmentMode', 'false']
    return cli.main()


if __name__ == '__main__':
    raise SystemExit(main())
