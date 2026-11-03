"""Start Cyber Twin on an available loopback port and open the dashboard."""
import argparse
import os
from pathlib import Path
import socket
from threading import Thread
import time
from urllib.parse import urlsplit
from urllib.request import urlopen
import webbrowser


def bind_local(preferred=None):
    ports = list(dict.fromkeys([p for p in [preferred, 8765, 8766, 18080, 0] if p is not None]))
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(('127.0.0.1', port))
            sock.listen(128)
            return sock
        except OSError:
            sock.close()
    raise RuntimeError('Windows did not allow a local port. Check local app/network restrictions.')


def open_when_ready(url):
    for _ in range(100):
        try:
            with urlopen(url + 'health', timeout=.5) as response:
                if response.status == 200:
                    webbrowser.open(url)
                    return
        except OSError:
            time.sleep(.1)


def main():
    parser = argparse.ArgumentParser(description='Open Cyber Twin')
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    os.chdir(root)
    try:
        from dotenv import load_dotenv
        import uvicorn
    except ImportError:
        print('First setup: run python -m pip install -r requirements.txt, then open Cyber Twin again.')
        return 1
    load_dotenv(root / '.env')
    preferred = None
    if os.getenv('GOOGLE_CLIENT_TYPE', 'web') == 'web':
        try:
            redirect = urlsplit(os.getenv('GOOGLE_REDIRECT_URI', ''))
            if redirect.hostname in {'localhost', '127.0.0.1'}:
                preferred = redirect.port
        except ValueError:
            pass
    sock = bind_local(preferred)
    port = sock.getsockname()[1]
    url = f'http://localhost:{port}/'
    os.environ['CYBERTWIN_APP_URL'] = url
    print(f'Cyber Twin is opening at {url}\nKeep this window open. Press Ctrl+C to stop.', flush=True)
    if not args.no_browser:
        Thread(target=open_when_ready, args=(url,), daemon=True).start()
    try:
        uvicorn.Server(uvicorn.Config('app.main:app', host='127.0.0.1', port=port, use_colors=False)).run(sockets=[sock])
    finally:
        sock.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
