"""
Launch script for Phishing URL Detector
Starts a local lightweight HTTP server and automatically opens the application in your default web browser.
"""
import http.server
import socketserver
import webbrowser
import threading
import os
import sys

PORT = 8000

class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        sys.stdout.write(f"[{self.log_date_time_string()}] {args[0]} {args[1]}\n")

def start_server():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    port = PORT
    server = None
    for p in range(PORT, PORT + 20):
        try:
            server = socketserver.TCPServer(("", p), QuietHandler)
            port = p
            break
        except OSError:
            continue

    if not server:
        print("Could not bind to any port between 8000 and 8020. Opening index.html directly...")
        webbrowser.open(f"file://{os.path.abspath('index.html')}")
        return

    url = f"http://localhost:{port}/index.html"
    print("=" * 60)
    print("      PHISHING URL DETECTOR - LAUNCH SUCCESSFUL")
    print("=" * 60)
    print(f" Web Application running at: {url}")
    print(" Press Ctrl+C in this terminal to stop the server.")
    print("=" * 60 + "\n")

    threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server. Goodbye!")
        server.server_close()

if __name__ == "__main__":
    start_server()
