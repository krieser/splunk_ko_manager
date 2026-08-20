#!/usr/bin/env python3
"""Serve the dice roll web simulator locally."""

import argparse
import http.server
import socketserver
from pathlib import Path

SIMULATOR_DIR = Path(__file__).resolve().parent / "simulator"


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(SIMULATOR_DIR), **kwargs)


def main() -> None:
    parser = argparse.ArgumentParser(description="Dice Roll Simulator HTTP server")
    parser.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
    args = parser.parse_args()

    with socketserver.TCPServer(("", args.port), Handler) as httpd:
        print(f"Serving simulator at http://localhost:{args.port}/")
        print("Press Ctrl+C to stop.")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
