#!/usr/bin/env python3

"""Test an Ollama-compatible endpoint without touching Security VM data.

This helper lists remote models and sends a tiny connectivity prompt. It is a
diagnostic command only: no case evidence, API key, or SQLite row is involved.
"""

import argparse
import requests


def main():
    """Parse the target endpoint, verify it, and print one model response."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True, help="Example: http://127.0.0.1:11434")
    parser.add_argument("--model", default="gemma4:e4b")
    args = parser.parse_args()

    tags = requests.get(f"{args.host}/api/tags", timeout=15)
    tags.raise_for_status()
    print(tags.json())

    response = requests.post(
        f"{args.host}/api/generate",
        json={
            "model": args.model,
            "prompt": "Reply with one short sentence confirming connectivity.",
            "stream": False,
        },
        timeout=90,
    )
    response.raise_for_status()
    print(response.json().get("response", "").strip())


if __name__ == "__main__":
    main()
