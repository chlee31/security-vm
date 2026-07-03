#!/usr/bin/env python3

import argparse
import requests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True, help="Example: http://127.0.0.1:11434")
    parser.add_argument("--model", default="llama3.2:latest")
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
