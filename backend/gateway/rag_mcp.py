"""Codex MCP server for locally guarded note retrieval."""

import argparse
import json
import sys
from http.client import HTTPException
from typing import Any

from backend.gateway.local_http import request_json

TOOLS = [
    {
        "name": "list_notes",
        "description": "List available guarded local note IDs and titles.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    },
    {
        "name": "read_note",
        "description": "Read a local note by ID through the prompt firewall before using its contents.",
        "inputSchema": {
            "type": "object",
            "properties": {"note": {"type": "string", "maxLength": 60}},
            "required": ["note"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    },
]


def reply(message: dict[str, Any], port: int) -> dict[str, Any]:
    envelope = {"jsonrpc": "2.0", "id": message["id"]}
    method = message.get("method")
    params = message.get("params", {})
    if method == "initialize":
        return {
            **envelope,
            "result": {
                "protocolVersion": params["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "guarded-firewall-notes", "version": "1.0.0"},
            },
        }
    if method == "ping":
        return {**envelope, "result": {}}
    if method == "tools/list":
        return {**envelope, "result": {"tools": TOOLS}}
    if method == "tools/call":
        try:
            tool = params.get("name")
            arguments = params.get("arguments") or {}
            if tool == "list_notes" and not arguments:
                notes = request_json(port, "GET", "/api/guarded-notes")
                text = json.dumps(notes)
            elif (
                tool == "read_note"
                and isinstance(arguments, dict)
                and isinstance(arguments.get("note"), str)
            ):
                note = request_json(
                    port, "POST", "/api/guarded-notes/read", {"note": arguments["note"]}
                )
                text = note["text"]
                if not isinstance(text, str):
                    raise ValueError("Invalid guarded note response.")
            else:
                return {
                    **envelope,
                    "error": {"code": -32602, "message": "Unknown tool or arguments."},
                }
        except (OSError, HTTPException, ValueError, TypeError, KeyError):
            return {
                **envelope,
                "result": {
                    "isError": True,
                    "content": [
                        {
                            "type": "text",
                            "text": "Guarded retrieval could not return this note.",
                        }
                    ],
                },
            }
        return {**envelope, "result": {"content": [{"type": "text", "text": text}]}}
    return {**envelope, "error": {"code": -32601, "message": "Method not found."}}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8010)
    args = parser.parse_args()
    for line in sys.stdin:
        try:
            message = json.loads(line)
            if isinstance(message, dict) and "id" in message:
                print(json.dumps(reply(message, args.port)), flush=True)
        except (AttributeError, KeyError, TypeError, ValueError, RecursionError):
            print(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32600, "message": "Invalid MCP request."},
                    }
                ),
                flush=True,
            )


if __name__ == "__main__":
    main()
