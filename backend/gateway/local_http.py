"""Small loopback-only JSON client for stdio integrations."""

import json
from http.client import HTTPConnection
from typing import Any


def request_json(
    port: int, method: str, path: str, body: dict[str, Any] | None = None
) -> Any:
    connection = HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        encoded = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"} if body is not None else {}
        connection.request(method, path, encoded, headers)
        with connection.getresponse() as response:
            if response.status != 200:
                raise ValueError("The local firewall did not return success.")
            payload = response.read(256 * 1024 + 1)
            if len(payload) > 256 * 1024:
                raise ValueError("The local firewall response was too large.")
            return json.loads(payload)
    finally:
        connection.close()
