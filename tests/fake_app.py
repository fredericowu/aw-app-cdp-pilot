"""A fake Chromium-ish app for tests: prints the DevTools line, serves
/json/list and a minimal CDP websocket. Run via an executable wrapper."""
import base64
import hashlib
import json
import socket
import struct
import sys
import threading
import time

MODE = sys.argv[0] and __import__("os").environ.get("FAKE_APP_MODE", "ok")
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 70000  # > 64 KiB: exercises 64-bit frame lengths
state = {"clicked": 0, "typed": "", "value": "old", "selected": False}


def frame(payload: bytes) -> bytes:
    n = len(payload)
    if n < 126:
        return bytes([0x81, n]) + payload
    if n < 65536:
        return bytes([0x81, 126]) + struct.pack(">H", n) + payload
    return bytes([0x81, 127]) + struct.pack(">Q", n) + payload


def read_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise EOFError
        data += chunk
    return data


def read_frame(conn):
    b0, b1 = read_exact(conn, 2)
    n = b1 & 0x7F
    if n == 126:
        n = struct.unpack(">H", read_exact(conn, 2))[0]
    elif n == 127:
        n = struct.unpack(">Q", read_exact(conn, 8))[0]
    mask = read_exact(conn, 4)
    data = bytes(b ^ mask[i % 4] for i, b in enumerate(read_exact(conn, n)))
    return b0 & 0x0F, data


def handle_cdp(msg):
    method, params = msg["method"], msg.get("params", {})
    if method == "Runtime.evaluate":
        return {"result": {"objectId": "g1"}}
    if method == "Runtime.callFunctionOn":
        fn = params["functionDeclaration"]
        arg = params["arguments"][0]["value"] if params["arguments"] else None
        if "no-such" in str(arg):
            return {"result": {"value": {"error": "no visible match", "matches": 0}}}
        if "boom" in str(arg):
            return {"exceptionDetails": {"text": "x"}}
        if "count: nodes.length" in fn and arg == "huge":
            return {"result": {"value": {"count": 100, "returned": 100, "title": "Fake",
                                         "nodes": [{"tag": "p", "text": "x" * 20000}] * 100}}}
        if "count: nodes.length" in fn:
            return {"result": {"value": {"count": 1, "returned": 1, "title": "Fake",
                                         "nodes": [{"tag": "button", "text": "Log in",
                                                    "value": state["value"]}]}}}
        if "scrollIntoView" in fn:
            return {"result": {"value": {"x": 10, "y": 20}}}
        if "document.activeElement" in fn:
            if MODE == "no_focus":
                return {"result": {"value": {"error": "no focused element"}}}
            state["selected"] = True
            return {"result": {"value": {"ok": True}}}
        if "el.focus" in fn and "focus-miss" in str(arg):
            return {"result": {"value": {"error": "no match"}}}
        if "el.focus" in fn:
            state["selected"] = bool(params["arguments"][1]["value"])
            return {"result": {"value": {"ok": True}}}
        return {"result": {"value": None}}
    if method == "Input.dispatchMouseEvent" and params["type"] == "mouseReleased":
        state["clicked"] += 1
    if method == "Input.insertText":
        state["typed"] = params["text"]
        # a selection is replaced; otherwise the text is appended to the value
        state["value"] = params["text"] if state["selected"] else state["value"] + params["text"]
        state["selected"] = False
    if method == "Page.captureScreenshot":
        return {"data": base64.b64encode(PNG).decode()}
    if method == "Input.fail":
        return {"__error__": "nope"}
    return {}


def serve_ws(conn):
    try:
        conn.sendall(frame(b'{"method":"Noise.event","params":{}}'))
        conn.sendall(bytes([0x89, 0]))  # ping
        while True:
            op, data = read_frame(conn)
            if op == 0x8:
                return
            if op != 0x1:
                continue
            msg = json.loads(data)
            out = handle_cdp(msg)
            if "__error__" in out:
                reply = {"id": msg["id"], "error": {"message": out["__error__"]}}
            else:
                reply = {"id": msg["id"], "result": out}
            raw = json.dumps(reply).encode()
            half = len(raw) // 2  # fragmented: exercises continuation frames
            conn.sendall(bytes([0x01, half]) + raw[:half] if half < 126 else frame(raw))
            if half < 126:
                conn.sendall(bytes([0x80, len(raw) - half]) + raw[half:])
    except (EOFError, OSError):
        pass
    finally:
        conn.close()


def serve(conn, port):
    head = b""
    while b"\r\n\r\n" not in head:
        head += conn.recv(4096)
    line = head.split(b"\r\n")[0].decode()
    if "/json/list" in line:
        body = json.dumps([
            {"id": "PAGE1", "type": "page", "title": "AW Desktop",
             "url": "file:///x/index.html?token=SECRET#frag",
             "webSocketDebuggerUrl": f"ws://127.0.0.1:{port}/devtools/page/PAGE1"},
            {"id": "SW1", "type": "service_worker", "title": "sw", "url": "https://x/sw.js"},
        ]).encode()
        if MODE == "evil_ws":
            body = body.replace(f"127.0.0.1:{port}".encode(), b"10.9.9.9:80")
        if MODE == "no_pages":
            body = b"[]"
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                     + str(len(body)).encode() + b"\r\n\r\n" + body)
        conn.close()
        return
    key = [h for h in head.decode().split("\r\n") if h.lower().startswith("sec-websocket-key")][0]
    key = key.split(":")[1].strip()
    accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
    if "/devtools/page/BAD" in line:
        conn.sendall(b"HTTP/1.1 400 Bad\r\n\r\n")
        conn.close()
        return
    conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                 b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n")
    serve_ws(conn)


def main():
    if MODE == "exit_now":
        sys.exit(3)
    if MODE == "hang":
        time.sleep(600)
    if MODE == "slow":
        time.sleep(3)  # startup longer than the session ttl used in the test
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    print(f"DevTools listening on ws://127.0.0.1:{port}/devtools/browser/abc", file=sys.stderr, flush=True)
    if MODE == "exit_soon":
        threading.Timer(1.0, lambda: __import__("os")._exit(0)).start()
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=serve, args=(conn, port), daemon=True).start()


if __name__ == "__main__":
    main()
