#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import socket


def _normalize_connect_host(host):
    text = str(host or "").strip()
    if text == "" or text == "0.0.0.0":
        return "127.0.0.1"
    return text


class GhidraMCP:
    def __init__(self, host='127.0.0.1', port=9999):
        self.host = _normalize_connect_host(host)
        self.port = port

    @staticmethod
    def _recv_one_json(sock):
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
            if b"\n" in data:
                break
        if not chunks:
            raise Exception("empty response (server closed connection)")
        raw = b"".join(chunks).decode("utf-8").strip()
        if not raw:
            raise Exception("empty response payload")
        return json.loads(raw)

    def call(self, cmd, **args):
        with socket.create_connection((self.host, self.port)) as sock:
            payload = json.dumps({"cmd": cmd, "args": args}).encode("utf-8") + b"\n"
            sock.sendall(payload)
            res = self._recv_one_json(sock)

        if res.get("ok"):
            return res.get("result")
        raise Exception(res.get("error"))
