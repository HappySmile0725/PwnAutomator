# -*- coding: utf-8 -*-
import os
import json
import re
import subprocess

from utils import GhidraContext as ctx, resolve_path

try:
    TEXT_TYPE = unicode
except NameError:
    TEXT_TYPE = str

FROM_IMAGE_RE = re.compile(r"^\s*FROM\s+([^\s]+)(?:\s+AS\s+\S+)?\s*$", re.I)


class MetaHandler:
    CMD_LIST = []

    @staticmethod
    def set_commands(cmds):
        MetaHandler.CMD_LIST = list(cmds)

    @staticmethod
    def _to_text(data):
        if data is None:
            return ""
        if isinstance(data, TEXT_TYPE):
            return data
        if hasattr(data, "decode"):
            try:
                return data.decode("utf-8", "ignore")
            except UnicodeDecodeError:
                return data.decode("latin-1", "ignore")
        return str(data)

    @staticmethod
    def _parse_json(raw):
        raw = raw.strip()
        if not raw:
            return None
        
        candidates = [raw]
        
        p1, p2 = raw.find("{"), raw.rfind("}")
        if p1 >= 0 and p2 > p1:
            candidates.append(raw[p1:p2 + 1])
        
        p1, p2 = raw.find("["), raw.rfind("]")
        if p1 >= 0 and p2 > p1:
            candidates.append(raw[p1:p2 + 1])

        for c in candidates:
            try:
                return json.loads(c)
            except ValueError:
                continue
        return None

    @staticmethod
    def _normalize_checksec(parsed, binary_path):
        if isinstance(parsed, list) and len(parsed) == 1:
            parsed = parsed[0]
        
        if isinstance(parsed, dict) and binary_path:
            if binary_path in parsed:
                return parsed[binary_path]
            
            bn = os.path.basename(binary_path)
            if bn in parsed:
                return parsed[bn]
            
        return parsed

    @staticmethod
    def _collect_checksec(binary_path):
        resolved_path = resolve_path(binary_path)
        
        if not resolved_path:
            return {"available": False, "error": "No binary path"}

        cmds = [
            ["checksec", "--output=json", "--file=%s" % resolved_path],
            ["checksec", "--file=%s" % resolved_path],
            ["pwn", "checksec", "--file", resolved_path]
        ]
        
        last_err = None
        for c in cmds:
            try:
                p = subprocess.Popen(c, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = p.communicate()
            except (OSError, IOError) as e:
                last_err = str(e)
                continue
            
            out_txt = MetaHandler._to_text(out).strip()
            err_txt = MetaHandler._to_text(err).strip()
            raw = out_txt if out_txt else err_txt
            
            if p.returncode != 0:
                last_err = raw or ("exit code %d" % p.returncode)
                continue
                
            if not raw:
                last_err = "empty output"
                continue
                
            parsed = MetaHandler._parse_json(raw)
            res = MetaHandler._normalize_checksec(parsed, binary_path) if parsed else raw
            
            return {
                "available": True,
                "binary_path": binary_path,
                "resolved_path": resolved_path,
                "command": " ".join(c),
                "result": res
            }
            
        return {
            "available": False,
            "binary_path": binary_path,
            "resolved_path": resolved_path,
            "error": last_err or "checksec failed"
        }

    @staticmethod
    def _resolve_binary_path(args):
        args = args or {}

        ex_path = args.get("binary_path")
        runtime_path = os.environ.get("GHIDRA_MCP_BINARY_PATH")
        if not ex_path and runtime_path:
            ex_path = runtime_path

        if not ex_path:
            p = ctx.program.getExecutablePath()
            if p:
                ex_path = str(p)

        return ex_path, runtime_path

    @staticmethod
    def _collect_ubuntu(binary_path):
        resolved_path = resolve_path(binary_path)
        if not resolved_path:
            return {"available": False, "error": "No binary path"}

        dockerfile_path = os.path.join(os.path.dirname(resolved_path), "Dockerfile")
        if not os.path.exists(dockerfile_path):
            return {
                "available": False,
                "resolved_binary_path": resolved_path,
                "dockerfile_path": dockerfile_path,
                "error": "Dockerfile not found"
            }

        try:
            with open(dockerfile_path, "r") as handle:
                lines = handle.readlines()
        except (IOError, OSError) as e:
            return {
                "available": False,
                "resolved_binary_path": resolved_path,
                "dockerfile_path": dockerfile_path,
                "error": str(e)
            }

        for raw_line in lines:
            line = MetaHandler._to_text(raw_line).strip()
            if not line or line.startswith("#"):
                continue

            match = FROM_IMAGE_RE.match(line)
            if not match:
                continue

            image = match.group(1)
            image_lower = image.lower()
            if image_lower == "ubuntu" or image_lower.startswith("ubuntu:"):
                version = "latest"
                if ":" in image:
                    version = image.split(":", 1)[1]
                return {
                    "available": True,
                    "resolved_binary_path": resolved_path,
                    "dockerfile_path": dockerfile_path,
                    "image": image,
                    "version": version
                }

        return {
            "available": False,
            "resolved_binary_path": resolved_path,
            "dockerfile_path": dockerfile_path,
            "error": "Ubuntu base image not found"
        }

    @staticmethod
    def get_meta(args):
        ex_path, runtime_path = MetaHandler._resolve_binary_path(args)
        ubuntu = MetaHandler._collect_ubuntu(ex_path)

        return {
            "name": ctx.program.getName(),
            "arch": str(ctx.program.getLanguage()),
            "base": str(ctx.program.getImageBase()),
            "executable_path": ex_path,
            "runtime_binary_path": runtime_path,
            "checksec": MetaHandler._collect_checksec(ex_path),
            "ubuntu_version": ubuntu.get("version") if ubuntu.get("available") else None,
            "ubuntu": ubuntu,
            "commands": MetaHandler.CMD_LIST
        }
