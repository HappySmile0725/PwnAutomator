# -*- coding: utf-8 -*-
import os
import json
import subprocess
from utils import GhidraContext as ctx

class MetaHandler:
    CMD_LIST = []

    @staticmethod
    def set_commands(cmds):
        MetaHandler.CMD_LIST = list(cmds)

    @staticmethod
    def _to_text(data):
        if data is None: return ""
        try: return data.decode("utf-8", "ignore")
        except:
            try: return data.decode("latin-1", "ignore")
            except: return str(data)

    @staticmethod
    def _parse_json(raw):
        raw = raw.strip()
        if not raw: return None
        
        candidates = [raw]
        
        # Try object
        p1, p2 = raw.find("{"), raw.rfind("}")
        if p1 >= 0 and p2 > p1: candidates.append(raw[p1:p2+1])
        
        # Try array
        p1, p2 = raw.find("["), raw.rfind("]")
        if p1 >= 0 and p2 > p1: candidates.append(raw[p1:p2+1])

        for c in candidates:
            try: return json.loads(c)
            except: continue
        return None

    @staticmethod
    def _normalize_checksec(parsed, binary_path):
        if isinstance(parsed, list) and len(parsed) == 1:
            parsed = parsed[0]
        
        if isinstance(parsed, dict) and binary_path:
            # check full path
            if binary_path in parsed: return parsed[binary_path]
            # check basename
            bn = os.path.basename(binary_path)
            if bn in parsed: return parsed[bn]
            
        return parsed

    @staticmethod
    def _collect_checksec(binary_path):
        if not binary_path:
            return {"available": False, "error": "No binary path"}

        cmds = [
            ["checksec", "--output=json", "--file=%s" % binary_path],
            ["checksec", "--file=%s" % binary_path],
            ["pwn", "checksec", "--file", binary_path]
        ]
        
        last_err = None
        for c in cmds:
            try:
                p = subprocess.Popen(c, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = p.communicate()
            except Exception as e:
                last_err = str(e)
                continue
            
            # Output handling
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
                "command": " ".join(c),
                "result": res
            }
            
        return {
            "available": False, 
            "binary_path": binary_path, 
            "error": last_err or "checksec failed"
        }

    @staticmethod
    def get_meta(args):
        args = args or {}
        
        # Get Executable Path
        ex_path = args.get("binary_path")
        if not ex_path:
            try:
                p = ctx.program.getExecutablePath()
                if p: ex_path = str(p)
            except: pass

        return {
            "name": ctx.program.getName(),
            "arch": str(ctx.program.getLanguage()),
            "base": str(ctx.program.getImageBase()),
            "executable_path": ex_path,
            "checksec": MetaHandler._collect_checksec(ex_path),
            "commands": MetaHandler.CMD_LIST
        }
