import gdb
import os


class GdbHandler:
    def __init__(self, server):
        self.server = server

    @staticmethod
    def ok(result=None):
        return {"ok": True, "result": {} if result is None else result}

    @staticmethod
    def err(message):
        return {"ok": False, "error": str(message)}


def gdb_quote_path(path):
    text = str(path).replace("\\", "\\\\").replace('"', '\\"')
    return '"' + text + '"'


def loaded_binary_path():
    current_progspace = getattr(gdb, "current_progspace", None)
    if not callable(current_progspace):
        return ""

    progspace = current_progspace()
    filename = getattr(progspace, "filename", None)
    if not filename:
        return ""
    return os.path.realpath(str(filename))


__all__ = ["GdbHandler", "gdb_quote_path", "loaded_binary_path"]
