"""Analyse des macros Office (oletools). Lancé SANS privilèges par l'utilisateur avscan.

Entrée : chemins séparés par des octets nuls sur stdin.
Sortie : une ligne JSON par fichier.
"""
import json
import os
import sys


def main():
    try:
        from oletools.mraptor import MacroRaptor
        from oletools.olevba import VBA_Parser
    except Exception as e:  # paquet absent ou cassé
        print(json.dumps({"error": f"oletools indisponible : {e}"}), flush=True)
        return
    for raw in sys.stdin.buffer.read().split(b"\0"):
        if not raw:
            continue
        path = os.fsdecode(raw)
        res = {"path": path}
        vp = None
        try:
            vp = VBA_Parser(path)
            if vp.detect_vba_macros():
                code = "\n".join(c for (_, _, _, c) in vp.extract_macros() if c)
                mr = MacroRaptor(code)
                mr.scan()
                res["macro"] = True
                res["suspicious"] = bool(mr.suspicious)
                res["flags"] = mr.get_flags()
                res["keywords"] = [f"{t} {k}" for (t, k, _d) in vp.analyze_macros()
                                   if t in ("AutoExec", "Suspicious", "IOC")][:15]
            else:
                res["macro"] = False
        except Exception as e:
            res["error"] = str(e)[:200]
        finally:
            if vp is not None:
                try:
                    vp.close()
                except Exception:
                    pass
        print(json.dumps(res), flush=True)


if __name__ == "__main__":
    main()
