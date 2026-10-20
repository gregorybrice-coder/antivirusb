"""Constantes et utilitaires communs."""
import json
import os
import re
import subprocess
import tempfile
import time
import traceback
from collections import namedtuple
from pathlib import Path

# Espace de stockage persistant (disque interne de la station, étiquette AVDATA)
DATA = Path("/srv/avdata")
CLAM_STORE = DATA / "clamav"          # monté par-dessus /var/lib/clamav
CLAM_DB = Path("/var/lib/clamav")
YARA_DIR = DATA / "yara"
YARA_RULES = YARA_DIR / "rules.yarc"
QUAR = DATA / "quarantine"
LOGS = DATA / "logs"
CONF_FILE = DATA / "config.json"

MNT_ROOT = Path("/mnt/avscan")        # points de montage des clés analysées
LIB = Path(__file__).resolve().parent.parent
DEBUG_LOG = Path("/var/log/antivirusb.log")

SCAN_USER = "avscan"                  # les analyseurs tournent sans privilèges
QUAR_PASSWORD = "infected"            # convention habituelle pour les archives de malwares
DEFS_WARN_DAYS = 2                    # au-delà : rappel de mise à jour
DEFS_OLD_DAYS = 7                     # au-delà : avertissement fort

STATE = {"ram": False}

Result = namedtuple("Result", "rc out err")


def log(msg):
    try:
        with open(DEBUG_LOG, "a", encoding="utf-8", errors="replace") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + str(msg) + "\n")
    except OSError:
        pass


def log_exception(exc):
    log("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))


def _as_user(cmd, user):
    cmd = [str(c) for c in cmd]
    return ["runuser", "-u", user, "--"] + cmd if user else cmd


def run(cmd, timeout=None, user=None, input=None):
    """Lance une commande et renvoie (rc, stdout, stderr) sans jamais lever d'exception."""
    cmd = _as_user(cmd, user)
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, input=input)
        out, err, rc = r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired as e:
        out, err, rc = e.stdout or b"", (e.stderr or b"") + b"\n[delai depasse]", 124
    except OSError as e:
        out, err, rc = b"", str(e).encode(), 127
    return Result(rc, os.fsdecode(out), os.fsdecode(err))


def run_progress(gauge, cmd, lo, hi, label, est=60, user=None, stdin_bytes=None, timeout=None):
    """Lance une commande longue en faisant avancer une jauge (progression estimée)."""
    cmd = _as_user(cmd, user)
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            p = subprocess.Popen(cmd, stdout=out, stderr=err,
                                 stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL)
        except OSError as e:
            return 127, "", str(e)
        if stdin_bytes is not None:
            try:
                p.stdin.write(stdin_bytes)
                p.stdin.close()
            except OSError:
                pass
        t0 = time.monotonic()
        while True:
            try:
                rc = p.wait(timeout=1)
                break
            except subprocess.TimeoutExpired:
                pass
            el = time.monotonic() - t0
            if timeout and el > timeout:
                p.kill()
                rc = p.wait()
                err.write(b"\n[delai depasse]")
                break
            gauge.set(lo + (hi - lo) * el / (el + est),
                      f"{label}\n\nTemps écoulé : {int(el) // 60} min {int(el) % 60:02d} s")
        gauge.set(hi)
        out.seek(0)
        err.seek(0)
        return rc, os.fsdecode(out.read()), os.fsdecode(err.read())


def conf_load():
    try:
        return json.loads(CONF_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def conf_set(**values):
    c = conf_load()
    c.update(values)
    tmp = CONF_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(c, indent=1, ensure_ascii=False), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONF_FILE)


def human(n):
    n = float(n or 0)
    for unit in ("o", "Ko", "Mo", "Go", "To"):
        if n < 1000 or unit == "To":
            s = f"{n:.0f} {unit}" if unit == "o" else f"{n:.1f} {unit}"
            return s.replace(".", ",")
        n /= 1000
    return ""


def fmt_dt(ts):
    if not ts:
        return "jamais"
    return time.strftime("%d/%m/%Y %H:%M", time.localtime(ts))


def safe_name(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s or "").strip("_")[:40] or "cle"
