"""Enchaînement des analyses : heuristiques, ClamAV, YARA, macros Office."""
import json
import os
import sys
import time

from . import core, worm
from .model import Finding, Item, ScanResult

# Règles YARA (signature-base) : préfixes jugés graves, et préfixes trop génériques ignorés
YARA_MENACE = ("MAL_", "APT_", "EXPL_", "HKTL_", "WEBSHELL_", "RANSOM", "CRIME_")
YARA_IGNORE = ("SUSP_", "PUA_", "VULN_", "INDICATOR_", "Generic_")

_skip_larger = None


def clamd_ping():
    return core.run(["clamdscan", "--ping=1"], timeout=15).rc == 0


def _clamd_starting():
    r = core.run(["systemctl", "is-active", "clamav-daemon.service"], timeout=10)
    return r.out.strip() in ("active", "activating", "reloading")


def wait_clamd(gauge, timeout=300):
    """Attend que le service ClamAV ait chargé ses définitions (long sur un ancien PC)."""
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if clamd_ping():
            return True
        if not _clamd_starting():
            return False
        gauge.set(1, "Chargement des définitions antivirus en mémoire...\n\n"
                     f"({int(time.monotonic() - t0)} s, jusqu'à 2 ou 3 minutes sur un ancien PC)")
        time.sleep(2)
    return False


def clam_scan(gauge, mnt, lo, hi, use_clamd):
    if use_clamd:
        cmd, user, est = ["clamdscan", "--fdpass", "--infected", "--no-summary", mnt], None, 90
    else:
        cmd = ["clamscan", "--recursive", "--infected", "--no-summary",
               "--max-filesize=400M", "--max-scansize=1000M", mnt]
        user, est = core.SCAN_USER, 240
    rc, out, err = core.run_progress(gauge, cmd, lo, hi, "Analyse antivirus (ClamAV)...",
                                     est=est, user=user, timeout=6 * 3600)
    findings, errors = [], []
    for line in (out + "\n" + err).splitlines():
        line = line.rstrip()
        if line.endswith(" FOUND") and ": " in line:
            path, sig = line[:-len(" FOUND")].rsplit(": ", 1)
            findings.append(Finding(path, "ClamAV", sig, "menace"))
        elif line.endswith(" ERROR") or line.startswith(("ERROR", "WARNING", "LibClamAV Error")):
            errors.append("ClamAV : " + line)
    # code 2 accepté seulement si les erreurs concernent des fichiers précis de la clé
    ok = rc in (0, 1) or (rc == 2 and errors and all(mnt in e for e in errors))
    if not ok and use_clamd and not findings:
        core.log(f"clamdscan rc={rc} : repli sur clamscan\n{out[-1000:]}\n{err[-1000:]}")
        return clam_scan(gauge, mnt, lo, hi, False)
    if not ok:
        errors.append(f"ClamAV : analyse incomplète (code {rc})")
    return findings, errors, ok, "ClamAV" + (" (service)" if use_clamd else "")


def _yara_skip_flag():
    global _skip_larger
    if _skip_larger is None:
        r = core.run(["yara", "--help"], timeout=10)
        _skip_larger = "--skip-larger" in (r.out + r.err)
    return _skip_larger


def yara_scan(gauge, mnt, lo, hi):
    if not core.YARA_RULES.exists():
        return [], ["YARA : règles absentes (faire une mise à jour)"]
    cmd = ["yara", "-C", "-r", "-N", "-w", "-p", "2"]
    if _yara_skip_flag():
        cmd.append("--skip-larger=104857600")
    cmd += [str(core.YARA_RULES), mnt]
    rc, out, err = core.run_progress(gauge, cmd, lo, hi, "Analyse par règles YARA...",
                                     est=120, user=core.SCAN_USER, timeout=3 * 3600)
    findings = []
    for line in out.splitlines():
        rule, _, path = line.partition(" ")
        if not path.startswith(mnt) or rule.startswith(YARA_IGNORE):
            continue
        level = "menace" if rule.startswith(YARA_MENACE) else "suspect"
        findings.append(Finding(path, "YARA", f"règle {rule}", level))
    errors = ["YARA : " + l for l in err.splitlines() if l.strip()][:20]
    return findings, errors


def macro_scan(gauge, files, lo, hi):
    if not files:
        return [], []
    helper = core.LIB / "avb_macro.py"
    data = b"\0".join(os.fsencode(p) for p in files)
    rc, out, err = core.run_progress(
        gauge, [sys.executable, "-I", str(helper)], lo, hi,
        f"Analyse des macros Office ({len(files)} documents)...",
        est=max(10, len(files)), user=core.SCAN_USER, stdin_bytes=data, timeout=2 * 3600)
    findings, errors = [], []
    for line in out.splitlines():
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if "path" not in r:
            errors.append("Macros : " + str(r.get("error", "erreur inconnue")))
        elif r.get("error"):
            errors.append(f"Macros : {r['path']} : {r['error']}")
        elif r.get("suspicious"):
            kw = ", ".join(r.get("keywords", [])[:5])
            findings.append(Finding(r["path"], "Macro Office",
                                    "macro suspecte (lancement automatique + écriture/exécution)"
                                    + (f" : {kw}" if kw else ""), "suspect"))
    if rc:
        errors.append(f"Macros : code {rc} {err.strip()[-200:]}")
    return findings, errors


def _owner(path, mounts):
    for part, mnt in mounts:
        if path == mnt or path.startswith(mnt.rstrip("/") + "/"):
            return part, mnt
    return None, None


def group(findings, mounts):
    items = {}
    for f in findings:
        it = items.get(f.path)
        if it is None:
            part, mnt = _owner(f.path, mounts)
            rel = "/" + os.path.relpath(f.path, mnt) if mnt else f.path
            if len(mounts) > 1 and part:
                rel = f"[{part.label or os.path.basename(part.path)}] {rel}"
            it = items[f.path] = Item(f.path, rel, f.kind, part.fstype if part else "")
        if not any(x.engine == f.engine and x.name == f.name for x in it.findings):
            it.findings.append(f)
    return sorted(items.values(), key=lambda i: (i.level != "menace", i.rel.lower()))


def run_scan(gauge, mounts):
    """mounts : liste de (Part, point de montage). Renvoie un ScanResult."""
    findings, errors, engines = [], [], set()
    nfiles, complete = 0, True
    use_clamd = wait_clamd(gauge)
    n = len(mounts)
    for i, (part, mnt) in enumerate(mounts):
        lo, span = 100 * i / n, 100 / n

        def seg(a, b):
            return lo + span * a / 100, lo + span * b / 100

        a, _ = seg(0, 10)
        gauge.set(a, "Inventaire des fichiers...")
        h, office, cnt, errs = worm.analyze(mnt, part.fstype,
                                            lambda k: gauge.set(a, f"Inventaire des fichiers : {k}"))
        findings += h
        errors += errs
        nfiles += cnt
        engines.add("Heuristiques USB")

        f, e, ok, eng = clam_scan(gauge, mnt, *seg(10, 65), use_clamd)
        findings += f
        errors += e
        complete &= ok
        engines.add(eng)

        f, e = yara_scan(gauge, mnt, *seg(65, 88))
        findings += f
        errors += e
        if core.YARA_RULES.exists():
            engines.add("YARA")

        f, e = macro_scan(gauge, office, *seg(88, 100))
        findings += f
        errors += e
        if office:
            engines.add("Macros Office")
    gauge.set(100, "Analyse terminée.")
    return ScanResult(group(findings, mounts), nfiles, errors, complete, sorted(engines))
