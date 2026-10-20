"""Quarantaine : les fichiers retirés des clés sont conservés sur la station dans une
archive zip protégée (mot de passe « infected »), inerte, avec une fiche descriptive."""
import hashlib
import json
import os
import re
import secrets
import shutil
import tempfile
import time

from . import core


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def add(path, rel, disk, detections):
    """Archive le fichier puis le supprime de la clé. Renvoie le numéro de quarantaine."""
    qid = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
    d = core.QUAR / qid
    d.mkdir(parents=True)
    try:
        meta = {"id": qid, "date": time.time(), "sha256": _sha256(path), "taille": os.path.getsize(path),
                "nom": os.path.basename(path), "chemin": rel, "cle": disk.title(),
                "serie": disk.serial or "inconnu", "detections": detections}
        r = core.run(["zip", "-q", "-j", "-nw", "-P", core.QUAR_PASSWORD, d / "fichier.zip", path],
                     timeout=1800)
        if r.rc:
            raise OSError("archivage impossible : " + (r.err or r.out).strip()[-200:])
        (d / "meta.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
        os.remove(path)
    except Exception:
        shutil.rmtree(d, ignore_errors=True)
        raise
    return qid


def list_items():
    out = []
    for m in core.QUAR.glob("*/meta.json"):
        try:
            out.append(json.loads(m.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass
    return sorted(out, key=lambda x: x.get("date", 0), reverse=True)


def size():
    return sum(f.stat().st_size for f in core.QUAR.rglob("*") if f.is_file())


def remove(qid):
    if re.fullmatch(r"[0-9]{8}-[0-9]{6}-[0-9a-f]{6}", qid):
        shutil.rmtree(core.QUAR / qid, ignore_errors=True)


def purge():
    for m in list_items():
        remove(m["id"])


def restore(meta, dest_root):
    """Remet le fichier sur la clé montée en dest_root (à son emplacement d'origine si possible)."""
    tmp = tempfile.mkdtemp(dir=str(core.DATA))
    try:
        r = core.run(["unzip", "-q", "-o", "-P", core.QUAR_PASSWORD,
                      core.QUAR / meta["id"] / "fichier.zip", "-d", tmp], timeout=1800)
        files = [os.path.join(tmp, f) for f in os.listdir(tmp)]
        if r.rc or len(files) != 1:
            raise OSError("décompression impossible")
        rel = re.sub(r"^\[[^\]]*\] ", "", meta.get("chemin") or meta.get("nom", "fichier")).lstrip("/")
        root = os.path.realpath(dest_root)
        target = os.path.join(root, rel)
        if not os.path.realpath(target).startswith(root + os.sep):
            target = os.path.join(root, os.path.basename(rel))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        base, ext = os.path.splitext(target)
        k = 1
        while os.path.exists(target):
            target, k = f"{base} (restauré {k}){ext}", k + 1
        shutil.copyfile(files[0], target)   # copyfile : pas de copie de droits (FAT/exFAT)
        os.sync()
        remove(meta["id"])
        return target[len(root):]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
