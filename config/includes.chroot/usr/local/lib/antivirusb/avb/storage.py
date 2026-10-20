"""Espace de stockage AVDATA sur le disque INTERNE de la station : définitions antivirus,
règles YARA, quarantaine, rapports. La clé de démarrage reste en lecture seule."""
import os
import shutil
import subprocess
import time

from . import core, devices


def find_avdata():
    r = core.run(["blkid", "-c", "/dev/null", "-t", "LABEL=AVDATA", "-o", "device"], timeout=30)
    live = devices.live_disk()
    usb = {d.path for d in devices.list_disks() if d.tran == "usb"}
    for dev in r.out.split():
        parent = devices.parent_disk(dev)
        # une clé USB étiquetée AVDATA (piégée ou non) n'est jamais utilisée
        if parent not in usb and parent != live:
            return dev
    return None


def _prepare():
    os.chmod(core.DATA, 0o755)
    for d in (core.LOGS, core.YARA_DIR, core.CLAM_STORE, core.QUAR):
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o755)
    os.chmod(core.QUAR, 0o700)
    os.chmod(core.LOGS, 0o750)
    shutil.chown(core.CLAM_STORE, "clamav", "clamav")
    core.CLAM_DB.mkdir(parents=True, exist_ok=True)
    if not os.path.ismount(core.CLAM_DB):
        core.run(["mount", "--bind", core.CLAM_STORE, core.CLAM_DB], timeout=30)


def mount_data():
    if os.path.ismount(core.DATA):
        _prepare()
        return True
    dev = find_avdata()
    if not dev:
        return False
    core.DATA.mkdir(parents=True, exist_ok=True)
    core.run(["e2fsck", "-p", dev], timeout=1800)
    r = core.run(["mount", "-t", "ext4", "-o", "nodev,nosuid,noexec", dev, core.DATA], timeout=60)
    if r.rc:
        core.log(f"montage AVDATA impossible : {r.err}")
        return False
    _prepare()
    core.STATE["ram"] = False
    return True


def mount_ram():
    core.DATA.mkdir(parents=True, exist_ok=True)
    core.run(["mount", "-t", "tmpfs", "-o", "size=60%,mode=0755,nodev,nosuid,noexec", "avdata", core.DATA],
             timeout=30)
    _prepare()
    core.STATE["ram"] = True


def format_disk(disk):
    core.run(["swapoff", "-a"], timeout=60)
    for p in disk.parts:
        core.run(["umount", p.path], timeout=30)
    for cmd in (["wipefs", "-a", disk.path],
                ["parted", "-s", disk.path, "mklabel", "gpt", "mkpart", "AVDATA", "ext4", "1MiB", "100%"]):
        r = core.run(cmd, timeout=300)
        if r.rc:
            return False, f"{cmd[0]} : {(r.err or r.out).strip()[-300:]}"
    core.run(["partprobe", disk.path], timeout=60)
    core.run(["udevadm", "settle", "--timeout=15"], timeout=30)
    time.sleep(2)
    part = next((d.parts[0].path for d in devices.list_disks() if d.path == disk.path and d.parts), None)
    if not part:
        return False, "partition introuvable après sa création"
    r = core.run(["mkfs.ext4", "-F", "-q", "-L", "AVDATA", part], timeout=3600)
    if r.rc:
        return False, f"mkfs : {(r.err or r.out).strip()[-300:]}"
    core.run(["udevadm", "settle", "--timeout=15"], timeout=30)
    return True, part


def ensure_data(ui):
    if mount_data():
        return
    while True:
        disks = devices.internal_disks()
        items = [(d.path, f"{d.title()}  [{d.path}]") for d in disks]
        items.append(("ram", "Pas de disque : mode mémoire vive (tout est perdu à l'arrêt)"))
        c = ui.menu(
            "Configuration initiale",
            "PREMIÈRE CONFIGURATION DE LA STATION\n\n"
            "La station a besoin d'un espace de stockage pour conserver les définitions antivirus, "
            "la quarantaine et les rapports.\n\n"
            "Choisissez le disque INTERNE de la station à utiliser.\n"
            "ATTENTION : TOUT SON CONTENU SERA EFFACÉ.\n\n"
            "Si vous n'êtes pas l'administrateur de la station, choisissez Éteindre et prévenez-le.",
            items, cancel="Éteindre")
        if c is None:
            subprocess.run(["systemctl", "poweroff"])
            time.sleep(120)
            continue
        if c == "ram":
            mount_ram()
            ui.msg("Mode mémoire vive",
                   "La station fonctionne sans disque.\n\nLes définitions, la quarantaine et les rapports "
                   "seront PERDUS à chaque arrêt : il faudra refaire une mise à jour à chaque démarrage.",
                   theme="orange")
            return
        disk = next(d for d in disks if d.path == c)
        word = ui.input("Confirmation",
                        f"Le disque {disk.title()} [{disk.path}] va être ENTIÈREMENT EFFACÉ.\n\n"
                        "Tapez EFFACER (en majuscules) pour confirmer :")
        if word != "EFFACER":
            continue
        ui.info("Configuration initiale", "Préparation du disque en cours, patientez...")
        ok, msg = format_disk(disk)
        if ok and mount_data():
            ui.msg("Configuration initiale", "Le disque de la station est prêt.", theme="vert")
            return
        ui.msg("Erreur", f"La préparation du disque a échoué :\n\n{msg}", theme="rouge")
