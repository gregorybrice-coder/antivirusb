"""Mise à jour des définitions (ClamAV + règles YARA) via le partage de connexion USB
d'un smartphone. Le réseau n'est activé que pendant la mise à jour."""
import os
import shutil
import tarfile
import tempfile
import time
from pathlib import Path

from . import core, devices
from .ui import Gauge

SIGBASE_URL = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.tar.gz"

PHONE_HELP = (
    "1. Retirez toute clé USB à analyser.\n"
    "2. Branchez le smartphone sur la station avec son câble USB.\n"
    "3. Sur le smartphone, activez le partage de connexion USB :\n"
    "   - Android : Paramètres > Réseau (ou Connexions) > Partage de connexion\n"
    "     > « Partage de connexion USB »\n"
    "   - iPhone : Réglages > Partage de connexion > activer,\n"
    "     puis répondez « Se fier » si l'iPhone le demande.\n"
    "4. Choisissez Continuer.\n\n"
    "La première mise à jour télécharge environ 300 Mo de données mobiles,\n"
    "les suivantes quelques dizaines de Mo.")


def network_on():
    core.run(["nmcli", "networking", "on"], timeout=20)


def network_off():
    core.run(["nmcli", "networking", "off"], timeout=20)


def defs_present():
    def has(base):
        return any((core.CLAM_DB / f"{base}.{e}").exists() for e in ("cvd", "cld"))
    return has("main") and has("daily")


def last_update():
    ts = core.conf_load().get("clamav_update")
    if ts:
        return ts
    for n in ("daily.cld", "daily.cvd"):
        p = core.CLAM_DB / n
        if p.exists():
            return p.stat().st_mtime
    return None


def defs_age_days():
    ts = last_update()
    return None if ts is None else max(0.0, (time.time() - ts) / 86400)


def status_lines():
    lines = []
    if not defs_present():
        lines.append("ANTIVIRUS : AUCUNE DÉFINITION. Faites une mise à jour (choix 2).")
    else:
        age, d = defs_age_days() or 0, core.fmt_dt(last_update())
        if age < core.DEFS_WARN_DAYS:
            lines.append(f"Antivirus : à jour (mise à jour du {d})")
        elif age < core.DEFS_OLD_DAYS:
            lines.append(f"Antivirus : mis à jour le {d}. Pensez à le mettre à jour.")
        else:
            lines.append(f"ATTENTION : antivirus pas mis à jour depuis {int(age)} jours !")
    y = core.conf_load().get("yara_update")
    lines.append(f"Règles YARA : mise à jour du {core.fmt_dt(y)}" if y and core.YARA_RULES.exists()
                 else "Règles YARA : absentes")
    if core.STATE.get("ram"):
        lines.append("Mode mémoire vive : les mises à jour seront perdues à l'arrêt.")
    return lines


def start_clamd(restart=False):
    if defs_present():
        core.run(["systemctl", "restart" if restart else "start", "--no-block", "clamav-daemon.service"],
                 timeout=30)


def wait_internet(gauge, timeout=120):
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if core.run(["getent", "ahosts", "database.clamav.net"], timeout=10).rc == 0:
            return True
        el = int(time.monotonic() - t0)
        gauge.set(10 * el / timeout, "Connexion à Internet via le smartphone...\n\n"
                                     f"Vérifiez que le partage de connexion USB est activé. ({el} s)")
        time.sleep(3)
    return False


def sync_time(timeout=30):
    """Remet l'horloge à l'heure (indispensable pour HTTPS sur un vieux PC à pile morte)."""
    core.run(["timedatectl", "set-ntp", "true"], timeout=15)
    core.run(["systemctl", "restart", "systemd-timesyncd.service"], timeout=30)
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if core.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], timeout=10).out.strip() == "yes":
            core.run(["hwclock", "--systohc"], timeout=20)
            return True
        time.sleep(2)
    return False


def update_clamav(gauge, lo, hi):
    shutil.chown(core.CLAM_STORE, "clamav", "clamav")
    rc, out, err = core.run_progress(gauge, ["freshclam", "--stdout"], lo, hi,
                                     "Téléchargement des définitions ClamAV...", est=240, timeout=3600)
    core.log(f"freshclam rc={rc}\n{out[-3000:]}\n{err[-2000:]}")
    if rc in (0, 1) and defs_present():
        return True, "ClamAV : définitions à jour"
    tail = "\n".join((out + "\n" + err).strip().splitlines()[-4:])
    return False, f"ClamAV : ÉCHEC (code {rc})\n{tail}"


def _extract_rules(tgz, dest):
    with tarfile.open(tgz, "r:gz") as tf:
        members = [m for m in tf.getmembers()
                   if m.isfile() and "/yara/" in m.name and m.name.lower().endswith((".yar", ".yara"))]
        try:
            tf.extractall(dest, members=members, filter="data")
        except TypeError:  # Python sans filtre d'extraction sécurisé
            for m in members:
                if not m.name.startswith("/") and ".." not in m.name.split("/"):
                    tf.extract(m, dest)


def update_yara(gauge, lo, hi):
    tmp = tempfile.mkdtemp(prefix="yara-", dir=str(core.DATA))
    try:
        tgz = os.path.join(tmp, "signature-base.tar.gz")
        mid = lo + (hi - lo) * 0.3
        rc, _, _ = core.run_progress(gauge, ["curl", "-fsSL", "--retry", "3", "--max-time", "1200",
                                             "-o", tgz, SIGBASE_URL],
                                     lo, mid, "Téléchargement des règles YARA...", est=60, timeout=1300)
        if rc:
            return False, "YARA : ÉCHEC du téléchargement"
        src = os.path.join(tmp, "src")
        os.mkdir(src)
        _extract_rules(tgz, src)
        files = sorted(str(p) for p in Path(src).rglob("*")
                       if p.is_file() and p.suffix.lower() in (".yar", ".yara"))
        # Chaque fichier est vérifié seul : ceux qui exigent des variables externes
        # (spécifiques à l'outil THOR) ou des modules absents sont écartés.
        good = []
        for k, f in enumerate(files):
            if k % 5 == 0:
                gauge.set(mid + (hi - mid) * 0.8 * k / max(1, len(files)),
                          f"Vérification des règles YARA : {k}/{len(files)}")
            if core.run(["yarac", f, os.path.join(tmp, "test.yarc")], timeout=120).rc == 0:
                good.append(f)
        if not good:
            return False, "YARA : aucune règle utilisable"
        gauge.set(mid + (hi - mid) * 0.85, "Compilation des règles YARA...")
        out_file = os.path.join(tmp, "rules.yarc")
        r = core.run(["yarac"] + [f"r{i}:{f}" for i, f in enumerate(good)] + [out_file], timeout=1800)
        if r.rc:
            return False, "YARA : ÉCHEC de la compilation\n" + r.err.strip()[-300:]
        core.YARA_DIR.mkdir(parents=True, exist_ok=True)
        os.replace(out_file, core.YARA_RULES)
        os.chmod(core.YARA_RULES, 0o644)
        return True, f"YARA : {len(good)} fichiers de règles sur {len(files)}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def do_update(ui):
    if devices.usb_disks():
        ui.msg("Mise à jour", "Retirez d'abord toute clé USB à analyser.\n\n"
                              "Par sécurité, la station ne se connecte jamais à Internet "
                              "quand une clé à contrôler est branchée.", theme="orange")
        return
    if not ui.yesno("Mise à jour des antivirus", PHONE_HELP, yes="Continuer", no="Annuler"):
        return
    results, connected = [], False
    network_on()
    try:
        with Gauge("Mise à jour", "Connexion à Internet via le smartphone...") as g:
            connected = wait_internet(g)
            if connected:
                g.set(10, "Mise à l'heure de l'horloge...")
                if not sync_time():
                    results.append("Horloge : synchronisation impossible (on continue)")
                ok_c, msg = update_clamav(g, 12, 65)
                results.append(msg)
                if ok_c:
                    core.conf_set(clamav_update=time.time())
                ok_y, msg = update_yara(g, 65, 99)
                results.append(msg)
                if ok_y:
                    core.conf_set(yara_update=time.time())
                g.set(100, "Terminé.")
    finally:
        network_off()
    if not connected:
        blocked = devices.blocked_usb()
        ui.msg("Pas de connexion",
               "La station n'a pas pu accéder à Internet.\n\n"
               "- Vérifiez que le partage de connexion USB est bien ACTIVÉ sur le smartphone.\n"
               "- Vérifiez que le smartphone a du réseau (4G/5G).\n"
               "- Essayez de débrancher/rebrancher le câble, puis recommencez."
               + ("\n\nPériphérique(s) bloqué(s) par sécurité : " + ", ".join(blocked) if blocked else ""),
               theme="orange")
        return
    start_clamd(restart=True)
    nok = sum("ÉCHEC" in r or "aucune" in r for r in results)
    ui.msg("Mise à jour terminée",
           "\n".join(results) + "\n\nVous pouvez débrancher le smartphone et désactiver le partage.",
           theme="vert" if nok == 0 else ("orange" if nok < 2 else "rouge"))
