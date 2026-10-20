"""Menu principal de la station blanche antivirusb (lancé automatiquement sur tty1)."""
import csv
import hashlib
import os
import secrets
import shutil
import signal
import subprocess
import sys
import time

from . import VERSION, core, devices, quarantine, scanners, storage, update, worm
from .model import ScanResult
from .ui import UI, Gauge

ui = UI()

ACTIONS = {"quarantaine": "Mise en quarantaine", "supprimer": "Suppression définitive",
           "reparer": "Réparation (réaffichage)", "ignorer": "Ignoré"}


# --------------------------------------------------------------------------- démarrage
def main():
    if os.geteuid() != 0:
        print("antivirusb doit être lancé en root.")
        sys.exit(1)
    for s in (signal.SIGINT, signal.SIGQUIT, signal.SIGTSTP):
        signal.signal(s, signal.SIG_IGN)
    os.environ.setdefault("TERM", "linux")
    core.log(f"démarrage antivirusb {VERSION}")
    update.network_off()
    storage.ensure_data(ui)
    ensure_admin_password()
    update.start_clamd()
    while True:
        try:
            main_menu()
        except Exception as exc:  # l'utilisateur ne doit jamais se retrouver devant un terminal
            core.log_exception(exc)
            ui.msg("Erreur", f"Une erreur inattendue s'est produite :\n\n{exc}\n\n"
                             "Le menu principal va être réaffiché.", theme="rouge")


def main_menu():
    text = "\n".join(update.status_lines()) + "\n\nQue voulez-vous faire ?"
    c = ui.menu("Menu principal", text,
                [("scan", "1. Analyser une clé USB"),
                 ("maj", "2. Mettre à jour les antivirus (smartphone)"),
                 ("stop", "3. Éteindre la station"),
                 ("admin", "4. Administration")], cancel=None)
    if c == "scan":
        menu_scan()
    elif c == "maj":
        update.do_update(ui)
    elif c == "stop":
        if ui.yesno("Éteindre", "Éteindre la station maintenant ?"):
            os.sync()
            subprocess.run(["systemctl", "poweroff"])
            time.sleep(120)
    elif c == "admin":
        menu_admin()


# --------------------------------------------------------------------------- mot de passe
def _hash(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()


def set_admin_password(mandatory):
    while True:
        p1 = ui.input("Mot de passe administrateur", "Nouveau mot de passe (6 caractères minimum) :",
                      password=True)
        if p1 is None:
            if mandatory:
                continue
            return False
        if len(p1) < 6:
            ui.msg("Mot de passe", "Mot de passe trop court (6 caractères minimum).", theme="orange")
            continue
        if ui.input("Mot de passe administrateur", "Retapez le mot de passe :", password=True) != p1:
            ui.msg("Mot de passe", "Les deux saisies sont différentes.", theme="orange")
            continue
        salt = secrets.token_hex(16)
        core.conf_set(admin_salt=salt, admin_hash=_hash(p1, salt))
        ui.msg("Mot de passe", "Mot de passe administrateur enregistré.", theme="vert")
        return True


def ensure_admin_password():
    if core.conf_load().get("admin_hash"):
        return
    ui.msg("Configuration initiale",
           "Choisissez maintenant le mot de passe ADMINISTRATEUR.\n\n"
           "Il protège la quarantaine, les rapports et la maintenance.\n"
           "Ne le communiquez pas aux utilisateurs de la station.")
    set_admin_password(mandatory=True)


def check_admin():
    c = core.conf_load()
    for _ in range(3):
        pw = ui.input("Administration", "Mot de passe administrateur :", password=True)
        if pw is None:
            return False
        if secrets.compare_digest(_hash(pw, c.get("admin_salt", "")), c.get("admin_hash", "")):
            return True
        ui.msg("Administration", "Mot de passe incorrect.", theme="orange")
    return False


# --------------------------------------------------------------------------- analyse
def wait_for_key(title, prompt):
    if not ui.yesno(title, prompt, yes="Continuer", no="Annuler"):
        return None
    ui.info(title, "Recherche de la clé USB...")
    disks = []
    for _ in range(15):
        core.run(["udevadm", "settle", "--timeout=3"], timeout=10)
        disks = devices.usb_disks()
        if disks:
            break
        time.sleep(1)
    blocked = devices.blocked_usb()
    if blocked:
        ui.msg("PÉRIPHÉRIQUE BLOQUÉ",
               "Par sécurité, la station a BLOQUÉ :\n\n" + "\n".join("- " + b for b in blocked) +
               "\n\nUn périphérique qui se présente comme un clavier ou comme un appareil inconnu "
               "est probablement PIÉGÉ. NE L'UTILISEZ PAS et remettez-le à l'administrateur.\n\n"
               "(Si vous avez débranché puis rebranché le clavier ou la souris de la station, "
               "redémarrez simplement la station.)", theme="rouge")
    if not disks:
        if not blocked:
            ui.msg(title, "Aucune clé USB détectée.\n\nVérifiez qu'elle est bien branchée, puis recommencez.",
                   theme="orange")
        return None
    if len(disks) == 1:
        return disks[0]
    c = ui.menu(title, "Plusieurs clés sont branchées. Laquelle choisir ?", [(d.path, d.title()) for d in disks])
    return next((d for d in disks if d.path == c), None)


def menu_scan():
    if not update.defs_present():
        ui.msg("Analyse impossible", "Les définitions antivirus sont absentes.\n\n"
                                     "Faites d'abord une mise à jour (menu principal, choix 2).", theme="orange")
        return
    age = update.defs_age_days() or 0
    if age >= core.DEFS_OLD_DAYS and not ui.yesno(
            "Antivirus pas à jour",
            f"Les définitions antivirus ont {int(age)} jours : les menaces récentes ne seront pas détectées.\n\n"
            "Il est conseillé de faire d'abord une mise à jour. Analyser quand même ?",
            default_no=True, theme="orange"):
        return
    update.network_off()
    disk = wait_for_key("Analyser une clé USB",
                        "Branchez la clé USB à analyser sur la station,\n"
                        "attendez 5 secondes, puis choisissez Continuer.")
    if disk:
        scan_disk(disk)


def do_scan(mounts, title):
    with Gauge(title, "Préparation de l'analyse...") as g:
        return scanners.run_scan(g, mounts)


def section(title, res):
    out = ["", title, "-" * len(title), f"Fichiers analysés : {res.nfiles}",
           f"Moteurs : {', '.join(res.engines)}", f"Éléments détectés : {len(res.items)}"]
    for it in res.items:
        out += it.text().splitlines()
    if not res.complete:
        out.append("ATTENTION : l'analyse antivirus n'a pas pu être complète.")
    if res.errors:
        out.append("Avertissements :")
        out += ["  " + e for e in res.errors[:50]]
    return out


def items_text(items):
    return "\n\n".join(it.text() for it in items)


def choose_each(items):
    dec = []
    for k, it in enumerate(items, 1):
        text = f"Élément {k} sur {len(items)} :\n\n{it.text()}"
        if it.repair_only:
            opts = [("reparer", "Réparer : réafficher (recommandé)"), ("ignorer", "Ignorer")]
        else:
            opts = [("quarantaine", "Mettre en quarantaine (recommandé)"),
                    ("supprimer", "Supprimer définitivement"),
                    ("ignorer", "Ignorer (laisser sur la clé)")]
        while True:
            c = ui.menu("Choix de l'action", text, opts, cancel="Annuler")
            if c is None:
                return None
            if c != "supprimer" or ui.yesno(
                    "Suppression définitive",
                    f"Le fichier suivant sera supprimé SANS copie de sauvegarde :\n\n{it.rel}\n\nConfirmer ?",
                    default_no=True):
                break
        dec.append((it, c))
    return dec


def ask_decisions(items):
    nm = sum(1 for i in items if i.level == "menace")
    text = (f"{nm} menace(s) et {len(items) - nm} élément(s) suspect(s) ou à réparer ont été trouvés.\n\n"
            "Que voulez-vous faire ?")
    while True:
        c = ui.menu("Résultat de l'analyse", text,
                    [("detail", "Voir la liste détaillée"),
                     ("auto", "Traiter automatiquement (recommandé)"),
                     ("choix", "Choisir pour chaque élément"),
                     ("rien", "Ne rien faire (clé à NE PAS utiliser)")],
                    cancel=None, theme="rouge" if nm else "orange")
        if c == "detail":
            ui.text("Éléments détectés", items_text(items))
            continue
        if c == "rien":
            return [(i, "ignorer") for i in items]
        dec = [(i, i.recommended) for i in items] if c == "auto" else choose_each(items)
        if dec is None:
            continue
        counts = {a: sum(1 for _, x in dec if x == a) for a in ACTIONS}
        lines = [f"- {ACTIONS[a]} : {n} élément(s)" for a, n in counts.items() if n]
        if ui.yesno("Confirmation",
                    "Actions à appliquer sur la clé :\n\n" + "\n".join(lines) +
                    "\n\nLes fichiers mis en quarantaine sont retirés de la clé et conservés "
                    "sur la station.\n\nConfirmer ?", yes="Appliquer", no="Revenir"):
            return dec


def _remount_all(mounts, rw):
    ok_all, err_txt = True, ""
    for p, mnt in mounts:
        devices.umount(mnt)
        ok, err = devices.mount(p, mnt, rw=rw)
        if not ok:
            ok_all, err_txt = False, f"{p.path} : {err}"
    return ok_all, err_txt


def apply_decisions(disk, mounts, todo):
    """Renvoie (lignes de compte rendu, clé correctement remontée en lecture seule)."""
    lines = []
    ok, err = _remount_all(mounts, rw=True)
    if not ok:
        lines.append(f"Écriture impossible sur la clé : {err}")
        ui.msg("Écriture impossible",
               "La clé ne peut pas être modifiée (clé protégée en écriture, ou disque verrouillé "
               "par Windows).\n\nAucune action n'a été appliquée.\n"
               "NE PAS UTILISER cette clé : remettez-la à l'administrateur.", theme="rouge")
        return lines, _remount_all(mounts, rw=False)[0]
    todo = sorted(todo, key=lambda d: d[1] == "reparer")  # réparations (renommages) en dernier
    with Gauge("Traitement de la clé", "Application des actions...") as g:
        for k, (it, action) in enumerate(todo):
            g.set(100 * k / len(todo), f"{ACTIONS[action]} :\n{it.rel}")
            try:
                if not os.path.lexists(it.path):
                    raise OSError("élément introuvable")
                if action == "quarantaine":
                    msg = "n° " + quarantine.add(it.path, it.rel, disk,
                                                 [f"{f.engine} : {f.name}" for f in it.findings])
                elif action == "supprimer":
                    os.remove(it.path)
                    msg = "supprimé"
                else:
                    msg = worm.repair(it.path, it.fstype)
                lines.append(f"{ACTIONS[action]} : {it.rel} -> OK ({msg})")
            except Exception as exc:
                core.log_exception(exc)
                lines.append(f"{ACTIONS[action]} : {it.rel} -> ÉCHEC ({exc})")
        g.set(100, "Enregistrement sur la clé...")
        os.sync()
    return lines, _remount_all(mounts, rw=False)[0]


def compute_verdict(res, errors):
    nm = sum(1 for i in res.items if i.level == "menace")
    ns = len(res.items) - nm
    if nm:
        return ("rouge", "CLÉ DANGEREUSE",
                f"{nm} menace(s) présente(s) sur la clé.\n\n"
                "NE PAS UTILISER CETTE CLÉ sur les ordinateurs du parc.\nRemettez-la à l'administrateur.")
    if ns or not res.complete or errors:
        why = []
        if ns:
            why.append(f"{ns} élément(s) suspect(s) laissé(s) sur la clé")
        if not res.complete or errors:
            why.append("l'analyse n'a pas pu être complète")
        return ("orange", "CLÉ À VÉRIFIER",
                "\n".join("- " + w for w in why) +
                "\n\nN'utilisez pas cette clé sans l'accord de l'administrateur.")
    text = f"{res.nfiles} fichier(s) analysé(s), aucune menace connue.\n\n" \
           "La clé peut être utilisée sur les ordinateurs du parc."
    if (update.defs_age_days() or 0) >= core.DEFS_OLD_DAYS:
        text += "\n\n(Attention : définitions antivirus anciennes.)"
    return ("vert", "AUCUNE MENACE DÉTECTÉE", text)


def save_report(disk, lines, verdict):
    core.LOGS.mkdir(parents=True, exist_ok=True)
    name = f"{time.strftime('%Y%m%d-%H%M%S')}_{core.safe_name(disk.serial or disk.model)}.txt"
    try:
        (core.LOGS / name).write_text("\n".join(lines) + "\n", encoding="utf-8", errors="replace")
        journal = core.LOGS / "journal.csv"
        new = not journal.exists()
        with open(journal, "a", newline="", encoding="utf-8", errors="replace") as f:
            w = csv.writer(f, delimiter=";")
            if new:
                w.writerow(["date", "cle", "numero_serie", "verdict", "rapport"])
            w.writerow([core.fmt_dt(time.time()), disk.title(), disk.serial, verdict[1], name])
    except OSError as exc:
        core.log_exception(exc)


def scan_disk(disk):
    parts = [p for p in disk.parts if p.fstype in devices.SUPPORTED_FS]
    errors = [f"Partition {p.path} ({p.fstype or 'format inconnu'}) non analysable"
              for p in disk.parts if p.fstype not in devices.SUPPORTED_FS]
    rep = ["ANTIVIRUSB - RAPPORT D'ANALYSE", "=" * 30,
           f"Date          : {core.fmt_dt(time.time())}",
           f"Clé           : {disk.title()}",
           f"N° de série   : {disk.serial or 'inconnu'}"] + ["  " + l for l in update.status_lines()]
    verdict = ("rouge", "CLÉ ILLISIBLE", "Analyse interrompue.")
    mounts = []
    try:
        for i, p in enumerate(parts):
            mnt = str(core.MNT_ROOT / f"p{i}")
            ok, err = devices.mount(p, mnt)
            if ok:
                mounts.append((p, mnt))
            else:
                errors.append(f"Partition {p.path} ({p.fstype}) illisible : {err}")
        if not mounts:
            verdict = ("rouge", "CLÉ ILLISIBLE",
                       "Le contenu de cette clé ne peut pas être lu, elle n'a donc pas pu être contrôlée.\n\n"
                       "NE PAS L'UTILISER sur les ordinateurs du parc.")
            rep += ["", "Erreurs :"] + ["  " + e for e in errors]
        else:
            verdict = scan_and_treat(disk, mounts, errors, rep)
    finally:
        for _, mnt in mounts:
            devices.umount(mnt)
        rep += ["", f"VERDICT : {verdict[1]}"]
        save_report(disk, rep, verdict)
    ui.msg(verdict[1], verdict[2], theme=verdict[0])
    ui.msg("Analyse terminée", "Vous pouvez retirer la clé USB.")


def scan_and_treat(disk, mounts, errors, rep):
    """Analyse, propose et applique les actions, refait une analyse de contrôle. Renvoie le verdict."""
    res = final = do_scan(mounts, "Analyse en cours")
    rep += section("ANALYSE", res)
    if res.items:
        dec = ask_decisions(res.items)
        rep += ["", "ACTIONS", "-------"]
        rep += [f"  Ignoré : {it.rel}" for it, a in dec if a == "ignorer"]
        todo = [(it, a) for it, a in dec if a != "ignorer"]
        if todo:
            lines, remounted = apply_decisions(disk, mounts, todo)
            rep += ["  " + l for l in lines]
            if remounted:
                final = do_scan(mounts, "Analyse de contrôle")
                rep += section("ANALYSE DE CONTRÔLE (après actions)", final)
            else:
                final = ScanResult(res.items, res.nfiles, ["Analyse de contrôle impossible"], False, res.engines)
    if errors:
        rep += ["", "Erreurs :"] + ["  " + e for e in errors]
    return compute_verdict(final, errors)


# --------------------------------------------------------------------------- administration
def menu_admin():
    if not check_admin():
        return
    while True:
        c = ui.menu("Administration", "Choisissez une action :",
                    [("rapports", "Consulter les rapports d'analyse"),
                     ("quar", "Gérer la quarantaine"),
                     ("etat", "État de la station"),
                     ("mdp", "Changer le mot de passe administrateur"),
                     ("shell", "Ouvrir un terminal (maintenance)"),
                     ("reboot", "Redémarrer la station")])
        if c is None:
            return
        try:
            {"rapports": admin_reports, "quar": admin_quarantine, "etat": admin_status,
             "mdp": lambda: set_admin_password(False), "shell": admin_shell,
             "reboot": admin_reboot}[c]()
        except Exception as exc:
            core.log_exception(exc)
            ui.msg("Erreur", str(exc), theme="rouge")


def admin_reports():
    while True:
        files = sorted(core.LOGS.glob("*.txt"), reverse=True)[:40]
        items = [("journal.csv", "Journal de toutes les analyses")] if (core.LOGS / "journal.csv").exists() else []
        items += [(f.name, f.stem.replace("_", "  ", 1)) for f in files]
        if not items:
            ui.msg("Rapports", "Aucun rapport pour le moment.")
            return
        c = ui.menu("Rapports", "Rapports les plus récents :", items)
        if c is None:
            return
        ui.textbox(c, core.LOGS / c)


def admin_quarantine():
    while True:
        items = quarantine.list_items()
        if not items:
            ui.msg("Quarantaine", "La quarantaine est vide.")
            return
        opts = [(m["id"], f"{core.fmt_dt(m.get('date'))}  {str(m.get('nom', '?'))[:45]}") for m in items[:200]]
        opts.append(("__purge", "VIDER TOUTE LA QUARANTAINE"))
        c = ui.menu("Quarantaine", f"{len(items)} fichier(s) en quarantaine ({core.human(quarantine.size())}).",
                    opts)
        if c is None:
            return
        if c == "__purge":
            if ui.yesno("Quarantaine", "Supprimer DÉFINITIVEMENT tous les fichiers en quarantaine ?",
                        default_no=True):
                quarantine.purge()
            continue
        quar_entry(next(m for m in items if m["id"] == c))


def quar_entry(meta):
    info = (f"Fichier : {meta.get('nom')}\nEmplacement d'origine : {meta.get('chemin')}\n"
            f"Clé : {meta.get('cle')} (n° {meta.get('serie')})\nDate : {core.fmt_dt(meta.get('date'))}\n"
            f"SHA-256 : {meta.get('sha256')}\n\nDétections :\n" +
            "\n".join("- " + d for d in meta.get("detections", [])))
    c = ui.menu("Élément en quarantaine", info,
                [("rest", "Restaurer sur une clé USB (faux positif)"), ("del", "Supprimer définitivement")])
    if c == "del" and ui.yesno("Quarantaine", "Supprimer définitivement ce fichier ?", default_no=True):
        quarantine.remove(meta["id"])
    elif c == "rest":
        restore_flow(meta)


def restore_flow(meta):
    if not ui.yesno("Restauration",
                    "ATTENTION : ce fichier a été détecté comme dangereux ou suspect.\n"
                    "Ne le restaurez que si vous êtes CERTAIN qu'il s'agit d'une erreur (faux positif).\n\n"
                    "Continuer ?", default_no=True, theme="orange"):
        return
    disk = wait_for_key("Restauration", "Branchez la clé USB qui doit recevoir le fichier,\n"
                                        "puis choisissez Continuer.")
    if not disk:
        return
    parts = [p for p in disk.parts if p.fstype in devices.SUPPORTED_FS - devices.READONLY_FS]
    if not parts:
        ui.msg("Restauration", "Cette clé ne peut pas recevoir de fichier.", theme="orange")
        return
    part = parts[0]
    if len(parts) > 1:
        c = ui.menu("Restauration", "Sur quelle partition ?",
                    [(p.path, f"{p.label or p.path} ({p.fstype}, {core.human(p.size)})") for p in parts])
        part = next((p for p in parts if p.path == c), None)
        if not part:
            return
    mnt = str(core.MNT_ROOT / "restore")
    ok, err = devices.mount(part, mnt, rw=True)
    if not ok:
        ui.msg("Restauration", f"Impossible d'écrire sur la clé :\n{err}", theme="rouge")
        return
    try:
        target = quarantine.restore(meta, mnt)
        ui.msg("Restauration", f"Fichier restauré sur la clé :\n\n{target}", theme="vert")
    except OSError as exc:
        ui.msg("Restauration", f"Échec de la restauration :\n{exc}", theme="rouge")
    finally:
        devices.umount(mnt)


def _mem_total():
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * 1024
    except OSError:
        pass
    return 0


def admin_status():
    mem = _mem_total()
    lines = [f"antivirusb version {VERSION}", "",
             f"Mémoire vive : {core.human(mem)}" + ("  (moins de 3 Go : analyses lentes)" if mem < 3e9 else "")]
    if os.path.ismount(core.DATA):
        du = shutil.disk_usage(core.DATA)
        lines.append(f"Stockage : {'mémoire vive' if core.STATE.get('ram') else 'disque interne'}, "
                     f"{core.human(du.used)} utilisés sur {core.human(du.total)}")
    lines += update.status_lines()
    lines.append("Service ClamAV : " + ("prêt" if scanners.clamd_ping() else "arrêté (analyses plus lentes)"))
    for cmd in (["clamscan", "--version"], ["yara", "--version"]):
        lines.append(f"{cmd[0]} : {core.run(cmd, timeout=20).out.strip()}")
    lines.append(f"Quarantaine : {len(quarantine.list_items())} fichier(s)")
    lines.append("Protection USB (USBGuard) : " +
                 core.run(["systemctl", "is-active", "usbguard.service"], timeout=10).out.strip())
    blocked = devices.blocked_usb()
    if blocked:
        lines.append("Périphériques bloqués : " + ", ".join(blocked))
    ui.text("État de la station", "\n".join(lines))


def _default_signals():
    for s in (signal.SIGINT, signal.SIGQUIT, signal.SIGTSTP):
        signal.signal(s, signal.SIG_DFL)


def admin_shell():
    ui.msg("Terminal", "Un terminal administrateur va s'ouvrir.\nTapez  exit  pour revenir au menu.")
    subprocess.run(["clear"])
    subprocess.run(["bash", "-l"], env=dict(os.environ, AVB_SHELL="1"), preexec_fn=_default_signals)


def admin_reboot():
    if ui.yesno("Redémarrer", "Redémarrer la station maintenant ?"):
        os.sync()
        subprocess.run(["systemctl", "reboot"])
        time.sleep(120)
