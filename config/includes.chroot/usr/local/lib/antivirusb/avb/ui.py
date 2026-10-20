"""Interface texte (whiptail) pensée pour des utilisateurs non techniques.

Les textes évitent les caractères absents des polices de la console Linux
(tirets longs, points de suspension typographiques, symboles).
"""
import os
import shutil
import subprocess
import tempfile

BACKTITLE = "ANTIVIRUSB - Station blanche de contrôle des clés USB"

THEMES = {
    "vert": "root=black,green window=black,green border=black,green title=black,green "
            "textbox=black,green button=white,black actbutton=white,black "
            "listbox=black,green actlistbox=white,black actsellistbox=white,black",
    "rouge": "root=white,red window=white,red border=white,red title=white,red "
             "textbox=white,red button=black,white actbutton=black,white "
             "listbox=white,red actlistbox=black,white actsellistbox=black,white",
    "orange": "root=black,yellow window=black,yellow border=black,yellow title=black,yellow "
              "textbox=black,yellow button=white,black actbutton=white,black "
              "listbox=black,yellow actlistbox=white,black actsellistbox=white,black",
}


def _term():
    s = shutil.get_terminal_size((80, 25))
    return s.lines, s.columns


def _safe(text):
    text = str(text)
    return " " + text if text.startswith("-") else text


def _box(text, extra=7, min_w=54):
    """Calcule hauteur/largeur d'une boîte pour un texte donné."""
    rows, cols = _term()
    lines = str(text).splitlines() or [""]
    w = min(cols - 4, max(min_w, min(78, max(len(l) for l in lines) + 6)))
    inner = max(10, w - 6)
    n = sum(max(1, -(-len(l) // inner)) for l in lines)
    return min(rows - 2, n + extra), w, n + extra > rows - 2


class UI:
    def _run(self, args, theme=None):
        env = dict(os.environ)
        if theme in THEMES:
            env["NEWT_COLORS"] = THEMES[theme]
        try:
            p = subprocess.run(["whiptail", "--backtitle", BACKTITLE] + [str(a) for a in args],
                               stderr=subprocess.PIPE, env=env)
        except OSError:
            return 255, ""
        return p.returncode, p.stderr.decode("utf-8", "replace").strip()

    def msg(self, title, text, theme=None, ok="OK"):
        h, w, scroll = _box(text)
        args = ["--title", title, "--ok-button", ok]
        if scroll:
            args.append("--scrolltext")
        self._run(args + ["--msgbox", _safe(text), h, w], theme)

    def yesno(self, title, text, yes="Oui", no="Non", default_no=False, theme=None):
        h, w, scroll = _box(text)
        args = ["--title", title, "--yes-button", yes, "--no-button", no]
        if default_no:
            args.append("--defaultno")
        if scroll:
            args.append("--scrolltext")
        rc, _ = self._run(args + ["--yesno", _safe(text), h, w], theme)
        return rc == 0

    def menu(self, title, text, items, cancel="Retour", ok="Valider", theme=None):
        """items : liste de (clé, libellé). Renvoie la clé choisie, ou None si annulé."""
        rows, cols = _term()
        h0, w, _ = _box(text, extra=0)
        w = min(cols - 4, max(w, min(78, max((len(l) for _, l in items), default=10) + 12)))
        list_h = max(1, min(len(items), rows - h0 - 10))
        h = min(rows - 2, h0 + list_h + 8)
        args = ["--title", title, "--notags", "--ok-button", ok]
        args += ["--cancel-button", cancel] if cancel else ["--nocancel"]
        args += ["--menu", _safe(text), h, w, list_h]
        for tag, label in items:
            args += [tag, label]
        rc, out = self._run(args, theme)
        return out if rc == 0 else None

    def input(self, title, text, password=False):
        h, w, _ = _box(text, extra=9)
        args = ["--title", title, "--ok-button", "Valider", "--cancel-button", "Annuler",
                "--passwordbox" if password else "--inputbox", _safe(text), h, w]
        rc, out = self._run(args)
        return out if rc == 0 else None

    def info(self, title, text):
        h, w, _ = _box(text, extra=4)
        self._run(["--title", title, "--infobox", _safe(text), h, w])

    def textbox(self, title, path):
        rows, cols = _term()
        self._run(["--title", title, "--scrolltext", "--ok-button", "Fermer",
                   "--textbox", str(path), rows - 2, cols - 2])

    def text(self, title, content):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", errors="replace",
                                         suffix=".txt", delete=False) as f:
            f.write(content)
        try:
            self.textbox(title, f.name)
        finally:
            os.unlink(f.name)


class Gauge:
    """Jauge de progression whiptail ; s'utilise avec « with »."""

    def __init__(self, title, text):
        rows, cols = _term()
        self.pct = 0
        self.p = subprocess.Popen(
            ["whiptail", "--backtitle", BACKTITLE, "--title", title, "--gauge", _safe(text),
             "11", str(min(cols - 4, 72)), "0"],
            stdin=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")

    def set(self, pct, text=None):
        self.pct = max(self.pct, min(100, int(pct)))
        try:
            if text is None:
                self.p.stdin.write(f"{self.pct}\n")
            else:
                self.p.stdin.write(f"XXX\n{self.pct}\n{text}\nXXX\n")
            self.p.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            pass

    def close(self):
        try:
            self.p.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        self.p.wait()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
