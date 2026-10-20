"""Heuristiques propres aux clés USB (vers à raccourcis, fichiers déguisés)
et réparation des dossiers masqués par un ver."""
import fcntl
import os
import re
import struct
import unicodedata

from .model import Finding

FAT_IOCTL_GET_ATTRIBUTES = 0x80047210
FAT_IOCTL_SET_ATTRIBUTES = 0x40047211
ATTR_HIDDEN, ATTR_SYSTEM = 0x02, 0x04
NTFS_XATTR = "system.ntfs_attrib_be"

EXEC_EXT = {"exe", "scr", "pif", "com", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh",
            "hta", "ps1", "msi", "cpl", "jar", "lnk", "dll"}
DOC_EXT = {"pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm", "odt", "ods",
           "odp", "rtf", "txt", "csv", "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "mp3",
           "mp4", "avi", "mkv", "mov", "wav", "zip", "rar", "7z", "htm", "html"}
OFFICE_EXT = {"doc", "docm", "docx", "dot", "dotm", "xls", "xlsm", "xlsx", "xlsb", "xlt", "xltm",
              "xla", "xlam", "ppt", "pptm", "pptx", "pps", "ppsm", "pot", "potm", "ppam"}
LEGIT_DIRS = {"system volume information", "$recycle.bin", ".trashes", ".spotlight-v100",
              ".fseventsd", "lost+found"}
LEGIT_HIDDEN_FILES = {"desktop.ini", "thumbs.db", ".ds_store"}

LNK_SUSPECT = re.compile(
    r"cmd(\.exe)?\s+/[ckr]|cmd\.exe|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|"
    r"certutil|bitsadmin|%comspec%|\.(vbs|vbe|js|jse|wsf|wsh|hta|bat|cmd|scr|pif|ps1)\b", re.I)
AUTORUN_EXEC = re.compile(
    r"^\s*(open|shellexecute|shell\\[^\r\n=]*\\command|action|useautoplay)\s*=", re.I | re.M)
_INVISIBLE = set("ㅤᅟᅠﾠ⠀")


def _ext(name):
    i = name.rfind(".")
    return name[i + 1:].strip().lower() if i > 0 else ""


def _blank(name):
    """Nom « invisible » (espaces, caractères de remplissage) : technique classique des vers USB."""
    return all(c in _INVISIBLE or unicodedata.category(c) in ("Zs", "Cf", "Cc") for c in name)


def get_attrs(path, fstype):
    """Attributs DOS/Windows (caché, système) ; None si le format ne permet pas de les lire."""
    try:
        if fstype == "vfat":
            fd = os.open(path, os.O_RDONLY)
            try:
                buf = bytearray(4)
                fcntl.ioctl(fd, FAT_IOCTL_GET_ATTRIBUTES, buf, True)
                return struct.unpack("=I", buf)[0]
            finally:
                os.close(fd)
        if fstype == "ntfs":
            return int.from_bytes(os.getxattr(path, NTFS_XATTR), "big")
    except OSError:
        pass
    return None


def set_attrs(path, fstype, value):
    if fstype == "vfat":
        fd = os.open(path, os.O_RDONLY)
        try:
            fcntl.ioctl(fd, FAT_IOCTL_SET_ATTRIBUTES, struct.pack("=I", value))
        finally:
            os.close(fd)
    elif fstype == "ntfs":
        os.setxattr(path, NTFS_XATTR, value.to_bytes(4, "big"))
    else:
        raise OSError(f"attributs non modifiables sur une clé {fstype}")


def _is_pe(path):
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"MZ"
    except OSError:
        return False


def _lnk_strings(path):
    try:
        with open(path, "rb") as f:
            data = f.read(262144)
    except OSError:
        return None
    if data[:4] != b"\x4c\x00\x00\x00":
        return None
    asc = re.findall(rb"[\x20-\x7e]{4,}", data)
    uni = re.findall(rb"(?:[\x20-\x7e]\x00){4,}", data)
    return " ".join([a.decode("ascii") for a in asc] + [u.decode("utf-16-le") for u in uni])


def _check_autorun(path):
    try:
        with open(path, "rb") as f:
            txt = f.read(65536).decode("latin-1").replace("\x00", "")
    except OSError:
        txt = ""
    if AUTORUN_EXEC.search(txt):
        return Finding(path, "Ver USB", "autorun.inf qui lance un programme", "menace")
    return Finding(path, "Heuristique", "fichier autorun.inf (inutile sur une clé USB)", "suspect")


def analyze(root, fstype, progress=None):
    """Parcourt la clé : renvoie (détections, documents Office, nombre de fichiers, erreurs)."""
    findings, office, errors = [], [], []
    nfiles = 0
    worm_sign = False
    root_lnk, hidden_dirs, hidden_files = set(), [], []

    # 1. Racine de la clé : là où agissent les vers USB
    try:
        entries = list(os.scandir(root))
    except OSError as e:
        return [], [], 0, [f"Lecture impossible : {e}"]
    for e in entries:
        low = e.name.lower()
        try:
            is_dir, is_file = e.is_dir(follow_symlinks=False), e.is_file(follow_symlinks=False)
        except OSError:
            continue
        attrs = get_attrs(e.path, fstype)
        hidden = attrs is not None and bool(attrs & (ATTR_HIDDEN | ATTR_SYSTEM))
        if is_dir:
            if low not in LEGIT_DIRS and (hidden or _blank(e.name)):
                hidden_dirs.append(e.path)
        elif is_file:
            ext = _ext(e.name)
            if low == "autorun.inf":
                f = _check_autorun(e.path)
                findings.append(f)
                worm_sign |= f.level == "menace"
            elif ext == "lnk":
                root_lnk.add(os.path.splitext(low)[0].strip())
            elif hidden and ext in EXEC_EXT:
                findings.append(Finding(e.path, "Ver USB", "programme caché à la racine de la clé", "menace"))
                worm_sign = True
            elif hidden and low not in LEGIT_HIDDEN_FILES and not low.startswith("._"):
                hidden_files.append(e.path)

    # 2. Tous les fichiers
    for dirpath, _dirs, filenames in os.walk(root, onerror=lambda err: errors.append(
            f"Lecture impossible : {err.filename}")):
        at_root = dirpath == root
        for name in filenames:
            nfiles += 1
            if progress and nfiles % 500 == 0:
                progress(nfiles)
            path = os.path.join(dirpath, name)
            ext = _ext(name)
            if "‮" in name:
                findings.append(Finding(path, "Heuristique",
                                        "nom de fichier piégé (caractère d'inversion du texte)", "menace"))
            parts = [p.strip() for p in name.lower().split(".")]
            if len(parts) >= 3 and parts[-1] in EXEC_EXT and parts[-2] in DOC_EXT:
                findings.append(Finding(path, "Heuristique",
                                        f"double extension (.{parts[-2]}.{parts[-1]}) : programme déguisé",
                                        "menace"))
            elif ext in EXEC_EXT and re.search(r"\s{3,}\.[^.]+$", name):
                findings.append(Finding(path, "Heuristique", "extension cachée par des espaces", "menace"))
            if ext == "lnk":
                s = _lnk_strings(path)
                if s is not None and LNK_SUSPECT.search(s):
                    findings.append(Finding(path, "Ver USB" if at_root else "Heuristique",
                                            "raccourci qui lance un programme ou un script",
                                            "menace" if at_root else "suspect"))
                    worm_sign |= at_root
            if (ext in DOC_EXT or ext == "lnk") and _is_pe(path):
                findings.append(Finding(path, "Heuristique", "programme Windows déguisé en document", "menace"))
            if ext in OFFICE_EXT:
                office.append(path)

    # 3. Dossiers et fichiers masqués par un ver : à réafficher
    lnk_match = any(os.path.basename(d).lower().strip() in root_lnk for d in hidden_dirs)
    for d in hidden_dirs:
        blank = _blank(os.path.basename(d))
        if blank or worm_sign or lnk_match:
            label = ("dossier sans nom visible (technique de ver USB)" if blank
                     else "dossier masqué par un ver USB")
            findings.append(Finding(d, "Ver USB", label + " : à réafficher", "suspect",
                                    kind="dossier", repair=True))
            worm_sign = True
    if worm_sign:
        for f in hidden_files:
            findings.append(Finding(f, "Ver USB", "fichier masqué par un ver USB : à réafficher",
                                    "suspect", repair=True))
    if progress:
        progress(nfiles)
    return findings, office, nfiles, errors


def repair(path, fstype):
    """Réaffiche un élément masqué ; renomme un dossier au nom invisible. Renvoie un compte rendu."""
    done = []
    attrs = get_attrs(path, fstype)
    if attrs is not None and attrs & (ATTR_HIDDEN | ATTR_SYSTEM):
        set_attrs(path, fstype, attrs & ~(ATTR_HIDDEN | ATTR_SYSTEM))
        done.append("réaffiché")
    elif attrs is None and fstype not in ("vfat", "ntfs"):
        done.append(f"attribut caché non modifiable sur une clé {fstype}")
    if _blank(os.path.basename(path)):
        parent, base = os.path.dirname(path), "Fichiers récupérés"
        new, k = os.path.join(parent, base), 2
        while os.path.exists(new):
            new, k = os.path.join(parent, f"{base} {k}"), k + 1
        os.rename(path, new)
        done.append(f"renommé en « {os.path.basename(new)} »")
    return ", ".join(done) or "rien à modifier"
