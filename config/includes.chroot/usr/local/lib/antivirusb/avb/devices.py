"""Détection des disques USB et montage sécurisé des clés à analyser."""
import json
import os
import pwd
import re
from dataclasses import dataclass, field

from . import core

SUPPORTED_FS = {"vfat", "exfat", "ntfs", "ext2", "ext3", "ext4", "iso9660", "udf"}
READONLY_FS = {"iso9660", "udf"}


@dataclass
class Part:
    path: str
    fstype: str
    label: str
    size: int


@dataclass
class Disk:
    path: str
    model: str
    vendor: str
    serial: str
    size: int
    tran: str
    parts: list = field(default_factory=list)

    def title(self):
        name = " ".join(x for x in (self.vendor, self.model) if x).strip() or "Clé USB"
        return f"{name} ({core.human(self.size)})"


def _s(v):
    return str(v or "").strip()


def _lsblk():
    r = core.run(["lsblk", "-J", "-b", "-o",
                  "NAME,PATH,TYPE,TRAN,SIZE,FSTYPE,LABEL,MODEL,VENDOR,SERIAL"], timeout=20)
    if r.rc:
        return []
    try:
        return json.loads(r.out).get("blockdevices", [])
    except ValueError:
        return []


def _walk_parts(node, out):
    for c in node.get("children") or []:
        if c.get("type") == "part":
            out.append(Part(c["path"], _s(c.get("fstype")), _s(c.get("label")), int(c.get("size") or 0)))
        _walk_parts(c, out)


def list_disks():
    disks = []
    for d in _lsblk():
        if d.get("type") != "disk" or _s(d.get("name")).startswith(("zram", "loop")):
            continue
        parts = []
        _walk_parts(d, parts)
        if not parts and d.get("fstype"):   # clé formatée sans table de partitions
            parts = [Part(d["path"], _s(d.get("fstype")), _s(d.get("label")), int(d.get("size") or 0))]
        disks.append(Disk(d["path"], _s(d.get("model")), _s(d.get("vendor")), _s(d.get("serial")),
                          int(d.get("size") or 0), _s(d.get("tran")), parts))
    return disks


def parent_disk(dev):
    r = core.run(["lsblk", "-n", "-d", "-o", "PKNAME", dev], timeout=10)
    pk = r.out.strip().splitlines()[0].strip() if r.out.strip() else ""
    return "/dev/" + pk if pk else dev


def live_disk():
    """Disque qui porte le système antivirusb (à ne jamais analyser ni effacer)."""
    src = core.run(["findmnt", "-n", "-o", "SOURCE", "/run/live/medium"], timeout=10).out.strip()
    return parent_disk(src) if src else None


def usb_disks():
    live = live_disk()
    return [d for d in list_disks() if d.tran == "usb" and d.path != live and d.size > 0]


def internal_disks():
    live = live_disk()
    return [d for d in list_disks() if d.tran != "usb" and d.path != live and d.size >= 2 * 10**9]


def blocked_usb():
    """Périphériques bloqués par USBGuard (ex. : clé qui se fait passer pour un clavier)."""
    r = core.run(["usbguard", "list-devices", "--blocked"], timeout=10)
    out = []
    for line in r.out.splitlines():
        name = re.search(r'name "([^"]*)"', line)
        ident = re.search(r"id ([0-9a-fA-F]{4}:[0-9a-fA-F]{4})", line)
        out.append(f"{name.group(1) if name and name.group(1) else 'périphérique inconnu'}"
                   f" ({ident.group(1) if ident else '?'})")
    return out


def mount(part, mnt, rw=False):
    """Monte une partition : lecture seule par défaut, jamais d'exécution possible."""
    mnt = str(mnt)
    os.makedirs(mnt, exist_ok=True)
    if rw and part.fstype in READONLY_FS:
        return False, "support en lecture seule"
    pw = pwd.getpwnam(core.SCAN_USER)
    base = ("rw" if rw else "ro") + ",nosuid,nodev,noexec"
    own = f"uid={pw.pw_uid},gid={pw.pw_gid},fmask=0137,dmask=0027"
    fs = part.fstype
    if fs == "vfat":
        cmd = ["mount", "-t", "vfat", "-o", f"{base},{own},utf8,shortname=mixed", part.path, mnt]
    elif fs == "exfat":
        cmd = ["mount", "-t", "exfat", "-o", f"{base},{own},iocharset=utf8", part.path, mnt]
    elif fs == "ntfs":
        cmd = ["mount", "-t", "ntfs-3g", "-o", f"{base},{own}" + (",windows_names" if rw else ""), part.path, mnt]
    elif fs in ("ext2", "ext3", "ext4"):
        # noload : ne pas rejouer le journal (aucune écriture sur la clé en lecture seule)
        cmd = ["mount", "-t", fs, "-o", base + ("" if rw else ",noload"), part.path, mnt]
    else:
        cmd = ["mount", "-t", fs, "-o", base, part.path, mnt]
    r = core.run(cmd, timeout=60)
    if r.rc:
        return False, (r.err or r.out).strip()[-300:]
    return True, ""


def umount(mnt):
    os.sync()
    if core.run(["umount", str(mnt)], timeout=60).rc:
        core.run(["umount", "-l", str(mnt)], timeout=30)
