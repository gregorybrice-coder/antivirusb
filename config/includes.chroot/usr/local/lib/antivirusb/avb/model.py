"""Structures de données des résultats d'analyse."""
from dataclasses import dataclass, field


@dataclass
class Finding:
    path: str
    engine: str          # ClamAV, YARA, Macro Office, Ver USB, Heuristique
    name: str            # libellé de la détection
    level: str           # "menace" ou "suspect"
    kind: str = "fichier"
    repair: bool = False  # True : élément à réafficher (masqué par un ver), pas à supprimer


@dataclass(eq=False)
class Item:
    """Un fichier ou dossier de la clé, avec toutes ses détections."""
    path: str
    rel: str
    kind: str
    fstype: str
    findings: list = field(default_factory=list)

    @property
    def level(self):
        return "menace" if any(f.level == "menace" for f in self.findings) else "suspect"

    @property
    def repair_only(self):
        return all(f.repair for f in self.findings)

    @property
    def recommended(self):
        return "reparer" if self.repair_only else "quarantaine"

    def text(self):
        tag = "MENACE" if self.level == "menace" else ("À RÉPARER" if self.repair_only else "SUSPECT")
        return "\n".join([f"[{tag}] {self.rel}"] + [f"    - {f.engine} : {f.name}" for f in self.findings])


@dataclass
class ScanResult:
    items: list
    nfiles: int
    errors: list
    complete: bool       # False si l'antivirus principal n'a pas pu tout analyser
    engines: list
