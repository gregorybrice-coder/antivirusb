#!/bin/bash
# antivirusb - construction de l'image ISO de la clé de démarrage de la station blanche.
#
# À lancer en root sur une Debian amd64 (machine virtuelle, WSL2, conteneur Docker --privileged) :
#     sudo bash build.sh
# Variables facultatives : DIST (défaut : trixie), WORK (dossier de travail).
set -euo pipefail

DIST="${DIST:-trixie}"
SRC="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-/var/tmp/antivirusb-build}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Lancez ce script en root : sudo bash build.sh" >&2
    exit 1
fi
if [ "$(dpkg --print-architecture)" != "amd64" ]; then
    echo "Ce script doit tourner sur une machine amd64 (x86-64)." >&2
    exit 1
fi

echo "==> Installation des outils de construction"
export DEBIAN_FRONTEND=noninteractive
apt-get update
# (les chargeurs de démarrage sont installés par live-build dans son propre environnement)
apt-get install -y live-build debootstrap squashfs-tools xorriso mtools dosfstools python3-minimal

echo "==> Vérification de la syntaxe du programme"
python3 -m compileall -q "$SRC/config/includes.chroot/usr/local/lib/antivirusb"
python3 -m py_compile "$SRC/config/includes.chroot/usr/local/bin/antivirusb"
find "$SRC/config" -name __pycache__ -prune -exec rm -rf {} +

echo "==> Préparation de $WORK"
if [ -d "$WORK" ]; then
    (cd "$WORK" && lb clean --purge >/dev/null 2>&1) || true
    rm -rf "$WORK"
fi
mkdir -p "$WORK"
cd "$WORK"

lb config \
    --distribution "$DIST" \
    --architectures amd64 \
    --archive-areas "main non-free-firmware" \
    --debian-installer none \
    --binary-images iso-hybrid \
    --iso-volume ANTIVIRUSB \
    --iso-application antivirusb \
    --memtest none \
    --firmware-chroot false \
    --firmware-binary false \
    --apt-indices false \
    --bootappend-live "boot=live components quiet loglevel=3 noswap noroot noautologin hostname=antivirusb locales=fr_FR.UTF-8 keyboard-layouts=fr timezone=Europe/Paris"

echo "==> Ajout de la configuration antivirusb"
cp -a "$SRC/config/." config/
# Fichiers venant de Windows : fins de ligne CRLF et droits d'exécution perdus
find config/hooks config/includes.chroot config/package-lists -type f -exec sed -i 's/\r$//' {} +
chmod 755 config/hooks/live/*.hook.chroot config/includes.chroot/usr/local/bin/*
chmod 600 config/includes.chroot/etc/usbguard/rules.conf

echo "==> Construction (30 à 60 minutes)"
lb build 2>&1 | tee build.log

ISO="$(ls -1 ./*.iso 2>/dev/null | head -n 1 || true)"
if [ -z "$ISO" ]; then
    echo "ÉCHEC : aucune image produite, voir $WORK/build.log" >&2
    exit 1
fi
OUT="$SRC/antivirusb-$(date +%Y%m%d).iso"
cp "$ISO" "$OUT"
(cd "$SRC" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256")
echo
echo "Image prête : $OUT ($(du -h "$OUT" | cut -f1))"
