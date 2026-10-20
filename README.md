# antivirusb : station blanche de contrôle des clés USB

Une clé USB de démarrage transforme un vieux PC en **station blanche**. Avant d'utiliser
une clé USB sur le parc Windows, on la branche sur la station, qui l'analyse puis propose de
**désinfecter, mettre en quarantaine ou supprimer** ce qu'elle trouve, toujours avec confirmation.
Les définitions antivirus se mettent à jour via le **partage de connexion USB d'un smartphone**.

## Fonctionnement

| Élément | Choix |
|---|---|
| Système | Debian 13 « trixie » en version live, **en lecture seule** : un redémarrage remet la station à neuf |
| Stockage | Le **disque interne** du PC (étiquette `AVDATA`) contient les définitions, la quarantaine et les rapports |
| Antivirus | **ClamAV** (service `clamd` chargé en mémoire, analyses rapides) |
| Règles | **YARA** [signature-base](https://github.com/Neo23x0/signature-base) (licence DRL 1.1) |
| Documents | **oletools** / MacroRaptor : macros Office malveillantes |
| Vers USB | Analyse maison : `autorun.inf`, raccourcis `.lnk` piégés, dossiers masqués, double extension, `.exe` déguisé en document, caractère d'inversion du texte |
| Protection | Clés montées en **lecture seule et sans exécution possible**, analyseurs lancés **sans privilèges**, **USBGuard** bloque les périphériques « BadUSB » (clé qui se fait passer pour un clavier), réseau **coupé** sauf pendant les mises à jour, une seule console (le menu) |

**Désinfection** : sur une clé USB, les malwares sont des fichiers entiers. On les met en
quarantaine, ou on les supprime. La *réparation* concerne les vers à raccourcis : les dossiers
de l'utilisateur, masqués par le ver, sont réaffichés, et un dossier au nom invisible est renommé
« Fichiers récupérés ». Après chaque traitement, une **analyse de contrôle** est relancée.

**Verdicts** : 🟩 VERT, aucune menace connue, la clé peut être utilisée. 🟧 ORANGE, éléments
suspects laissés sur la clé ou analyse incomplète : demander à l'administrateur. 🟥 ROUGE, menace
présente : ne pas utiliser la clé.

## Matériel

- Le vieux PC fixe, avec un **processeur 64 bits** (pratiquement tout PC postérieur à 2008)
- **4 Go de RAM conseillés** : ClamAV occupe environ 1,5 Go. Avec 2 Go, ça fonctionne, mais lentement.
- Un **disque interne** qui sera **entièrement effacé** au premier démarrage
- Une clé USB de **4 Go minimum** pour le système. Elle reste branchée en permanence sur la station.
- Un smartphone et son câble USB pour les mises à jour

---

## 1. Construire l'image ISO

La construction nécessite une machine **Linux x86-64**. Une VM Windows ARM sur Mac
(Apple Silicon) ne convient pas. Deux méthodes :

### Méthode A (recommandée) : GitHub Actions, gratuit, rien à installer

1. Créez un compte sur <https://github.com> si vous n'en avez pas.
2. Créez un dépôt **privé** nommé `antivirusb` (bouton **New repository**).
3. Envoyez-y le contenu de ce dossier, sous-dossier `.github` compris (bouton
   **uploading an existing file**, glisser-déposer du dossier).
4. Onglet **Actions** > **Construire l'ISO antivirusb** > **Run workflow**.
5. Au bout de 30 à 60 minutes, téléchargez l'artefact **antivirusb-iso** en bas de la page du
   « run ». C'est un zip qui contient l'ISO et son empreinte SHA-256.

Le serveur vérifie d'abord la syntaxe du programme. En cas d'erreur, le journal du « run »
l'indique.

### Méthode B : machine Debian amd64 (PC, VM sur un PC Intel/AMD, WSL2)

```bash
sudo bash build.sh
```

Il faut environ 10 Go libres et une connexion Internet (environ 1 Go téléchargé). L'image
`antivirusb-AAAAMMJJ.iso` est créée à côté de `build.sh`. Sur un Mac Apple Silicon, on peut
essayer Docker Desktop avec émulation, mais c'est lent et pas garanti :
`docker run --rm --privileged --platform linux/amd64 -v "$PWD":/src -w /src debian:trixie bash build.sh`

## 2. Écrire l'ISO sur la clé de démarrage

Avec **Rufus** (Windows) ou **balenaEtcher** (Windows et macOS) : sélectionnez l'ISO puis la clé.
Rufus demande le mode d'écriture : choisissez **« Écrire en mode Image DD »**.
⚠️ Tout le contenu de la clé est effacé.

## 3. Premier démarrage (administrateur)

1. Branchez la clé antivirusb sur le PC, allumez-le et ouvrez le menu de démarrage (touche
   **F12**, **F11**, **F8** ou **Échap** selon la marque), puis choisissez la clé USB. Le BIOS
   peut aussi être réglé pour démarrer toujours sur USB.
2. **Configuration initiale** : choisissez le disque interne, puis tapez `EFFACER` pour confirmer.
3. Choisissez le **mot de passe administrateur**.
4. Faites une **mise à jour** (menu, choix 2). La première télécharge environ 300 Mo de données
   mobiles : définitions ClamAV, puis compilation des règles YARA, quelques minutes sur un vieux PC.

## 4. Fiche utilisateur (à imprimer et poser à côté de la station)

> **Contrôler une clé USB avant de l'utiliser sur un ordinateur du parc**
>
> 1. Allumez la station (la clé antivirusb doit rester branchée). Le menu apparaît.
> 2. Choisissez **1. Analyser une clé USB**, branchez votre clé, puis **Continuer**.
> 3. Attendez la fin de l'analyse.
>    - S'il y a des menaces, choisissez **Traiter automatiquement (recommandé)**, puis **Appliquer**.
> 4. Lisez le résultat :
>    - 🟩 **VERT** : la clé peut être utilisée.
>    - 🟧 **ORANGE** : demandez l'avis de l'administrateur.
>    - 🟥 **ROUGE** : **n'utilisez pas la clé**, remettez-la à l'administrateur.
> 5. Retirez la clé quand la station l'indique.
>
> Ne débranchez jamais le clavier ni la souris de la station. Si un message
> « PÉRIPHÉRIQUE BLOQUÉ » apparaît, ne réutilisez pas ce périphérique.

**Mise à jour** (au moins une fois par semaine ; la station prévient au bout de 2 jours) : menu
**2**, branchez le smartphone, activez le **partage de connexion USB**, puis **Continuer**.

## 5. Administration (menu 4, avec mot de passe)

- **Rapports** : un rapport détaillé par analyse, plus `journal.csv` avec date, clé, numéro de série et verdict
- **Quarantaine** : consulter (empreinte SHA-256, détections), **restaurer** un faux positif sur une clé, supprimer, vider
- **État de la station** : mémoire, stockage, âge des définitions, versions, USBGuard
- **Terminal** de maintenance (`exit` pour revenir au menu)

Les fichiers en quarantaine sont dans `/srv/avdata/quarantine/<n°>/fichier.zip`, une archive
zip protégée par le mot de passe `infected`, comme le veut la convention pour les échantillons.

## 6. Maintenance

- **Reconstruire l'ISO tous les 6 à 12 mois** pour profiter des correctifs Debian et des nouvelles
  versions de ClamAV. Le serveur de ClamAV refuse les versions trop anciennes. Il suffit de
  relancer le workflow puis de réécrire la clé. Le disque AVDATA est conservé.
- Si une mise à jour ClamAV échoue avec un code 429 ou 403, le serveur de ClamAV limite les
  téléchargements trop fréquents : réessayez quelques heures plus tard.
- Journal technique, pendant la session : `/var/log/antivirusb.log` (menu Terminal).

## 7. Limites (à connaître)

- Un verdict vert signifie « **aucune menace connue** ». Un malware très récent, ou un
  fichier chiffré par mot de passe, peut passer.
- ClamAV détecte moins bien les malwares Windows que les antivirus commerciaux. Les règles
  YARA et l'analyse des vers USB complètent la détection.
- Le **firmware** d'une clé piégée (BadUSB) ne peut pas être analysé. USBGuard bloque les
  périphériques qui se présentent comme un clavier, mais pas une clé qui reste un simple
  support de stockage.
- Clés **exFAT** : un dossier masqué par un ver est détecté s'il a un nom invisible, mais
  l'attribut « caché » ne peut pas être retiré depuis Linux. Les clés FAT32 et NTFS sont
  entièrement prises en charge.

## Arborescence

```
build.sh                               construction de l'ISO (live-build)
.github/workflows/build-iso.yml        construction automatique sur GitHub
config/package-lists/                  paquets Debian installés
config/hooks/live/                     réglages (ClamAV, USBGuard, utilisateur avscan)
config/includes.chroot/
  usr/local/bin/antivirusb             lanceur du menu
  usr/local/lib/antivirusb/avb/        programme (Python)
    main.py        menus, analyse, actions, administration
    scanners.py    ClamAV, YARA, macros
    worm.py        heuristiques vers USB + réparation
    quarantine.py  quarantaine
    update.py      mise à jour via smartphone
    storage.py     disque AVDATA
    devices.py     détection et montage des clés
  usr/local/lib/antivirusb/avb_macro.py   analyse des macros (sans privilèges)
  etc/usbguard/rules.conf              politique anti-BadUSB
```
