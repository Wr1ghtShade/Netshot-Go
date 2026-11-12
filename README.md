# netshot (Go)

Inventaire et capture d'écran des services web exposés, à partir d'IP, de subnets CIDR, de numéros
d'AS, de noms d'hôte, d'exports CSV (AD, ADCS, CMDB) ou de sous-domaines trouvés par des sources
passives (logs Certificate Transparency, DNS passif, archives web). Les IP trouvées sont enrichies
avec des sources gratuites (ports et CVE connus, fuites, priorisation KEV / EPSS).
Un seul exécutable portable, sans installation.

![NetShot (Go) : onglet Scan après une capture de example.com et example.org](docs/netshot-go.png)

## 📁 Organisation du dossier

```
netshot-go/
├── README.md
├── build.ps1                 compile vers dist\
├── go.mod, go.sum
├── cmd/netshot/              code source (un seul package Go)
│   ├── main.go               options de la ligne de commande
│   ├── gui.go, gui.html      interface graphique (HTML intégré dans l'exe)
│   ├── scan.go               moteur : test des ports, captures, limite de débit
│   ├── browser.go            lancement et fermeture d'Edge/Chrome headless
│   ├── ct.go                 sources passives de sous-domaines
│   ├── ranges.go             plages d'un AS (RIPEstat), import CSV (AD, ADCS, CMDB)
│   ├── enrich.go             enrichissement des IP (InternetDB, LeakIX, KEV, EPSS, DNS inverse)
│   ├── keys.go               clés API des services gratuits
│   ├── dns.go, dns_*.go      client DNS (comme dig) et serveurs DNS du système
│   ├── tlsscan.go            analyse TLS et certificats (comme sslscan)
│   ├── tlsreport.go          sorties de l'analyse TLS (texte, CSV, rapport)
│   ├── whois.go              whois d'un domaine, d'une IP ou d'un AS (RDAP + port 43)
│   ├── leakcheck.go          fuites de données (LeakCheck Pro API v2), onglet Leaks
│   ├── settings.go           réglages de l'interface (thème) dans settings.json
│   ├── window_*.go           ouverture maximisée de la fenêtre (Windows)
│   ├── wordlist.go, subdomains.txt   dictionnaire de la force brute DNS
│   ├── report.go             report.html et results.csv
│   ├── targets.go, ua.go     analyse des cibles et des ports, liste des user agents
│   ├── icon.png              favicon de l'interface (généré)
│   └── rsrc_windows_amd64.syso   icône de l'exe (généré)
├── tools/mkicon/             générateur de l'icône
├── assets/icon.ico           icône multi-tailles (référence)
└── dist/                     exécutables compilés + dossier screenshots\ par défaut (non versionné)
```

`keys.json` (clés API) et `settings.json` (thème) ne sont jamais versionnés (`.gitignore`).

## ✅ Prérequis sur le poste qui lance le scan

Rien à installer : `netshot.exe` + Edge ou Chrome (Edge est présent par défaut sur Windows 10/11).
Le navigateur est détecté automatiquement. Sinon : `-browser "C:\chemin\msedge.exe"`.

## 🖥️ Interface graphique

Double-clic sur `dist\netshot.exe` (ou lancement sans argument).
L'interface s'ouvre dans une fenêtre Edge/Chrome. Elle est servie en local sur `127.0.0.1`,
sur un port aléatoire et une adresse contenant un jeton aléatoire : elle n'est pas joignable depuis le réseau.

La fenêtre s'ouvre maximisée.

#### 🗂️ Onglets

Dans l'ordre du déroulé d'une reconnaissance :

| Onglet | Rôle |
|---|---|
| **🌐 Domaine** | Ouvert au démarrage. Recherche de sous-domaines dans les sources passives, avec filtres DNS ; les sources à clé restent grisées tant que la clé manque. Les noms trouvés sont ajoutés aux cibles du Scan. |
| **📸 Scan** | Cibles, options, user agents, lancement des captures. Le nombre de cibles s'affiche dans l'onglet. |
| **🧭 DNS** | Enregistrements d'un domaine (comme dig), constats, ajout des hôtes aux cibles, copie au format dig. |
| **🪪 Whois** | Propriétaire d'un domaine, d'une IP ou d'un AS : tableau à gauche, texte WHOIS brut à droite, constats. L'onglet occupe toute la hauteur de la fenêtre. |
| **🔒 Certificats** | Analyse TLS des services https (bouton « Services https du dernier scan »), tableau trié du pire au meilleur, détail au clic, CSV dans le dossier de sortie. |
| **🔓 Leaks** | Fuites de données (LeakCheck, clé requise) : mots de passe masqués par défaut, tri, export CSV. |
| **🔑 Clés API** | Saisie des clés des services gratuits, avec le lien pour en obtenir une. Seuls les champs remplis sont enregistrés, `-` supprime une clé. |

#### 📸 Onglet Scan

- **Cibles** : saisie (IP, CIDR, `AS1234`, nom d'hôte, une par ligne) ou chargement d'un fichier `.txt` ou d'un export `.csv`.
- **Options** : ports, dossier de sortie, nombre de tests en parallèle, timeouts, délai entre deux captures,
  résolution (1366x768, 1920x1080 par défaut, 2560x1440, 4K, mobile).
- **Cases** : « Enrichir les IP » (Shodan, LeakIX, KEV, EPSS), « Analyser les certificats TLS »,
  « Inscrire l'URL sur les captures » (bandeau hôte:port, URL, statut et date en bas de chaque image).
- **User agents** : sélection rapide Navig. / Bots / Tous / Aucun, ou UA personnalisé.
- **Pendant le scan** : barre de progression, boutons Arrêter, Ouvrir le dossier, Ouvrir le rapport.
- **Dernière capture** : aperçu affiché à côté du journal ; clic pour ouvrir l'image.

Chaque scan crée un sous-dossier `scan_<date>` dans le dossier de sortie (par défaut `screenshots\` à côté de l'exe).

#### 🧰 Partout

- **Journal** en bas de chaque onglet, sauf Whois.
- Boutons **Copier** et **Reset** sur les zones de texte, les tableaux et le journal.
- **Thème** choisi dans l'en-tête, gardé dans `settings.json` (à côté de `keys.json`) : Auto (suit Windows),
  Clair, Sombre, Terminal / SOC (bleu nuit, accent cyan, tableaux en police fixe), Orange (anthracite et
  orange), Nord (gris bleutés doux).

#### 🚪 Fermeture

- Fermer la fenêtre arrête le programme au bout de 10 secondes ; un scan en cours est arrêté proprement
  et son rapport écrit. Recharger la page ne l'arrête pas.
- La fenêtre console affichée à côté sert de journal technique ; la fermer arrête aussi le programme.

## ⌨️ Ligne de commande

```
netshot.exe 192.168.1.0/24
netshot.exe -f targets.txt -p 80,443,8080,8443 -o captures
netshot.exe 10.0.0.0/24 -d 2 -u browsers -u bots
netshot.exe 10.0.0.5 -u "MonScanner/1.0"
netshot.exe -list-ua
netshot.exe -ct exemple.fr -ct-private            # sous-domaines qui pointent vers une IP privée
netshot.exe -ct exemple.fr -ct-only > noms.txt    # liste seulement, sans scan
netshot.exe -ct exemple.fr -ct-sources all        # toutes les sources utilisables
netshot.exe AS3215 -p 443                          # plages IPv4 annoncées par l'AS
netshot.exe -f ad_computers.csv                    # export CSV (AD, ADCS, CMDB…)
netshot.exe -key domscan=XXXX -key leakix=YYYY -save-keys   # enregistre des clés
netshot.exe -list-sources                         # sources et clés configurées
netshot.exe -dns exemple.fr                       # enregistrements DNS, comme dig
netshot.exe -dns exemple.fr -dns-server 1.1.1.1   # en interrogeant un serveur précis
netshot.exe -whois exemple.fr -whois 8.8.8.8 -whois AS3215   # propriétaire (RDAP + WHOIS)
netshot.exe -tls exemple.fr -tls intranet:8443    # certificat et configuration TLS
netshot.exe 10.0.0.0/24 -tls-scan                 # scan puis analyse TLS des services https
```

| Option | Rôle | Défaut |
|---|---|---|
| `-f FILE` | fichier de cibles : une par ligne (`#` = commentaire) ou export CSV (répétable) | - |
| `-p PORTS` | ports, ex. `80,443,8000-8010` | `80,443,8000,8080,8443` |
| `-o DIR` | dossier de sortie | `screenshots_<date>` dans le dossier courant |
| `-c N` | tests en parallèle | `10` |
| `-connect-timeout` | délai TCP (s) | `1.5` |
| `-page-timeout` | délai de chargement de page (s) | `15` |
| `-d` | secondes minimum entre deux captures | `0` (pas de limite) |
| `-u` | user agent : nom, `browsers`, `bots`, `all` ou chaîne libre (répétable) | UA du navigateur |
| `-list-ua` | liste les UA intégrés | - |
| `-ct DOMAINE` | ajoute aux cibles les sous-domaines trouvés par les sources passives (répétable) | - |
| `-ct-sources` | `default`, `all`, ou une liste (voir `-list-sources`) | `default` |
| `-key SOURCE=CLÉ` | clé API d'un service (répétable) | fichier de clés |
| `-save-keys` | enregistre les `-key` dans le fichier de clés | - |
| `-list-sources` | liste les sources et les clés configurées | - |
| `-no-enrich` | désactive l'enrichissement des IP | enrichissement actif |
| `-no-label` | n'inscrit pas hôte:port, URL, code HTTP et date en bas des captures | bandeau inscrit |
| `-dns DOMAINE` | affiche les enregistrements DNS du domaine (comme dig) et quitte | - |
| `-dns-server` | serveur DNS pour `-dns`, ex. `1.1.1.1` ou `10.0.0.1:53` | résolveurs du système |
| `-whois REQUÊTE` | propriétaire d'un domaine, d'une IP ou d'un AS (`AS1234`), puis quitte (répétable) | - |
| `-tls HÔTE[:PORT]` | analyse TLS et certificat d'un point d'accès, puis quitte (répétable) | port 443 |
| `-tls-scan` | après le scan, analyse TLS de chaque service https trouvé | non |
| `-ct-all` | garde aussi les noms qui ne résolvent plus dans le DNS | non |
| `-ct-private` | garde seulement les noms qui résolvent vers une IP privée | non |
| `-ct-only` | affiche les noms trouvés et quitte, sans scan | - |
| `-width` / `-height` | taille de la fenêtre de capture | `1920x1080` |
| `-max-hosts` | refuse au-delà de ce nombre d'adresses | `65536` |
| `-browser` | chemin de msedge.exe / chrome.exe | détection auto |
| `-gui` / `-no-open` | force l'interface / n'ouvre pas de fenêtre, affiche seulement l'URL | - |

`Ctrl+C` arrête le scan et écrit quand même le rapport.

## 🔎 Sources passives de sous-domaines

Toutes gratuites. Seul le nom de domaine leur est envoyé, rien n'est envoyé aux cibles.

| Source | Clé | Par défaut | Remarque |
|---|---|---|---|
| crt.name | non | oui | logs CT + historique, le plus complet. 100 requêtes/jour/IP. Domaine racine uniquement |
| Cert Spotter | optionnelle | oui | logs CT. Petit quota sans clé |
| HackerTarget | optionnelle | oui | DNS passif. 50 requêtes/jour sans clé |
| urlscan.io | optionnelle | oui | sites scannés par urlscan |
| VirusTotal | **requise** | oui si clé | DNS passif. 4 requêtes/minute : 4 pages max, espacées de 16 s |
| DNSDumpster | **requise** | oui si clé | enregistrements DNS |
| DomScan | **requise** | oui si clé | logs CT. 1 000 crédits/mois gratuits, 4-5 par page de 500 noms (3 pages max) |
| ViewDNS | **requise** | oui si clé | index ViewDNS. 250 requêtes d'essai puis payant ; 1 requête par page de 1 000 noms (2 pages max) |
| crt.sh | non | non | logs CT, souvent lent ou surchargé (30 s, 2 essais) |
| Wayback Machine | non | non | anciennes URL archivées. Lent : 6 000 URL max, résultat partiel |
| Shodan | **requise** | oui si clé | noms vus par les scans Shodan. 1 crédit de requête par domaine |
| Dictionnaire DNS | non | non | **actif** : force brute DNS avec 1 000 noms courants (`subdomains.txt`, intégré à l'exe) ou `-wordlist fichier`. Détection des wildcards : un DNS qui répond à n'importe quel nom est filtré |

Les sources sont interrogées en parallèle. Les wildcards (`*.exemple.fr`) sont ramenés au domaine.
Par défaut, seuls les noms qui résolvent encore dans le DNS sont gardés. Avec `-ct-private`,
seuls ceux qui pointent vers une IP privée (10.x, 172.16-31.x, 192.168.x…) restent :
pratique pour cibler les services internes publiés avec un certificat public.

Anubis (jldc.me) n'est pas inclus : le service ne répond plus.

## 🧭 DNS d'un domaine (comme dig)

`-dns exemple.fr` (ou l'onglet DNS) interroge le domaine comme `dig`, avec un client DNS intégré,
sans outil externe :

1. une requête **ANY** est tentée et son résultat affiché. La plupart des serveurs la refusent ou
   ne renvoient qu'un HINFO (RFC 8482) ;
2. chaque type est donc interrogé un par un : A, AAAA, CNAME, NS, SOA, MX, TXT, CAA, DS, DNSKEY, HTTPS ;
3. puis les noms utiles sous le domaine : `www`, `_dmarc`, `_mta-sts`, `_smtp._tls`, `default._bimi`,
   SRV Microsoft 365 (`_autodiscover`, `_sip`), Active Directory (`_ldap`, `_kerberos`, `_gc`,
   `_ldap._tcp.dc._msdcs`), XMPP, CalDAV.

Serveur : les résolveurs du système par défaut (donc les zones internes sont visibles depuis le
réseau interne), ou un serveur précis avec `-dns-server`. UDP avec EDNS0, puis TCP si la réponse
est tronquée ou vide (certains résolveurs comme 1.1.1.1 abandonnent les gros TXT en UDP).

Constats affichés : SPF (absent, multiple, `+all`, `~all`, `-all`), DMARC (absent, `p=none`,
`quarantine`, `reject`), CAA, DNSSEC (DS publié), MTA-STS, enregistrements Active Directory visibles.

## 🪪 Whois d'un domaine, d'une IP ou d'un AS

`-whois exemple.fr` (ou l'onglet Whois) interroge deux sources en parallèle, sans outil externe :

- **RDAP** (registre officiel, JSON en HTTPS, serveur trouvé par les fichiers d'amorçage de
  l'IANA) pour le tableau : registrar et son numéro IANA, titulaire, contacts, abuse, dates,
  statut, serveurs de noms, DNSSEC ; pour une IP, la plage, le CIDR, le nom du réseau et le pays ;
- **WHOIS port 43** pour le texte brut : renvoi de l'IANA, puis le registre, puis le registrar pour
  les .com. Ce port est souvent filtré en entreprise : le tableau RDAP reste alors disponible.

Un sous-domaine est cherché sous son domaine enregistré. Constats pour un domaine : expiration
proche ou dépassée, verrou de transfert (absent = détournement plus facile), verrou du registre,
DNSSEC, titulaire masqué. Même résultat que la version Python.

## 🔒 Certificats et configuration TLS (comme sslscan)

`-tls hôte:port`, `-tls-scan` ou l'onglet Certificats. Pour chaque point d'accès :

- **Versions** : SSLv3, TLS 1.0, 1.1, 1.2 et 1.3, testées une par une ;
- **Suites de chiffrement** : toutes celles acceptées, par version, dans l'ordre de préférence du
  serveur, classées sûre / faible (CBC, 3DES, sans confidentialité persistante) / non sûre (RC4, DES,
  EXPORT, NULL, anonyme). 80 suites TLS 1.0-1.2 et les 5 suites TLS 1.3 sont testées avec des
  ClientHello construits à la main : les suites que Go ne sait pas utiliser (DHE, CAMELLIA, RC4…)
  sont donc aussi détectées ;
- **PQC (post-quantique)** : échange de clés hybride X25519MLKEM768 accepté ou non, et groupe négocié
  par défaut. (Aucune autorité publique ne délivre encore de certificat à signature post-quantique :
  seul l'échange de clés peut l'être aujourd'hui.)
- **Certificat** : sujet, SAN, émetteur, dates et jours restants, type et taille de clé, algorithme
  de signature, numéro de série, empreinte SHA-256, wildcard, auto-signé, chaîne, confiance selon
  le magasin Windows (les AC internes déployées par GPO sont donc reconnues), nom couvert,
  OCSP agrafé, Must-Staple, preuves Certificate Transparency (SCT) ;
- **HTTP** : ALPN (h2 / http/1.1) et en-tête HSTS.

Note : F (SSLv3, suite non sûre, certificat expiré, clé RSA < 2048), T (certificat non reconnu,
nom absent, signature SHA-1), C (TLS 1.0 / 1.1 acceptés), B (suites faibles), A, A+ (A + TLS 1.3 + HSTS).
Alertes à 30 et 15 jours de l'expiration.

Non couvert : vulnérabilités spécifiques (Heartbleed, ROBOT, renégociation, compression),
taille des paramètres DH.

## 🔑 Clés API

Comptes gratuits. Les clés sont dans **`keys.json`, à côté de l'exe**. S'il manque au lancement, un
modèle vide est créé ; un `keys.json` existant n'est jamais écrasé. À l'enregistrement, seuls les
champs remplis sont modifiés et l'ancien fichier est gardé en `keys.json.bak`. Le fichier contient les
clés en clair : ne pas partager un dossier qui le contient (il est exclu de git).
Saisie : bloc « Clés API » de l'interface, ou `-key source=CLÉ -save-keys`.
Une variable `NETSHOT_KEY_<SOURCE>` (ex. `NETSHOT_KEY_DOMSCAN`) remplace la clé du fichier.

Services acceptant une clé : certspotter, hackertarget, urlscan, virustotal, dnsdumpster, domscan,
viewdns, leakix.

Non inclus : SecurityTrails (plus de formule gratuite). ViewDNS passe uniquement par son API officielle
(la page web est protégée par un contrôle anti-robot Cloudflare).

## 🌍 Plages d'IP d'un AS

Une cible `AS1234` est remplacée par les plages IPv4 annoncées par cet AS, lues dans RIPEstat
(gratuit, sans clé). La limite `-max-hosts` s'applique ensuite : un gros AS dépasse vite 65 536 adresses.

## 📄 Import CSV (AD, ADCS, CMDB)

`-f` et le bouton « Charger un fichier / CSV » acceptent un export CSV (séparateur `,` ou `;`).
Les colonnes dont le nom ressemble à un hôte sont lues (DNSHostName, Common Name, Subject Alternative
Name, FQDN, IPv4Address…). À défaut, toutes les cellules sont parcourues. Exemples d'export :

```powershell
Get-ADComputer -Filter * -Properties DNSHostName,IPv4Address | Select DNSHostName,IPv4Address | Export-Csv ad.csv -NoTypeInformation
certutil -view -restrict "Disposition=20" -out "CommonName,SAN" csv > adcs.csv
```

Les certificats émis par l'autorité interne (ADCS) sont l'équivalent interne des logs CT :
ils listent les noms des services internes protégés par TLS.

## 🛰️ Enrichissement des IP

Après le scan, chaque IP derrière les services trouvés est enrichie :

- **DNS inverse** (PTR), pour toutes les IP ;
- **Shodan** : avec une clé, la fiche complète de l'IP (organisation, ASN, pays, OS, service vu sur
  chaque port avec produit, version et titre de page, CVE, date du dernier passage) ; sans clé,
  **Shodan InternetDB** (gratuit) : ports ouverts, technologies (CPE), tags et CVE connus ;
- **LeakIX** (clé gratuite) : services indexés et fuites détectées ;
- **CISA KEV** : les CVE activement exploitées sont marquées en rouge ;
- **FIRST EPSS** : probabilité d'exploitation, utilisée pour trier les CVE.

Seules les IP **publiques** sont envoyées à Shodan et LeakIX ; les IP internes ne quittent jamais le poste.
Désactivable avec `-no-enrich` ou la case de l'interface.

## 📊 Résultats

- un PNG par service et par user agent : `<hôte>_<port>_<http|https>[_<ua>].png` ;
- `report.html` : captures groupées par `hôte:port`. Un badge orange signale les services dont
  la réponse change selon l'UA (code HTTP, titre, redirection, échec, taille de page qui varie
  de plus de 20 %). Une case à cocher n'affiche que ces services ;
- `results.csv` : host, port, ua, url, status, title, final_url, size, file, error ;
- avec l'enrichissement : un tableau « Exposition » en tête du rapport (IP les plus critiques
  d'abord), une ligne de synthèse sous chaque service, et `exposure.csv` (ip, noms, ports, CPE,
  CVE, CVE dans KEV, EPSS max, LeakIX).

Limite : seul l'en-tête `User-Agent` change. La page reste chargée par Edge/Chrome, qui envoie
ses autres en-têtes et exécute le JavaScript. Un vrai `curl` peut obtenir une réponse différente.
Le cache HTTP est désactivé pour que chaque UA reçoive une réponse fraîche.

## 🛠️ Compiler

Prérequis : Go (`winget install GoLang.Go`).

```
.\build.ps1             # dist\netshot.exe
.\build.ps1 -Linux      # + dist\netshot-linux
.\build.ps1 -Icon       # régénère l'icône avant de compiler
```

Ou à la main : `go build -ldflags "-s -w" -o dist\netshot.exe ./cmd/netshot`.

`gui.html` et `icon.png` sont intégrés dans l'exe (`go:embed`), l'icône Windows aussi
(fichier `.syso` généré par `tools/mkicon`, sans outil externe). Seul l'exe est à distribuer.

Notes techniques :

- chromedp est volontairement figé en v0.11.2. Les versions 0.15 à 0.23 changent l'API
  ou bloquent après le premier onglet.
- netshot lance lui-même Edge/Chrome headless avec un port de debug et un profil temporaire
  (`browser.go`), au lieu du lanceur de chromedp. Edge se relance parfois dans un processus
  enfant, ce que chromedp prenait pour un échec (« chrome failed to start »). Le navigateur est
  fermé par CDP à la fin ou à l'arrêt, et le profil temporaire est supprimé.

À utiliser uniquement sur des réseaux et des domaines que tu as l'autorisation de scanner.
