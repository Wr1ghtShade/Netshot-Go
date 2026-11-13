# Journal des modifications - NetShot (Go)

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). La version Python a son
propre journal dans le dépôt [Netshot](https://github.com/Wr1ghtShade/Netshot).

## [1.2.3] - 2026-11-13

Nouveau logo « radar », choisi parmi les six pistes proposées.

### Modifié
- Logo : carré arrondi en dégradé bleu → cyan, trois cercles de radar, secteur de balayage cyan,
  ligne de balayage et trois points blancs (les services trouvés). Il remplace la fenêtre de
  navigateur et les repères de capture.
- Petites tailles : sous 48 px, traits et points plus épais et cercle intérieur supprimé, pour
  rester lisible dans la barre des tâches et en favicon.
- `tools/mkicon` dessine le radar (toujours sans dépendance) et prend une option
  `-variant python -out <dossier>` qui produit `icon.png` (256 px) et `icon-32.png` (32 px) aux
  couleurs de la version Python (indigo, balayage ambre).
- Fichiers régénérés : `cmd/netshot/icon.png` (favicon de l'interface et logo du rapport),
  `cmd/netshot/rsrc_windows_amd64.syso` (icône de l'exe), `assets/icon.ico` (16 à 256 px).
- Captures du README refaites sur un intranet de démonstration (page de connexion en http et
  https) : onglet Scan après la capture, et nouvelle capture du rapport HTML du même scan
  (`docs/netshot-go-rapport.png`).

### Fichiers
- `tools/mkicon/main.go`, `cmd/netshot/icon.png`, `cmd/netshot/rsrc_windows_amd64.syso`,
  `assets/icon.ico`, `cmd/netshot/version.go`, `README.md`, `docs/netshot-go.png`.

### Tests
- `go vet` ; icônes générées et vérifiées de 16 à 256 px sur fond clair et sombre ; interface
  ouverte dans Chrome headless.
- Non vérifié : l'icône de l'exe dans l'Explorateur Windows (compilation Windows non faite ici).

## [1.2.2] - 2026-11-13

Refonte de l'interface, étape 2 : les autres onglets prennent le style de l'onglet Scan (même
étape que la version Python 1.2.2).

### Modifié
- Titres d'onglet (Domaine, DNS, Whois, Certificats, Leaks, Clés API) avec leur icône au trait.
- Chaque onglet occupe toute la hauteur ; tant qu'il n'y a pas de résultat, un encadré explique ce
  qui s'affichera (Domaine, DNS, Whois, Certificats, Leaks). Fini le grand vide sous le formulaire.
- **Domaine** : sources en boutons à cocher ; une source dont la clé manque est en pointillés,
  avec une icône de clé à la place de l'emoji 🔑.
- **DNS et Whois** : constats en pastilles colorées (orange = point d'attention, vert = bon point,
  gris = neutre) ; les signes ⚠ / ✓ sont remplacés par la couleur.
- **Tableaux** : en-têtes en petites capitales, ligne surlignée au survol.
- **Clés API** : une grille nom / état (« configurée » en vert, « absente ») / champ / lien
  (« obtenir une clé » ou « compte »).
- Les aides ne coupent plus les mots en plein milieu.
- Statut initial de la barre d'action : « Prêt. » (le nombre d'UA est affiché à côté de la liste).
- Capture du README mise à jour.

### Corrigé
- Onglet DNS : erreur JavaScript quand un domaine ne renvoie aucun enregistrement (liste vide
  renvoyée en `null`).

### Fichiers
- `cmd/netshot/gui.html`, `version.go`, `README.md`, `docs/netshot-go.png`.

### Tests
- `go vet`, `go test`.
- Chaque onglet ouvert dans Chrome headless (thème clair et sombre), requête DNS lancée depuis
  l'interface, scan complet sur une page locale ; aucune erreur JavaScript.

## [1.2.1] - 2026-11-13

Refonte de l'interface, étape 1 : en-tête et onglet Scan, d'après la maquette validée (même
organisation que la version Python 1.2.1).

### Modifié

**En-tête**
- Onglets dans une barre segmentée, avec des icônes au trait à la place des emojis ; compteurs en
  pastille (sans parenthèses) sur Scan, Certificats, Leaks et Clés API.
- Bouton « Quitter » discret (contour rouge, plein seulement au survol).
- Sélecteur de thème raccourci (« Auto (Windows) », « Clair »…) avec une icône palette.

**Onglet Scan**
- Colonne de gauche : cibles avec un compteur (entrées et estimation du nombre d'adresses des plages
  CIDR, « + AS » si un AS est présent), aide sous la zone, ports avec préréglages en boutons
  (Défaut, Web étendu, Services non web, Web + services ; le bouton actif suit le contenu du
  champ), user agents en boutons à cocher avec compteur et sélection rapide.
- Colonne de droite, options en groupes avec interrupteurs :
  - **Analyse passive** (bleu) : enrichissement, réputation des noms, certificats TLS, URL sur les
    captures ;
  - **Tests actifs** (orange, badge « requêtes en plus ») : dossiers courants, fichiers sensibles,
    présence d'un WAF, avec le nombre de requêtes par service ;
  - **Réglages avancés** et **Périmètre et proxy** repliés, avec un résumé sur une ligne mis à jour
    en direct.
- Barre d'action toujours visible sous l'onglet : Lancer le scan, Arrêter, progression fine,
  Ouvrir le dossier, Ouvrir le rapport. Avant, elle pouvait sortir de l'écran (1440×900).
- Journal et dernière capture dans un seul panneau à deux onglets, plus compact ; un point signale
  une capture pas encore vue. Les autres onglets n'affichent que le journal, comme avant.

**Réputation des noms**
- Interrupteur séparé de l'enrichissement dans l'interface (champ `reputation` de `/api/start`).
- Nouvelle option `-no-reputation` ; `-no-enrich` coupe toujours les deux.
- Sans enrichissement, les noms sont résolus par le résolveur du système pour écarter ceux qui
  pointent vers une IP interne (aucun appel à un tiers pour ça).

### Fichiers
- `cmd/netshot/gui.html` (CSS, en-tête, onglet Scan, barre d'action, panneau journal / capture,
  JavaScript : compteurs, préréglages, résumés, onglets du bas).
- `cmd/netshot/scan.go` (`Options.Reputation`), `gui.go` (champ `reputation`), `main.go`
  (`-no-reputation`), `reputation.go` (`resolveHosts`), `version.go`, `README.md`.

### Tests
- `go vet`, `go test`.
- Interface ouverte dans Chrome headless (1440×900, 1280×720, thèmes clair, sombre et Terminal),
  aucune erreur JavaScript ; scan lancé depuis l'interface sur une page locale : progression,
  rapport, aperçu de capture et point de nouvelle capture vérifiés.

## [1.2.0] - 2026-11-13

Ajout des contrôles de [web-check](https://web-check.xyz/checks) qui manquaient à NetShot, sans passer
par l'API web-check (encore en développement) : tout est fait localement ou auprès des sources
d'origine. Même fonctionnement que la version Python 1.2.0.

### Ajouté

**Contenu mixte et SRI** (analyse des pages, active par défaut)
- Liste des ressources (`script`, `link`, `img`, `iframe`, `audio`, `video`, `source`, `embed`,
  `track`, `object`) et des formulaires en `http://` sur une page HTTPS, lue dans le DOM de la page
  déjà chargée. Aucune requête de plus.
- Liste des scripts et feuilles de style d'un autre site chargés sans attribut `integrity` (SRI).
- Les deux constats s'ajoutent aux « Constats en-têtes » (`contenu mixte : N ressource(s)…`,
  `SRI absent : N script(s)…`).

**Traqueurs et tiers** (analyse des pages, active par défaut)
- Environ 80 domaines connus classés par catégorie : mesure d'audience, publicité, réseaux sociaux,
  analyse comportementale, gestionnaire de balises, consentement, polices (Google Fonts), vidéo,
  chat, monitoring, anti-robot.
- Liste des hôtes tiers appelés par la page (balises du DOM et Resource Timing), 100 au plus.

**WAF / CDN de protection**
- Détection passive dans les en-têtes et les cookies de chaque page : Cloudflare, Akamai, Imperva /
  Incapsula, Sucuri, F5 BIG-IP ASM, AWS WAF, AWS CloudFront, Azure Front Door, Azure Application
  Gateway, FortiWeb, Barracuda, Citrix NetScaler AppFirewall, ModSecurity, Fastly, DDoS-Guard,
  Wallarm, Reblaze, Radware. Le WAF trouvé s'affiche dans le journal (`WAF …`).
- `-waf-probe` (désactivé par défaut, test **actif**) : une requête normale puis une requête avec une
  chaîne inoffensive qui ressemble à une attaque (`<script>`, `' OR '1'='1`, `../`) dans le paramètre
  `netshot_waf_test`. Un code 400 / 403 / 406 / 418 / 429 / 501 / 503 / 999 différent de la page
  normale, ou une page de blocage reconnue (Cloudflare, Imperva, Akamai, AWS, F5, ModSecurity,
  Sucuri, FortiWeb, Barracuda, NetScaler, Wordfence, NAXSI, Wallarm, DDoS-Guard), donne
  `bloqué (403 au lieu de 200) : <produit>`. Respecte `-d` et le proxy.
- Interface : case « Tester la présence d'un WAF (requête de test) ».

**Réputation des noms** (avec l'enrichissement, `-no-enrich` la coupe)
- Résolveurs DNS filtrants, sans clé : Quad9 (malware / phishing), Cloudflare 1.1.1.2 (malware),
  OpenDNS (phishing), AdGuard DNS (publicité / traqueurs). Un nom qui résout chez 1.1.1.1 (ou
  9.9.9.10) mais que le résolveur filtrant bloque (NXDOMAIN, `0.0.0.0`, `127.0.0.1`, IP de page de
  blocage) est signalé. Si le port 53 sortant est filtré, le journal le dit.
- URLhaus (abuse.ch), nouvelle clé gratuite `abusech` : URL malveillantes connues sur le nom, nombre
  encore en ligne, type de menace, présence dans Spamhaus DBL et SURBL.
- VirusTotal (clé `virustotal` existante) : moteurs qui classent le domaine malveillant ou suspect.
  Limité aux 8 premiers noms, une requête toutes les 15 s (API gratuite : 4 / minute).
- Google Safe Browsing, nouvelle clé gratuite `safebrowsing` : malware, hameçonnage, logiciel
  indésirable sur les URL capturées (une seule requête pour 500 URL).
- Seuls les noms publics partent : un nom qui pointe vers une IP interne n'est jamais envoyé.
- Niveau par nom : critique, haute, moyenne, info (voir README).

**DKIM** (`-dns` et onglet DNS)
- 32 sélecteurs courants interrogés (`google`, `selector1`, `selector2`, `k1`, `s1`, `mailjet`,
  `brevo1`, `protonmail`, `fm1`…), y compris via le CNAME de Microsoft 365.
- Nouveaux constats : `✓ DKIM publié (sélecteur(s) : …)`, `DKIM non trouvé parmi 32 sélecteurs
  courants` (seulement si le domaine a un MX ou un SPF), `Clé DKIM révoquée (p= vide)`.

**Rapport et exports**
- Rapport : section « Réputation » en tête, sections « WAF / CDN de protection », « Contenu mixte et
  SRI » et « Traqueurs et tiers » après les en-têtes de sécurité.
- `results.csv` : nouvelles colonnes `waf`, `waf_probe`, `mixed_content`, `no_sri`, `trackers`,
  `third_party_hosts`.
- `results.json` : nouveaux champs par service (`waf`, `waf_probe`, `mixed_content`, `no_sri`,
  `trackers`, `third_party_hosts`) et nouvelle clé `reputation`.
- `results.xlsx` : nouveaux onglets « WAF, SRI, traqueurs » et « Réputation ».
- Nouveau fichier `reputation.csv`.

### Modifié
- `-no-enrich` coupe aussi la réputation des noms ; la case de l'interface s'appelle « Enrichir les
  IP, les versions et la réputation ».
- `-list-sources` décrit les sources de réputation.
- `detectTech` passe par une nouvelle fonction `detectWith(rules, …)` pour réutiliser le moteur de
  signatures avec les règles WAF, sans état partagé entre les workers.
- Version 1.2.0.

### Fichiers
- Nouveaux : `cmd/netshot/pagecheck.go`, `cmd/netshot/reputation.go`, `cmd/netshot/pagecheck_test.go`.
- Modifiés : `scan.go` (champs `Result`, option `WAFProbe`, appel des contrôles et de la réputation),
  `webinfo.go` (`detectWith`), `dns.go` (DKIM), `report.go`, `export.go`, `keys.go` (`abusech`,
  `safebrowsing`), `main.go` (`-waf-probe`), `gui.go`, `gui.html`, `version.go`, `README.md`.

### Tests
- `go test` : contenu mixte, SRI, traqueurs, WAF passif, DKIM (dont CNAME Microsoft 365 et clé
  révoquée), niveaux de réputation.
- Scan de bout en bout sur une page locale (HTTPS, Chrome headless) avec `-waf-probe` : WAF passif et
  actif, contenu mixte, SRI, traqueurs, sections du rapport, `results.json` et `results.xlsx`.
- Non testé en conditions réelles : les appels à Quad9 / Cloudflare / OpenDNS / AdGuard, URLhaus,
  VirusTotal et Safe Browsing (réseau de l'environnement de développement filtré).

## [1.1.0] - 2026-11-12

Portage des nouveautés de la version Python 1.1.0. Les options gardent la syntaxe Go (un seul
tiret : `-files`, `-proxy`…).

### Ajouté

**Analyse des pages** (active par défaut, `-no-analyze` pour la couper)
- Détection des technologies et de leur version : serveur, langage, CMS, framework, équipements
  (FortiGate, NetScaler, BIG-IP…), lus dans les en-têtes, les cookies, la balise `generator`, les
  scripts et le HTML.
- Recherche des CVE de chaque version dans NVD, classées avec CISA KEV, EPSS et CVSS. Seuls le
  produit et la version sont envoyés. Nouvelle clé optionnelle `nvd` pour aller plus vite.
- Hash du favicon, identique au filtre Shodan `http.favicon.hash`, avec un lien de recherche.
- Repérage des pages sensibles : `index-of` (liste de fichiers), `debug`, `default` (page par
  défaut), `admin`, `login`, `auth-http`.
- Regroupement des captures visuellement identiques (hash calculé en Go sur l'image), avec une case
  pour masquer les doublons. Une page sensible n'est jamais masquée.
- Contrôle des en-têtes de sécurité : HSTS, CSP, anti-clickjacking, `nosniff`, `Referrer-Policy`,
  version divulguée, cookies sans `Secure` / `HttpOnly` / `SameSite`, mot de passe envoyé en HTTP.

**Reconnaissance approfondie**
- `-files` : test d'environ 65 fichiers sensibles (`.env`, `.git/HEAD`, sauvegardes, `phpinfo`,
  `actuator/env`…), signature vérifiée pour écarter les pages 404 personnalisées. Liste intégrée à
  l'exe (`files.txt`) ou `-files-wordlist`.
- `-dirs` : test d'environ 95 dossiers courants et capture de ceux qui affichent une liste de
  fichiers. Liste intégrée (`dirs.txt`) ou `-dirs-wordlist`.
- Analyse du JavaScript chargé par les pages, récupéré dans le navigateur sans requête de plus :
  chemins d'API, URL internes, secrets masqués dans toutes les sorties.
- Lecture de `robots.txt`, `sitemap.xml` et `security.txt`.
- Détection des sous-domaines exposés à une prise de contrôle (CNAME vers un service cloud
  disparu).
- Lecture des bannières des services non web (SSH, FTP, SMTP, POP, IMAP, MySQL, Redis, VNC, RDP).
  La version trouvée part dans la recherche de CVE.
- Rappel des identifiants par défaut connus de chaque technologie trouvée. Rien n'est essayé.
- Préréglages de ports : `-p web`, `-p services`, combinables.

**Périmètre et proxy**
- `-exclude` et `-exclude-file` : les cibles hors périmètre ne sont jamais testées.
- `-proxy` : proxy HTTP (Burp, ZAP), avec mot de passe possible, ou SOCKS5. Le navigateur, les
  favicons, les dossiers et les fichiers passent par le proxy ; avec SOCKS5, le test des ports
  aussi. Edge envoie un peu de trafic Microsoft de fond par le proxy.

**Rapport et exports**
- Barre de filtres dans `report.html` : recherche libre, code HTTP, repère, technologie.
- Nouvelles sections en tête du rapport, comme la version Python.
- `results.xlsx` (un onglet par thème, filtres, en-tête figé) et `results.json`, avec la seule
  bibliothèque standard.
- `technologies.csv` et nouvelles colonnes dans `results.csv`.

**Interface graphique**
- Menu « Préréglages… » pour les ports.
- Cases « Tester les dossiers courants » et « Tester les fichiers sensibles ».
- Champs « Proxy » et « Hors périmètre ».

**Tests**
- Tests unitaires : MurmurHash3 (mêmes valeurs que Python), technologies, préréglages de ports,
  règles de fichiers, exclusions, JavaScript, bannières.

## [1.0.0] - 2026-11-12

Première version publiée sur GitHub.

### Contenu
- Exécutable unique Windows ou Linux, piloté par Edge ou Chrome déjà installé.
- Captures d'écran des services web trouvés sur des IP, plages CIDR, AS ou noms d'hôte, avec
  plusieurs user agents et comparaison des réponses.
- Sources passives de sous-domaines (logs CT, DNS passif, archives) et dictionnaire DNS.
- Outils DNS (comme dig), whois (RDAP et port 43), analyse TLS (comme sslscan), fuites de données
  (LeakCheck).
- Enrichissement des IP : Shodan, LeakIX, CISA KEV, EPSS.
- Interface graphique locale (127.0.0.1), thème clair ou sombre.

### Modifié
- `keys.json` est toujours à côté de l'exe. S'il manque, un modèle vide est créé ; un fichier
  existant n'est jamais écrasé. À l'enregistrement, seuls les champs remplis sont modifiés et
  l'ancien fichier est gardé en `keys.json.bak`.

### Retiré
- Reprise des clés depuis `%APPDATA%\netshot`.
