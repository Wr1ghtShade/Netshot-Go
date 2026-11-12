# Journal des modifications - NetShot (Go)

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). La version Python a son
propre journal dans le dépôt [Netshot](https://github.com/Wr1ghtShade/Netshot).

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
