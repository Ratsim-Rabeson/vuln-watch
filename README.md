# vuln-watch — scan de CVE à la demande

- **Watchlist** : les failles suivies et leurs plages de versions (`watchlist.toml`) ;
  Java4Shell et NGINX2Root y sont déjà.
- **Scan d’un projet** : dans un job GitLab CI ou sur un poste, verdict et rapports.
- **Scan d’un groupe GitLab** : tous les projets d’un coup, par l’API, pour pré-remplir
  le recensement.
- **Preuve** : version relevée dans l’image construite, rapports Markdown, JSON et CSV
  au format du fichier de suivi.

Python 3.11 ou plus récent, bibliothèque standard uniquement : aucune dépendance à installer.

## Démarrage rapide

```bash
python3 vuln_watch.py rules                          # failles suivies
python3 vuln_watch.py scan chemin/du/projet          # un dépôt
python3 vuln_watch.py scan . --cve CVE-2026-123007   # une seule faille
python3 -m unittest discover -s tests -v             # tests (27)
```

Code retour : `0` rien de bloquant, `1` faille trouvée (selon `--fail-on`),
`2` erreur de configuration, `3` erreur d’accès à GitLab.

## Les verdicts

| Verdict | Sens | Suite à donner |
|---|---|---|
| VULNÉRABLE | version dans une plage vulnérable | planifier la correction (lot, date) |
| À VÉRIFIER | version inconnue ou imprécise : tag flottant (`nginx:stable`), version majeure seule (`jdk21`), produit tiers (Keycloak, ingress-nginx…), paquet de distribution | relever la version exacte (job probe) ou lire l’avis éditeur |
| OK | version hors plage vulnérable | joindre le rapport comme preuve |

Chaque constat porte un contexte : **exécution** (image livrée, manifest de déploiement,
version relevée), **build** (étape intermédiaire d’un Dockerfile multi-stage) ou **CI**
(image d’un job). Seuls les constats en exécution comptent pour `--fail-on` et pour le CSV.

## Ce qui est analysé

| Source | Ce qui est lu |
|---|---|
| `Dockerfile*`, `Containerfile*` | images `FROM`, `ARG` résolus, étapes multi-stage |
| `*.yml`, `*.yaml` | `image:` (Kubernetes, Compose, GitLab CI), `repository:` + `tag:` (Helm) |
| `*.conf`, `*.conf.template` | `listen … http2` et `http2 on;` (exposition NGINX2Root) |
| `package-lock.json` | versions npm, pour les règles `npm:paquet` |
| `*.cdx.json`, `bom.json`, `sbom*.json` | SBOM CycloneDX : runtime Java, nginx, paquets npm et Maven |
| `--probe fichier` | sortie de `java -version`, du fichier `release` et de `nginx -v` relevée dans l’image |

Les dossiers `node_modules`, `target`, `build`, `dist`, `.git` et les jeux de test (`fixtures`, `testdata`) sont ignorés. Rien n’est
exécuté ni modifié dans les dépôts analysés.

## Dans un pipeline GitLab

Dans le `.gitlab-ci.yml` du projet :

```yaml
include:
  - project: "<groupe>/vuln-watch"
    ref: main
    file: "ci/vuln-watch.gitlab-ci.yml"

variables:
  VULN_WATCH_APP_IMAGE: "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA"
```

Deux jobs s’ajoutent au stage `test` :

1. `vuln-watch-probe` démarre l’image construite et relève `java -version` et `nginx -v` :
   c’est la version réelle, la preuve la plus forte ;
2. `vuln-watch` analyse le dépôt, lit le relevé et publie `vuln-watch-report/` en artefact.

Démarrer en observation (`VULN_WATCH_FAIL_ON: "never"`), puis passer à `"vulnerable"`
quand les lots sont corrigés, pour qu’aucune régression ne repasse.
Prérequis : dans vuln-watch, *Settings > CI/CD > Job token permissions*, autoriser le groupe.

## Scan à la demande d’un groupe

```bash
export GITLAB_TOKEN=…   # jeton en lecture seule, portée read_api, rôle Reporter
python3 vuln_watch.py group --gitlab-url https://gitlab.exemple --group lcl/bpi --out rapport-bpi
python3 vuln_watch.py group --gitlab-url https://gitlab.exemple --group lcl/bpi --cve Java4Shell --only "lcl/bpi/cia/*"
```

Le script lit l’arborescence de la branche par défaut de chaque projet par l’API, ne télécharge
que les fichiers utiles, et respecte les limites de débit (réessais sur 429). Options utiles :
`--ca-file` pour l’autorité de certification interne, `--max-projects`. Le proxy est pris dans
`HTTPS_PROXY`.

En pipeline planifié : voir le job `vuln-watch-group` du `.gitlab-ci.yml` de ce dépôt
(variable masquée `VULN_WATCH_TOKEN`).

## Les rapports

| Fichier | Usage |
|---|---|
| `vuln-watch-report.md` | lecture humaine, à joindre au canal ou à une merge request |
| `vuln-watch-report.json` | traitement automatique, historique |
| `vuln-watch-recensement.csv` | import dans l’onglet Recensement du fichier de suivi |

Le CSV (séparateur point-virgule, UTF-8) reprend les colonnes B à T de l’onglet
Recensement : coller ses lignes à partir de la colonne B. Statut proposé : « À qualifier »
pour VULNÉRABLE et À VÉRIFIER, « Non concerné » pour OK (à passer en « Vérifié » si l’asset
était déjà suivi et vient d’être corrigé). Tribu, squad, lot et date cible restent à compléter.

Un exemple de rapport de groupe est dans `exemples/`.

## Ajouter une CVE

1. Lire l’avis officiel (éditeur, CERT-FR, NVD) : composant, versions vulnérables, versions corrigées.
2. Ajouter une règle `[[rule]]` dans `watchlist.toml` : plages au format `>=A <B`
   (A inclus, B exclu), `label` identique à la liste du fichier de suivi, `targets`, `fix`,
   `sources`, `checked_on`. Un modèle npm et Maven est en bas du fichier.
3. Vérifier : `python3 vuln_watch.py rules`, puis un scan sur un projet connu.
4. Faire relire par un Security Champion. Aucune plage sans source.

## Skill d’agent

`skill/vuln-watch/SKILL.md` décrit à un agent de code compatible avec le format SKILL.md
comment utiliser l’outil : vérifier la watchlist, proposer une règle sourcée pour une nouvelle
CVE, lancer le scan, résumer les rapports. Pour Claude Code, copier le dossier dans
`.claude/skills/` du dépôt.

## Limites connues

- **Analyse statique des références d’images** : un tag flottant (`stable`, `latest`, `21-jre`)
  ne dit pas la version exacte. Le job probe ou une SBOM lèvent le doute.
- **Paquets de distribution** (apt, apk, rpm) : un correctif peut être rétroporté sans changer
  la version amont ; vuln-watch rend alors À VÉRIFIER. Xray et Sysdig connaissent ces rétroportages.
- **Images sans shell** (distroless) : le probe échoue ; générer une SBOM (Syft) et la passer
  avec `--sbom`.
- **Serveurs hors conteneurs, appliances, plateformes partagées** : hors de portée ; ils passent
  par l’onglet Partenaires du fichier de suivi.
- **Java4Shell** : l’exploitation suppose un processeur x86-64 avec AVX-512 VBMI ; vuln-watch ne
  connaît pas les processeurs de production (à demander à CAGIP). Sur un serveur, la version
  réellement chargée se lit avec `jcmd <PID> VM.version`.
- vuln-watch complète le Command Center sans le remplacer : il répond vite, sur les failles de
  la watchlist, et produit une preuve par projet.

## Sécurité

- Jeton GitLab lu dans une variable d’environnement, jamais en argument ni dans les rapports ;
  en CI, variable masquée et protégée.
- Accès en lecture seule (portée read_api) ; aucun autre appel réseau que l’API GitLab.
- Aucun code des dépôts analysés n’est exécuté.
