---
name: vuln-watch
description: Vérifie à la demande si un projet ou tout un groupe GitLab est touché par une CVE suivie (Java4Shell, NGINX2Root…) avec l’outil vuln-watch, et aide à ajouter une règle pour une nouvelle CVE. À utiliser pour « est-ce qu’on est touché par CVE-… ? », « scanne ce projet », « la vuln est-elle bien partie ? ».
---

# vuln-watch : scan de CVE à la demande

vuln-watch est un script Python (bibliothèque standard, Python 3.11+) qui compare les versions
de Java et de nginx (et de bibliothèques npm ou Maven) trouvées dans les dépôts à une watchlist de
failles suivies. Il rend un verdict par asset : VULNÉRABLE, À VÉRIFIER ou OK, avec l’emplacement
exact et la version cible.

## Étapes

1. Identifier la faille demandée (CVE, nom comme « Java4Shell », ou identifiant de règle).
   Lister les règles : `python3 vuln_watch.py rules`.
2. Si la faille n’est pas dans `watchlist.toml` :
   - chercher l’avis officiel (éditeur, CERT-FR, NVD) ; relever composant, versions vulnérables,
     versions corrigées, source et date ;
   - proposer une règle au format de `watchlist.toml` (plages `>=A <B`, `label`, `targets`, `fix`,
     `sources`, `checked_on`) ;
   - ne jamais inventer une plage de versions : sans source fiable, le dire et s’arrêter ;
   - faire relire la règle par un Security Champion avant de l’ajouter.
3. Lancer le scan avec `--cve <ID>` :
   - un dépôt local : `python3 vuln_watch.py scan <chemin> --cve <ID> --out /tmp/vw` ;
   - un groupe GitLab : `python3 vuln_watch.py group --gitlab-url <URL> --group <groupe> --cve <ID> --out /tmp/vw`
     (jeton en lecture seule dans la variable `GITLAB_TOKEN`, portée read_api).
4. Lire `/tmp/vw/vuln-watch-report.md` et résumer en quelques lignes : nombre de VULNÉRABLE,
   À VÉRIFIER et OK en exécution, puis la liste des VULNÉRABLE (projet, emplacement, version,
   version cible).
5. Pour chaque À VÉRIFIER, dire pourquoi (tag flottant, produit tiers, paquet de distribution,
   version partielle) et comment lever le doute (job probe, `java -version`, `nginx -v`, avis éditeur).
6. Proposer d’importer `vuln-watch-recensement.csv` dans l’onglet Recensement du fichier de suivi
   (coller à partir de la colonne B).

## Règles

- Ne jamais conclure qu’une faille est éradiquée sans preuve : version relevée sur l’image
  déployée ou job vuln-watch vert, puis confirmation du Command Center le lendemain.
- Les constats « build » et « CI » sont informatifs : ils ne concernent pas les services exposés.
- Ne jamais afficher, enregistrer ni transmettre le jeton GitLab.
- Citer les sources des plages de versions utilisées.
