# vuln-watch — rapport du 23/11/2026 23:54

**Périmètre :** groupe bpi · **projets analysés :** 4 · **failles suivies :** Java4Shell (CVE-2026-114938), NGINX2Root (5 CVE)

| Verdict | En exécution | Build et CI |
|---|---:|---:|
| VULNÉRABLE | 2 | 0 |
| À VÉRIFIER | 2 | 2 |
| OK | 3 | 0 |

## VULNÉRABLE — en exécution

| Projet | Faille | Composant | Version | Cible | Où | Notes |
|---|---|---|---|---|---|---|
| bpi/cia/back-comptes | Java4Shell (CVE-2026-114938) | Java runtime | 21.0.5 | 21.0.13.1 | Dockerfile:6 | contournement repéré dans : k8s/deployment.yaml |
| bpi/cia/front-espace-client | NGINX2Root (5 CVE) | nginx | 1.27.3 | 1.30.7 | Dockerfile:8 | HTTP/2 activé : nginx/default.conf:2 |

## À VÉRIFIER — en exécution

| Projet | Faille | Composant | Version | Cible | Où | Notes |
|---|---|---|---|---|---|---|
| bpi/cia/back-comptes | Java4Shell (CVE-2026-114938) | Java runtime | — | — | values.yaml:2 | produit embarquant une JVM (keycloak) : vérifier l’avis de l’éditeur; contournement repéré dans : k8s/deployment.yaml |
| bpi/cia/back-comptes | NGINX2Root (5 CVE) | nginx | — | — | values.yaml:5 | nginx embarqué dans un produit : sa version ne se lit pas dans le tag, voir l’avis de l’éditeur |

## OK — en exécution

| Projet | Faille | Composant | Version | Cible | Où | Notes |
|---|---|---|---|---|---|---|
| bpi/cia/back-comptes | NGINX2Root (5 CVE) | nginx | 1.31.9 | — | k8s/deployment.yaml:15 | — |
| bpi/fbi/batch-releves | Java4Shell (CVE-2026-114938) | Java runtime | 21.0.13.1 | — | Dockerfile:4 | — |
| bpi/fbi/batch-releves | NGINX2Root (5 CVE) | nginx | 1.30.7 | — | Dockerfile.front:1 | — |

## Build et CI (pour information)

| Projet | Faille | Composant | Version | Cible | Où | Notes |
|---|---|---|---|---|---|---|
| bpi/cia/back-comptes | Java4Shell (CVE-2026-114938) | Java runtime | 21 | 21.0.13.1 | .gitlab-ci.yml:3 | seule la version majeure (21) se lit dans le nom de l’image; image de job CI : outil de build, pas un service exposé; version imprécise (21) : vulnérable ou non selon le correctif, relever la version exacte (probe) |
| bpi/cia/back-comptes | Java4Shell (CVE-2026-114938) | Java runtime | 21 | 21.0.13.1 | Dockerfile:1 | seule la version majeure (21) se lit dans le nom de l’image; étape de build multi-stage, absente de l’image finale; version imprécise (21) : vulnérable ou non selon le correctif, relever la version exacte (probe) |

## Projets sans composant suivi détecté (1)

bpi/fbi/lib-commune

## Que faire

- **Java4Shell (CVE-2026-114938)** — Passer au runtime Java de novembre 2026 (Oracle 17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1 ou l’équivalent de la distribution), reconstruire l’image, redémarrer les JVM. En attendant : -XX:+UnlockDiagnosticVMOptions -XX:-UseBASE64Intrinsics, à valider avec SEC et à tester au démarrage. Exploitation possible seulement sur x86-64 avec AVX-512 VBMI.
  Sources : https://www.group-ib.com/blog/java4shell-vulnerability/ ; https://www.securityweek.com/java4shell-vulnerability-puts-many-enterprise-applications-at-risk-of-takeover ; alerte CERT-FR du 18/11/2026 (vérifié le 2026-11-23)
- **NGINX2Root (5 CVE)** — Passer à nginx 1.30.7 (stable) ou 1.31.9 (mainline), reconstruire et redéployer l’image. En attendant : Désactiver HTTP/2 ne couvre que CVE-2026-123007 et CVE-2026-123633 ; HTTP/3, resolver et mail proxy restent exposés.
  Sources : https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-nginx-could-allow-for-remote-code-execution_2026-136 ; https://blog.qualys.com/misc/2026/11/18/nginx2root-five-nginx-flaws-led-by-cve-2026-123007-how-to-find-mitigate-and-patch-now (vérifié le 2026-11-23)

> Un asset n’est éradiqué qu’avec une preuve : version relevée sur l’image déployée ou job vuln-watch vert, puis confirmation du Command Center le lendemain.
