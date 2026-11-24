#!/usr/bin/env python3
"""
vuln-watch — vérifie si un projet, ou tout un groupe GitLab, est touché par les vulnérabilités
d'une watchlist (Java4Shell, NGINX2Root…) et produit la preuve, projet par projet.

    python3 vuln_watch.py rules                                   # règles de la watchlist
    python3 vuln_watch.py scan  [CHEMIN] [--probe F] [--sbom F]   # un dépôt (job CI ou poste)
    python3 vuln_watch.py group --gitlab-url URL --group GROUPE   # tout un groupe, à la demande

Python 3.11 ou plus, bibliothèque standard uniquement. Lecture seule : rien n'est exécuté
ni modifié dans les dépôts analysés.
"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import datetime as dt
import fnmatch
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Iterable, Iterator

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    sys.exit("vuln-watch nécessite Python 3.11 ou plus récent (module tomllib).")

__version__ = "0.1.0"

VULNERABLE, UNKNOWN, OK = "VULNERABLE", "UNKNOWN", "OK"
VERDICT_FR = {VULNERABLE: "VULNÉRABLE", UNKNOWN: "À VÉRIFIER", OK: "OK"}
COMPONENT_FR = {"java": "Java runtime", "nginx": "nginx"}
FAIL_ON = ("vulnerable", "unknown", "never")
SKIP_DIRS = {".git", "node_modules", "target", "build", "dist", ".venv", "venv", "vendor", ".gradle",
             ".idea", ".angular", "coverage", "__pycache__", "fixtures", "testdata", "__fixtures__"}
MAX_FILE_BYTES = 2_000_000
INF = (10**9,)


class ConfigError(Exception):
    """Erreur de configuration : watchlist, arguments, fichiers d'entrée."""


class GitLabError(Exception):
    """Erreur d'accès à l'API GitLab."""


# ----------------------------------------------------------------------------- versions
_NUM = re.compile(r"\d+(?:\.\d+)*")


def parse_version(text: str | None, component: str = "") -> tuple[int, ...] | None:
    """'21.0.5+11' -> (21, 0, 5) ; '1.8.0_392' (java) -> (8, 0) ; 'stable' -> None."""
    if not text:
        return None
    s = re.sub(r"^\d+:", "", text.strip()).lstrip("vV")  # retire l'époque rpm/deb « 1:17.0.13 »
    m = _NUM.match(s)
    if not m:
        return None
    parts = tuple(int(p) for p in m.group(0).split(".")[:4])
    if component == "java" and len(parts) >= 2 and parts[0] == 1 and parts[1] <= 8:
        parts = parts[1:]  # ancienne numérotation Java : 1.8.0_392 -> 8.0
    return parts


def vkey(t: tuple[int, ...] | None) -> tuple[int, ...]:
    """Clé de comparaison : 21.0.0 == 21 ; None = +infini."""
    if t is None:
        return INF
    out = list(t)
    while len(out) > 1 and out[-1] == 0:
        out.pop()
    return tuple(out)


@dataclasses.dataclass
class VRange:
    lo: tuple[int, ...]
    hi: tuple[int, ...] | None
    note: str = ""
    text: str = ""

    def contains(self, v: tuple[int, ...]) -> bool:
        return vkey(self.lo) <= v < vkey(self.hi)


def _required_version(text: str, expr: str) -> tuple[int, ...]:
    v = parse_version(text)
    if v is None:
        raise ConfigError(f"version illisible dans la plage « {expr} »")
    return v


def parse_range(expr: str, note: str = "") -> VRange:
    """Plage « >=A <B » (A inclus, B exclu) ; « <B » seul ou « >=A » seul acceptés."""
    lo, hi = (0,), None
    norm = re.sub(r"(>=|<)\s+", r"\1", expr.replace(",", " "))
    for tok in norm.split():
        if tok.startswith(">="):
            lo = _required_version(tok[2:], expr)
        elif tok.startswith("<") and not tok.startswith("<="):
            hi = _required_version(tok[1:], expr)
        else:
            raise ConfigError(f"plage invalide « {expr} » : utiliser >=A et/ou <B")
    return VRange(lo, hi, note, expr)


def _merge(ranges: list[VRange]) -> list[tuple[tuple[int, ...], tuple[int, ...]]]:
    spans = sorted((vkey(r.lo), vkey(r.hi)) for r in ranges)
    merged: list[list[tuple[int, ...]]] = []
    for a, b in spans:
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return [(a, b) for a, b in merged]


def evaluate(version: str | None, rule: "Rule", component: str) -> tuple[str, list[str]]:
    """Verdict d'une version face aux plages vulnérables d'une règle.

    Version précise (au moins 3 nombres) : VULNERABLE ou OK.
    Version partielle (« 21 », « 1.27 ») : toutes les versions X.Y.* sont comparées ;
    VULNERABLE si toutes sont vulnérables, OK si aucune, sinon UNKNOWN.
    """
    t = parse_version(version, component)
    if t is None:
        return UNKNOWN, ["version non déterminée"]
    if len(t) >= 3:
        v = vkey(t)
        hit = next((r for r in rule.ranges if r.contains(v)), None)
        if hit:
            return VULNERABLE, [hit.note] if hit.note else []
        return OK, []
    lo, hi = vkey(t), vkey(t[:-1] + (t[-1] + 1,))
    shown = ".".join(map(str, t))
    overlap = [r for r in rule.ranges if lo < vkey(r.hi) and vkey(r.lo) < hi]
    if not overlap:
        return OK, [f"toutes les versions {shown}.x sont hors plage vulnérable"]
    if any(a <= lo and hi <= b for a, b in _merge(rule.ranges)):
        return VULNERABLE, [f"toutes les versions {shown}.x sont vulnérables"] + sorted({r.note for r in overlap if r.note})
    return UNKNOWN, [f"version imprécise ({shown}) : vulnérable ou non selon le correctif, relever la version exacte (probe)"]


# ----------------------------------------------------------------------------- watchlist
@dataclasses.dataclass
class Rule:
    id: str
    label: str
    component: str
    ranges: list[VRange]
    alias: str = ""
    cves: list[str] = dataclasses.field(default_factory=list)
    targets: dict[str, str] = dataclasses.field(default_factory=dict)
    fix: str = ""
    mitigation: str = ""
    mitigation_markers: list[str] = dataclasses.field(default_factory=list)
    severity: str = ""
    sources: list[str] = dataclasses.field(default_factory=list)
    checked_on: str = ""

    def matches(self, query: str) -> bool:
        q = query.strip().lower()
        return q in {self.id.lower(), self.alias.lower(), self.label.lower(), *(c.lower() for c in self.cves)}

    def target_for(self, version: str | None) -> str:
        if not version:
            return ""
        t = parse_version(version, self.component)
        if t:
            for key in (".".join(map(str, t[:2])), str(t[0])):
                if key in self.targets:
                    return self.targets[key]
        return self.targets.get("*", "")


def load_watchlist(path: str | Path) -> list[Rule]:
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"watchlist introuvable : {p}")
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as err:
        raise ConfigError(f"watchlist illisible ({p}) : {err}") from None
    rules: list[Rule] = []
    for raw in data.get("rule", []):
        missing = [k for k in ("id", "label", "component", "vulnerable") if k not in raw]
        if missing:
            raise ConfigError(f"règle incomplète dans {p} : {', '.join(missing)} manquant(s)")
        ranges = [parse_range(item) if isinstance(item, str) else parse_range(item["range"], item.get("note", ""))
                  for item in raw["vulnerable"]]
        rules.append(Rule(
            id=str(raw["id"]), label=str(raw["label"]), component=str(raw["component"]), ranges=ranges,
            alias=str(raw.get("alias", "")), cves=[str(c) for c in raw.get("cves", [])],
            targets={str(k): str(v) for k, v in raw.get("targets", {}).items()}, fix=str(raw.get("fix", "")),
            mitigation=str(raw.get("mitigation", "")), mitigation_markers=list(raw.get("mitigation_markers", [])),
            severity=str(raw.get("severity", "")), sources=[str(s) for s in raw.get("sources", [])],
            checked_on=str(raw.get("checked_on", ""))))
    if not rules:
        raise ConfigError(f"aucune règle dans {p}")
    if len({r.id for r in rules}) != len(rules):
        raise ConfigError(f"identifiants de règles en double dans {p}")
    return rules


def select_rules(rules: list[Rule], queries: Iterable[str]) -> list[Rule]:
    queries = [q for q in queries if q.strip()]
    if not queries:
        return rules
    chosen: list[Rule] = []
    unknown = []
    for q in queries:
        hits = [r for r in rules if r.matches(q)]
        if not hits:
            unknown.append(q)
        chosen += [h for h in hits if all(h is not c for c in chosen)]
    if unknown:
        raise ConfigError("absent de la watchlist : " + ", ".join(unknown)
                          + " — ajouter une règle (README, section « Ajouter une CVE »)")
    return chosen


# ----------------------------------------------------------------------------- détection
@dataclasses.dataclass
class Observation:
    component: str               # « java », « nginx », « npm:nom », « maven:groupe:artefact »
    version: str | None
    source: str                  # dockerfile | manifest | ci | probe | sbom | npm-lock
    location: str
    image: str | None = None
    context: str = "runtime"     # runtime | build | ci
    notes: list[str] = dataclasses.field(default_factory=list)
    distro_package: bool = False


def split_image(ref: str) -> tuple[str, str]:
    ref = ref.strip().split("@", 1)[0]
    slash, colon = ref.rfind("/"), ref.rfind(":")
    if colon > slash:
        return ref[:colon], ref[colon + 1:]
    return ref, "latest"


NGINX_IMAGES = {"nginx", "nginx-unprivileged"}
NGINX_EMBEDDED = ("ingress-nginx", "nginx-ingress", "openresty", "kong")
JAVA_IMAGES = {"eclipse-temurin", "temurin", "openjdk", "amazoncorretto", "sapmachine", "ibm-semeru-runtimes",
               "zulu-openjdk", "zulu-openjdk-alpine", "zulu-openjdk-debian", "liberica-openjdk-alpine",
               "liberica-openjdk-debian", "liberica-runtime-container", "adoptopenjdk", "java", "jdk", "jre"}
JAVA_PRODUCTS = ("keycloak", "jenkins", "jira", "confluence", "artifactory", "kafka", "elasticsearch", "solr",
                 "tomcat", "wildfly", "jboss", "pingfederate", "gerrit", "spinnaker")
JAVA_HINT = re.compile(r"(?:openjdk|temurin|corretto|zulu|semeru|liberica|jdk|jre|java)[-_]?(\d{1,2}(?:\.\d+){0,3})(?!\d)", re.I)
TAG_VERSION = re.compile(r"(?:jdk-|jre-)?v?(\d+(?:\.\d+){0,3})")


def _floating(tag: str) -> str:
    if "$" in tag:
        return f"variable non résolue dans le tag « {tag} » : relever la version avec le probe"
    return f"tag flottant « {tag} » : version exacte inconnue, relever la version avec le probe"


def classify_image(ref: str) -> list[tuple[str, str | None, list[str]]]:
    """Composants suivis qu'une référence d'image laisse deviner : (composant, version, notes)."""
    name, tag = split_image(ref)
    low = name.lower()
    last = low.rsplit("/", 1)[-1]
    found: list[tuple[str, str | None, list[str]]] = []
    if last in NGINX_IMAGES:
        m = TAG_VERSION.match(tag)
        found.append(("nginx", m.group(1) if m else None, [] if m else [_floating(tag)]))
    elif any(k in low for k in NGINX_EMBEDDED):
        found.append(("nginx", None, ["nginx embarqué dans un produit : sa version ne se lit pas dans le tag, voir l’avis de l’éditeur"]))
    elif "nginx" in last:
        found.append(("nginx", None, ["image dérivée contenant probablement nginx : relever la version avec le probe"]))
    if last in JAVA_IMAGES:
        m = TAG_VERSION.match(tag)
        found.append(("java", m.group(1) if m else None, [] if m else [_floating(tag)]))
    else:
        product = next((p for p in JAVA_PRODUCTS if p in last), None)
        hint = JAVA_HINT.search(f"{low}:{tag.lower()}")
        if product or hint:
            notes = []
            if product:
                notes.append(f"produit embarquant une JVM ({product}) : vérifier l’avis de l’éditeur")
            version = hint.group(1) if hint else None
            if version and len(version.split(".")) < 3:
                notes.append(f"seule la version majeure ({version}) se lit dans le nom de l’image")
            found.append(("java", version, notes))
    return found


def _logical_lines(text: str) -> list[tuple[int, str]]:
    out, buf, start = [], "", 0
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not buf:
            start = i
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        out.append((start, buf + line))
        buf = ""
    if buf:
        out.append((start, buf))
    return out


_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def _substitute(value: str, args: dict[str, str]) -> str:
    def rep(m: re.Match) -> str:
        name = m.group(1) or m.group(3)
        if args.get(name):
            return args[name]
        if m.group(2) is not None:
            return m.group(2)
        return m.group(0)
    return _VAR.sub(rep, value)


def dockerfile_stages(text: str) -> list[dict]:
    """Étapes FROM d'un Dockerfile, ARG résolus ; « final » = image livrée."""
    args: dict[str, str] = {}
    stages: list[dict] = []
    for lineno, line in _logical_lines(text):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"(?i)ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*=\s*(.*))?$", s)
        if m:
            if m.group(2) is not None:
                args[m.group(1)] = m.group(2).strip().strip("\"'")
            continue
        m = re.match(r"(?i)FROM\s+(.+)$", s)
        if not m:
            continue
        toks = [t for t in m.group(1).split() if not t.startswith("--")]
        if not toks:
            continue
        alias = toks[2] if len(toks) >= 3 and toks[1].lower() == "as" else None
        stages.append({"line": lineno, "image": _substitute(toks[0], args), "alias": alias, "from_stage": None})
    aliases: dict[str, str] = {}
    for st in stages:
        key = st["image"].lower()
        if key in aliases:
            st["from_stage"] = key
            st["image"] = aliases[key]
        if st["alias"]:
            aliases[st["alias"].lower()] = st["image"]
    for i, st in enumerate(stages):
        st["final"] = i == len(stages) - 1
    ancestors: set[str] = set()
    cur = stages[-1] if stages else None
    while cur and cur["from_stage"] and cur["from_stage"] not in ancestors:
        ancestors.add(cur["from_stage"])
        cur = next((s for s in stages if (s["alias"] or "").lower() == cur["from_stage"]), None)
    return [st for st in stages
            if st["image"].lower() != "scratch" and (st["final"] or (st["alias"] or "").lower() not in ancestors)]


_IMAGE_LINE = re.compile(r"""^\s*-?\s*image:\s*["']?([^\s"'#]+)""")
_IMAGE_KEY = re.compile(r"""^\s*-?\s*image:\s*(#.*)?$""")
_NAME_LINE = re.compile(r"""^\s*name:\s*["']?([^\s"'#]+)""")
_REPO_LINE = re.compile(r"""^\s*repository:\s*["']?([^\s"'#]+)""")
_TAG_LINE = re.compile(r"""^\s*tag:\s*["']?([^\s"'#]+)""")


def manifest_images(text: str) -> list[tuple[int, str]]:
    """Références d'images d'un YAML (Kubernetes, Helm, Compose, GitLab CI)."""
    out: list[tuple[int, str]] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if "{{" in line:
            continue
        m = _IMAGE_LINE.match(line)
        if m:
            out.append((i + 1, m.group(1)))
            continue
        if _IMAGE_KEY.match(line):
            if i + 1 < len(lines) and "{{" not in lines[i + 1]:
                n = _NAME_LINE.match(lines[i + 1])
                if n:
                    out.append((i + 2, n.group(1)))
            continue
        m = _REPO_LINE.match(line)
        if m:
            tag = None
            for nxt in lines[i + 1:i + 5]:
                t = _TAG_LINE.match(nxt)
                if t and "{{" not in nxt:
                    tag = t.group(1)
                    break
            out.append((i + 1, f"{m.group(1)}:{tag}" if tag else m.group(1)))
    return out


def nginx_http2_lines(path: str, text: str) -> list[str]:
    hits = []
    for i, line in enumerate(text.splitlines(), 1):
        code = line.split("#", 1)[0]
        if re.search(r"\blisten\b[^;]*\bhttp2\b", code) or re.match(r"\s*http2\s+on\s*;", code):
            hits.append(f"{path}:{i}")
    return hits


def npm_lock_packages(text: str) -> set[tuple[str, str]]:
    data = json.loads(text)
    found: set[tuple[str, str]] = set()
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, meta in packages.items():
            if not path or "node_modules/" not in path or not isinstance(meta, dict):
                continue
            name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
            if meta.get("version"):
                found.add((name, str(meta["version"])))
    stack = [data.get("dependencies") or {}]
    while stack:
        deps = stack.pop()
        for name, meta in deps.items():
            if isinstance(meta, dict):
                if meta.get("version"):
                    found.add((name, str(meta["version"])))
                stack.append(meta.get("dependencies") or {})
    return found


JAVA_PKG = re.compile(r"^(java|jdk|jre|openjdk\d*(-jre|-jdk)?(-headless)?(-base)?|java-\d+-openjdk[\w.-]*"
                      r"|openjdk-\d+-(jre|jdk)(-headless)?|temurin-\d+-(jre|jdk))$", re.I)
NGINX_PKG = re.compile(r"^nginx(-core|-full|-light|-extras|-mainline)?$", re.I)


def _purl_component(purl: str) -> str | None:
    m = re.match(r"pkg:(npm|maven)/([^@?#]+)", purl)
    if not m:
        return None
    path = urllib.parse.unquote(m.group(2))
    if m.group(1) == "npm":
        return "npm:" + path
    parts = path.split("/")
    return f"maven:{parts[0]}:{parts[1]}" if len(parts) >= 2 else None


def sbom_observations(location: str, text: str, wanted: set[str]) -> list[Observation]:
    """Composants suivis d'une SBOM CycloneDX JSON (Syft, Trivy, plugins Maven et npm)."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict) or data.get("bomFormat") != "CycloneDX":
        return []
    image = ((data.get("metadata") or {}).get("component") or {}).get("name")
    out: list[Observation] = []
    stack = list(data.get("components") or [])
    while stack:
        comp = stack.pop()
        stack.extend(comp.get("components") or [])
        name, version, purl = comp.get("name", ""), comp.get("version"), comp.get("purl") or ""
        if JAVA_PKG.match(name):
            kind = "java"
        elif NGINX_PKG.match(name):
            kind = "nginx"
        else:
            kind = _purl_component(purl)
            if kind not in wanted:
                continue
        distro = purl.startswith(("pkg:apk/", "pkg:deb/", "pkg:rpm/"))
        out.append(Observation(kind, version, "sbom", f"{location} · {name}", image, "runtime", [], distro))
    return out


_PROBE_SPLIT = re.compile(r"^#\s*image:\s*(\S+)\s*$", re.M)
_JAVA_OUT = re.compile(r'(?:openjdk|java) version "([^"]+)"', re.I)
_JAVA_RELEASE = re.compile(r'^JAVA_VERSION="([^"]+)"', re.M)
_IMPLEMENTOR = re.compile(r'^IMPLEMENTOR="([^"]+)"', re.M)
_NGINX_OUT = re.compile(r"nginx version: (?:nginx|openresty)/([\d.]+)", re.I)


def probe_observations(name: str, text: str) -> list[Observation]:
    """Versions réelles relevées dans l'image (sortie du job probe)."""
    parts = _PROBE_SPLIT.split(text)
    sections = [(None, parts[0])] if parts[0].strip() else []
    sections += [(parts[i], parts[i + 1] if i + 1 < len(parts) else "") for i in range(1, len(parts), 2)]
    out: list[Observation] = []
    for image, body in sections:
        m = _JAVA_OUT.search(body) or _JAVA_RELEASE.search(body)
        if m:
            impl = _IMPLEMENTOR.search(body)
            out.append(Observation("java", m.group(1), "probe", name, image, "runtime",
                                   [f"distribution : {impl.group(1)}"] if impl else []))
        n = _NGINX_OUT.search(body)
        if n:
            out.append(Observation("nginx", n.group(1), "probe", name, image, "runtime", []))
    return out


# ----------------------------------------------------------------------------- sources
def interesting(path: str) -> str | None:
    p = PurePosixPath(path)
    dirs = {d.lower() for d in p.parts[:-1]}
    if dirs & SKIP_DIRS:
        return None
    n = p.name.lower()
    if n == "dockerfile" or n.startswith(("dockerfile.", "containerfile")) or n.endswith(".dockerfile"):
        return "dockerfile"
    if n == "package-lock.json":
        return "npm-lock"
    if n.endswith(".cdx.json") or n in ("bom.json", "sbom.json") or (n.startswith("sbom") and n.endswith(".json")):
        return "sbom"
    if n.endswith((".yml", ".yaml")):
        return "ci" if (n.endswith(".gitlab-ci.yml") or ".gitlab" in dirs) else "manifest"
    if n.endswith((".conf", ".conf.template")):
        return "nginx-conf"
    return None


class LocalSource:
    def __init__(self, root: Path):
        self.root = root

    def files(self) -> Iterator[str]:
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d.lower() not in SKIP_DIRS)
            for fname in sorted(filenames):
                rel = (Path(dirpath) / fname).relative_to(self.root).as_posix()
                if interesting(rel):
                    yield rel

    def read(self, rel: str) -> str | None:
        p = self.root / rel
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                return None
            return p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None


class GitLabAPI:
    """Client minimal de l'API GitLab v4, en lecture seule (jeton read_api)."""

    def __init__(self, base_url: str, token: str, ca_file: str | None = None, timeout: int = 30):
        if not base_url.startswith(("https://", "http://")):
            raise ConfigError("--gitlab-url doit commencer par https://")
        self.base = base_url.rstrip("/") + "/api/v4"
        self.token = token
        self.timeout = timeout
        self.ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()

    def _get(self, path: str, params: dict | None = None):
        url = self.base + path + ("?" + urllib.parse.urlencode(params) if params else "")
        for attempt in range(4):
            req = urllib.request.Request(url, headers={"PRIVATE-TOKEN": self.token,
                                                       "User-Agent": f"vuln-watch/{__version__}"})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                    return resp.read(), resp.headers
            except urllib.error.HTTPError as err:
                if err.code == 404:
                    return None, err.headers
                if (err.code == 429 or err.code >= 500) and attempt < 3:
                    retry_after = (err.headers.get("Retry-After") if err.headers else None) or ""
                    time.sleep(min(int(retry_after), 60) if retry_after.isdigit() else 2 ** attempt)
                    continue
                if err.code in (401, 403):
                    raise GitLabError(f"accès refusé ({err.code}) sur {path} : vérifier le jeton (portée read_api) "
                                      "et ses droits sur le groupe") from None
                raise GitLabError(f"erreur HTTP {err.code} sur {path}") from None
            except urllib.error.URLError as err:
                if attempt < 3:
                    time.sleep(2 ** attempt)
                    continue
                raise GitLabError(f"GitLab injoignable : {err.reason}") from None
        raise GitLabError(f"échecs répétés sur {path}")

    def paginate(self, path: str, params: dict, max_pages: int = 1000) -> Iterator[dict]:
        page = 1
        while page and page <= max_pages:
            body, headers = self._get(path, {**params, "page": page})
            if body is None:
                return
            items = json.loads(body)
            if not isinstance(items, list):
                return
            yield from items
            nxt = ((headers.get("X-Next-Page") if headers else "") or "").strip()
            page = int(nxt) if nxt.isdigit() else 0

    def raw_file(self, project_id: int, file_path: str, ref: str) -> bytes | None:
        enc = urllib.parse.quote(file_path, safe="")
        body, _ = self._get(f"/projects/{project_id}/repository/files/{enc}/raw", {"ref": ref})
        return body


class GitLabSource:
    def __init__(self, api: GitLabAPI, project: dict, max_tree_pages: int = 50):
        self.api, self.project = api, project
        self.ref = project.get("default_branch") or "main"
        self.max_tree_pages = max_tree_pages

    def files(self) -> Iterator[str]:
        tree = self.api.paginate(f"/projects/{self.project['id']}/repository/tree",
                                 {"recursive": "true", "per_page": 100, "ref": self.ref}, self.max_tree_pages)
        for item in tree:
            if item.get("type") == "blob" and interesting(item.get("path", "")):
                yield item["path"]

    def read(self, rel: str) -> str | None:
        body = self.api.raw_file(self.project["id"], rel, self.ref)
        if body is None or len(body) > MAX_FILE_BYTES:
            return None
        return body.decode("utf-8", errors="replace")


# ----------------------------------------------------------------------------- analyse
@dataclasses.dataclass
class Finding:
    project: str
    rule: Rule
    obs: Observation
    verdict: str
    notes: list[str]

    def as_dict(self) -> dict:
        return {"project": self.project, "rule": self.rule.id, "label": self.rule.label, "cves": self.rule.cves,
                "component": self.obs.component, "version": self.obs.version, "verdict": self.verdict,
                "verdict_fr": VERDICT_FR[self.verdict], "context": self.obs.context, "source": self.obs.source,
                "location": self.obs.location, "image": self.obs.image,
                "target": self.rule.target_for(self.obs.version) if self.verdict != OK else "",
                "notes": self.notes}


def scan_source(source, rules: list[Rule], project: str, probes: Iterable[Path] = (),
                sboms: Iterable[Path] = ()) -> tuple[list[Finding], dict]:
    wanted = {r.component for r in rules if ":" in r.component}
    observations: list[Observation] = []
    texts: dict[str, str] = {}
    http2: list[str] = []
    for rel in source.files():
        kind = interesting(rel)
        text = source.read(rel)
        if text is None:
            continue
        texts[rel] = text
        if kind == "dockerfile":
            for st in dockerfile_stages(text):
                for comp, version, notes in classify_image(st["image"]):
                    obs = Observation(comp, version, "dockerfile", f"{rel}:{st['line']}", st["image"],
                                      "runtime" if st["final"] else "build", list(notes))
                    if not st["final"]:
                        obs.notes.append("étape de build multi-stage, absente de l’image finale")
                    observations.append(obs)
        elif kind in ("manifest", "ci"):
            for line, ref in manifest_images(text):
                for comp, version, notes in classify_image(ref):
                    obs = Observation(comp, version, kind, f"{rel}:{line}", ref,
                                      "runtime" if kind == "manifest" else "ci", list(notes))
                    if kind == "ci":
                        obs.notes.append("image de job CI : outil de build, pas un service exposé")
                    observations.append(obs)
        elif kind == "npm-lock" and wanted:
            try:
                packages = npm_lock_packages(text)
            except (json.JSONDecodeError, AttributeError):
                continue
            observations += [Observation(f"npm:{n}", v, "npm-lock", rel) for n, v in sorted(packages) if f"npm:{n}" in wanted]
        elif kind == "sbom":
            observations += sbom_observations(rel, text, wanted)
        elif kind == "nginx-conf":
            http2 += nginx_http2_lines(rel, text)
    for path in probes:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        texts[Path(path).name] = text
        observations += probe_observations(Path(path).name, text)
    for path in sboms:
        observations += sbom_observations(Path(path).name, Path(path).read_text(encoding="utf-8", errors="replace"), wanted)

    findings: list[Finding] = []
    seen: set[tuple] = set()
    for obs in observations:
        for rule in rules:
            key = (rule.id, obs.component, obs.version, obs.location, obs.context)
            if rule.component != obs.component or key in seen:
                continue
            seen.add(key)
            if obs.version:
                verdict, extra = evaluate(obs.version, rule, obs.component)
            else:
                verdict, extra = UNKNOWN, ([] if obs.notes else ["version non déterminée"])
            notes = list(obs.notes) + extra
            if obs.distro_package and verdict == VULNERABLE:
                verdict = UNKNOWN
                notes.append("paquet de distribution : correctif peut-être rétroporté sans changer la version amont, "
                             "vérifier l’avis de la distribution")
            findings.append(Finding(project, rule, obs, verdict, notes))
    for rule in rules:
        mitigations = sorted(n for n, t in texts.items() if any(m in t for m in rule.mitigation_markers))
        for f in findings:
            if f.rule is not rule or f.verdict == OK or f.obs.context != "runtime":
                continue
            if mitigations:
                f.notes.append("contournement repéré dans : " + ", ".join(mitigations[:3]))
            if rule.component == "nginx" and http2:
                f.notes.append("HTTP/2 activé : " + ", ".join(http2[:3]))
    stats = {"project": project, "files_analysed": len(texts), "observations": len(observations), "findings": len(findings)}
    return findings, stats


def scan_group(api: GitLabAPI, group: str, rules: list[Rule], only: str | None, max_projects: int,
               quiet: bool) -> tuple[list[Finding], list[dict]]:
    projects = [p for p in api.paginate(f"/groups/{urllib.parse.quote(group, safe='')}/projects",
                                        {"include_subgroups": "true", "archived": "false", "simple": "true",
                                         "per_page": 100, "order_by": "path", "sort": "asc"})
                if p.get("default_branch")]
    if only:
        projects = [p for p in projects if fnmatch.fnmatch(p.get("path_with_namespace", ""), only)]
    if not projects:
        raise GitLabError(f"groupe « {group} » introuvable ou sans projet accessible avec ce jeton")
    projects = projects[:max_projects]
    findings: list[Finding] = []
    stats: list[dict] = []
    for i, p in enumerate(projects, 1):
        name = p.get("path_with_namespace") or str(p.get("id"))
        if not quiet:
            print(f"[{i}/{len(projects)}] {name}", file=sys.stderr)
        try:
            found, st = scan_source(GitLabSource(api, p), rules, name)
        except GitLabError as err:
            found, st = [], {"project": name, "error": str(err), "files_analysed": 0, "observations": 0, "findings": 0}
        findings += found
        stats.append(st)
    return findings, stats


def should_fail(findings: list[Finding], fail_on: str) -> bool:
    runtime = [f for f in findings if f.obs.context == "runtime"]
    if fail_on == "vulnerable":
        return any(f.verdict == VULNERABLE for f in runtime)
    if fail_on == "unknown":
        return any(f.verdict in (VULNERABLE, UNKNOWN) for f in runtime)
    return False


# ----------------------------------------------------------------------------- rapports
CSV_HEADERS = ["Vulnérabilité", "Tribu", "Squad", "Application", "Asset (dépôt, image, serveur, produit)",
               "Type d’asset", "Environnement", "Exposition", "Composant", "Version détectée", "Version cible",
               "Statut", "Lot", "Date cible", "Responsable", "Source de détection",
               "Preuve (lien pipeline, scan, capture)", "Date de vérification", "Commentaire"]


def _sort_key(f: Finding) -> tuple:
    return (f.project, f.rule.id, f.obs.location)


def _where(f: Finding) -> str:
    if f.obs.image and f.obs.source in ("probe", "sbom"):
        return f"{f.obs.image} (relevé : {f.obs.location})"
    return f.obs.location


def _cell(value) -> str:
    return str(value if value not in (None, "") else "—").replace("|", "\\|").replace("\n", " ")


def render_markdown(findings: list[Finding], stats: list[dict], rules: list[Rule], meta: dict) -> str:
    when = dt.datetime.fromisoformat(meta["generated_at"]).strftime("%d/%m/%Y %H:%M")
    run = [f for f in findings if f.obs.context == "runtime"]
    other = [f for f in findings if f.obs.context != "runtime"]
    out = [f"# vuln-watch — rapport du {when}", "",
           f"**Périmètre :** {meta['scope']} · **projets analysés :** {len(stats)} · **failles suivies :** "
           + ", ".join(r.label for r in rules)]
    if meta.get("ci_job_url"):
        out.append(f"**Job :** {meta['ci_job_url']}")
    out += ["", "| Verdict | En exécution | Build et CI |", "|---|---:|---:|"]
    for v in (VULNERABLE, UNKNOWN, OK):
        out.append(f"| {VERDICT_FR[v]} | {sum(f.verdict == v for f in run)} | {sum(f.verdict == v for f in other)} |")

    def table(title: str, items: list[Finding]) -> None:
        out.extend(["", f"## {title}", ""])
        if not items:
            out.append("_Aucun._")
            return
        out.append("| Projet | Faille | Composant | Version | Cible | Où | Notes |")
        out.append("|---|---|---|---|---|---|---|")
        for f in sorted(items, key=_sort_key):
            target = f.rule.target_for(f.obs.version) if f.verdict != OK else ""
            out.append("| " + " | ".join(_cell(c) for c in (
                f.project, f.rule.label, COMPONENT_FR.get(f.obs.component, f.obs.component), f.obs.version,
                target, _where(f), "; ".join(f.notes))) + " |")

    table("VULNÉRABLE — en exécution", [f for f in run if f.verdict == VULNERABLE])
    table("À VÉRIFIER — en exécution", [f for f in run if f.verdict == UNKNOWN])
    table("OK — en exécution", [f for f in run if f.verdict == OK])
    table("Build et CI (pour information)", other)
    empty = sorted(s["project"] for s in stats if s.get("observations") == 0 and not s.get("error"))
    if empty and len(stats) > 1:
        out += ["", f"## Projets sans composant suivi détecté ({len(empty)})", "",
                ", ".join(empty[:300]) + (" …" if len(empty) > 300 else "")]
    errors = [s for s in stats if s.get("error")]
    if errors:
        out += ["", f"## Projets en erreur ({len(errors)})", ""] + [f"- {s['project']} : {s['error']}" for s in errors]
    out += ["", "## Que faire", ""]
    for r in rules:
        out.append(f"- **{r.label}** — {r.fix}" + (f" En attendant : {r.mitigation}" if r.mitigation else ""))
        if r.sources:
            out.append(f"  Sources : {' ; '.join(r.sources)}" + (f" (vérifié le {r.checked_on})" if r.checked_on else ""))
    out += ["", "> Un asset n’est éradiqué qu’avec une preuve : version relevée sur l’image déployée ou job vuln-watch "
            "vert, puis confirmation du Command Center le lendemain.", ""]
    return "\n".join(out)


def write_csv(path: Path, findings: list[Finding]) -> None:
    """Lignes au format de l'onglet Recensement (colonnes B à T), séparateur point-virgule."""
    today = dt.date.today().strftime("%d/%m/%Y")
    job = os.environ.get("CI_JOB_URL", "")
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(CSV_HEADERS)
        for f in sorted((f for f in findings if f.obs.context == "runtime"), key=_sort_key):
            asset = f"{f.obs.image} ({f.obs.location})" if f.obs.image else f.obs.location
            kind = "Image conteneur" if (f.obs.image or f.obs.source in ("dockerfile", "manifest", "probe")) else "Dépôt GitLab"
            comment = f"vuln-watch {VERDICT_FR[f.verdict]}" + (" : " + "; ".join(f.notes) if f.notes else "")
            w.writerow([f.rule.label, "", "", f.project, asset, kind, "", "",
                        COMPONENT_FR.get(f.obs.component, f.obs.component), f.obs.version or "",
                        f.rule.target_for(f.obs.version) if f.verdict != OK else "",
                        "Non concerné" if f.verdict == OK else "À qualifier", "", "", "", "vuln-watch", job,
                        today if f.verdict == OK else "", comment])


def write_reports(findings: list[Finding], stats: list[dict], rules: list[Rule], out_dir: str, scope: str) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    meta = {"tool": "vuln-watch", "version": __version__,
            "generated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"), "scope": scope,
            "ci_job_url": os.environ.get("CI_JOB_URL"),
            "rules": [{"id": r.id, "label": r.label, "cves": r.cves, "checked_on": r.checked_on} for r in rules]}
    summary: dict[str, dict[str, int]] = {}
    for f in findings:
        ctx = "runtime" if f.obs.context == "runtime" else "build_ci"
        summary.setdefault(ctx, {VULNERABLE: 0, UNKNOWN: 0, OK: 0})[f.verdict] += 1
    paths = {"md": out / "vuln-watch-report.md", "json": out / "vuln-watch-report.json",
             "csv": out / "vuln-watch-recensement.csv"}
    paths["json"].write_text(json.dumps({**meta, "summary": summary, "projects": stats,
                                         "findings": [f.as_dict() for f in sorted(findings, key=_sort_key)]},
                                        ensure_ascii=False, indent=2), encoding="utf-8")
    paths["md"].write_text(render_markdown(findings, stats, rules, meta), encoding="utf-8")
    write_csv(paths["csv"], findings)
    return paths


def print_summary(findings: list[Finding], stats: list[dict], paths: dict[str, Path], quiet: bool) -> None:
    run = [f for f in findings if f.obs.context == "runtime"]
    n = {v: sum(f.verdict == v for f in run) for v in (VULNERABLE, UNKNOWN, OK)}
    print(f"vuln-watch {__version__} — {len(stats)} projet(s) analysé(s)")
    print(f"  En exécution : {n[VULNERABLE]} VULNÉRABLE · {n[UNKNOWN]} À VÉRIFIER · {n[OK]} OK")
    if not quiet:
        for f in sorted(run, key=_sort_key):
            if f.verdict != OK:
                print(f"  [{VERDICT_FR[f.verdict]}] {f.project} · {f.rule.alias or f.rule.id} · "
                      f"{COMPONENT_FR.get(f.obs.component, f.obs.component)} {f.obs.version or '?'} · {_where(f)}")
    print("  Rapports : " + ", ".join(str(p) for p in paths.values()))


def print_rules(rules: list[Rule]) -> None:
    for r in rules:
        print(f"{r.id} — {r.label}  [{r.component}]")
        if r.cves:
            print("  CVE : " + ", ".join(r.cves))
        print("  Plages vulnérables : " + " ; ".join(x.text for x in r.ranges))
        if r.targets:
            print("  Versions cibles : " + ", ".join(f"{k} → {v}" for k, v in r.targets.items()))
        if r.checked_on:
            print(f"  Plages vérifiées le : {r.checked_on}")


# ----------------------------------------------------------------------------- CLI
def _existing(paths: list[str], what: str) -> list[Path]:
    found = []
    for p in paths:
        if Path(p).is_file():
            found.append(Path(p))
        else:
            print(f"vuln-watch : {what} absent, ignoré : {p}", file=sys.stderr)
    return found


def build_parser() -> argparse.ArgumentParser:
    here = Path(__file__).resolve().parent
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--watchlist", default=os.environ.get("VULN_WATCH_WATCHLIST", str(here / "watchlist.toml")),
                        help="fichier TOML des règles (défaut : watchlist.toml à côté du script)")
    common.add_argument("--cve", action="append", default=[], metavar="ID",
                        help="limiter à une faille : CVE, identifiant ou nom de la règle (répétable)")
    common.add_argument("--out", default="vuln-watch-report", help="dossier des rapports (défaut : vuln-watch-report)")
    common.add_argument("--quiet", action="store_true", help="n'afficher que le résumé")
    parser = argparse.ArgumentParser(prog="vuln_watch.py", description="Vérifie si des projets sont touchés par les "
                                     "vulnérabilités d'une watchlist et en produit la preuve.")
    parser.add_argument("--version", action="version", version=f"vuln-watch {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("rules", parents=[common], help="afficher les règles de la watchlist")
    scan = sub.add_parser("scan", parents=[common], help="analyser un dépôt local")
    scan.add_argument("path", nargs="?", default=".", help="dossier du dépôt (défaut : .)")
    scan.add_argument("--probe", action="append", default=[], metavar="FICHIER",
                      help="sortie du job probe (java -version, nginx -v), répétable")
    scan.add_argument("--sbom", action="append", default=[], metavar="FICHIER", help="SBOM CycloneDX JSON, répétable")
    scan.add_argument("--project", default=os.environ.get("CI_PROJECT_PATH"), help="nom du projet dans les rapports")
    scan.add_argument("--fail-on", default=os.environ.get("VULN_WATCH_FAIL_ON", "vulnerable"),
                      help="code retour 1 si : vulnerable (défaut), unknown (vulnérable ou à vérifier), never")
    group = sub.add_parser("group", parents=[common], help="analyser tous les projets d'un groupe GitLab")
    group.add_argument("--gitlab-url", default=os.environ.get("CI_SERVER_URL"), help="URL GitLab (défaut : CI_SERVER_URL)")
    group.add_argument("--group", required=True, help="chemin du groupe, ex. lcl/bpi")
    group.add_argument("--token-env", default="GITLAB_TOKEN", help="variable d'environnement du jeton (défaut : GITLAB_TOKEN)")
    group.add_argument("--ca-file", default=None, help="certificat d'autorité interne (PEM)")
    group.add_argument("--only", default=None, metavar="MOTIF", help="filtre sur le chemin des projets, ex. 'lcl/bpi/cia/*'")
    group.add_argument("--max-projects", type=int, default=1000)
    group.add_argument("--fail-on", default="never", help="vulnerable, unknown ou never (défaut)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rules = select_rules(load_watchlist(args.watchlist), args.cve)
        if args.command == "rules":
            print_rules(rules)
            return 0
        if args.fail_on not in FAIL_ON:
            raise ConfigError(f"--fail-on doit valoir {', '.join(FAIL_ON)}")
        if args.command == "scan":
            root = Path(args.path)
            if not root.is_dir():
                raise ConfigError(f"dossier introuvable : {root}")
            project = args.project or root.resolve().name
            findings, st = scan_source(LocalSource(root), rules, project,
                                       _existing(args.probe, "probe"), _existing(args.sbom, "SBOM"))
            stats, scope = [st], project
        else:
            if not args.gitlab_url:
                raise ConfigError("--gitlab-url manquant (ou variable CI_SERVER_URL)")
            token = os.environ.get(args.token_env)
            if not token:
                raise ConfigError(f"jeton absent : définir la variable {args.token_env} (jeton en lecture seule, portée read_api)")
            api = GitLabAPI(args.gitlab_url, token, args.ca_file)
            findings, stats = scan_group(api, args.group, rules, args.only, args.max_projects, args.quiet)
            scope = f"groupe {args.group}" + (f" ({args.only})" if args.only else "")
        paths = write_reports(findings, stats, rules, args.out, scope)
        print_summary(findings, stats, paths, args.quiet)
        return 1 if should_fail(findings, args.fail_on) else 0
    except ConfigError as err:
        print(f"vuln-watch : {err}", file=sys.stderr)
        return 2
    except GitLabError as err:
        print(f"vuln-watch : {err}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
