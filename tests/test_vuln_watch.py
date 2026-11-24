"""Tests de vuln-watch : python3 -m unittest discover -s tests -v"""
import contextlib
import csv
import http.server
import io
import json
import os
import re
import sys
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import vuln_watch as vw  # noqa: E402

FIX = HERE / "fixtures"
WATCHLIST = ROOT / "watchlist.toml"
V, U, OK = vw.VULNERABLE, vw.UNKNOWN, vw.OK
NPM_RULE = """
[[rule]]
id = "DEMO-NPM"
label = "Demo (CVE-0000-0001)"
cves = ["CVE-0000-0001"]
component = "npm:demo-lib"
vulnerable = [ { range = ">=1.0.0 <1.4.2" } ]
targets = { "*" = "1.4.2" }
fix = "Mettre à jour demo-lib."
"""


def rules():
    return vw.load_watchlist(WATCHLIST)


def rule(rule_id):
    return next(r for r in rules() if r.id == rule_id)


class VersionTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(vw.parse_version("21.0.5+11"), (21, 0, 5))
        self.assertEqual(vw.parse_version("1.8.0_392", "java"), (8, 0))
        self.assertEqual(vw.parse_version("1:17.0.13.0.11-3.el9"), (17, 0, 13, 0))
        self.assertIsNone(vw.parse_version("stable"))

    def test_java4shell_ranges(self):
        r = rule("JAVA4SHELL")
        cases = {"21.0.5": V, "21.0.13": V, "21.0.13.1": OK, "21.0.13.1+4": OK, "17.0.5": OK, "17.0.6": V,
                 "17.0.21": V, "17.0.21.1": OK, "11.0.25": OK, "1.8.0_392": OK, "25.0.5": V, "25.0.5.1": OK,
                 "27.0.1": V, "27.0.1.1": OK, "21": U, "17": U, "11": OK, "8": OK, "19": V}
        for version, expected in cases.items():
            with self.subTest(version=version):
                self.assertEqual(vw.evaluate(version, r, "java")[0], expected)

    def test_nginx2root_ranges(self):
        r = rule("NGINX2ROOT")
        cases = {"1.27.3": V, "1.30.6": V, "1.30.7": OK, "1.31.0": V, "1.31.8": V, "1.31.9": OK, "1.32.0": OK,
                 "1.27": V, "1.30": U, "1.31": U, "1.25.3.1": V}
        for version, expected in cases.items():
            with self.subTest(version=version):
                self.assertEqual(vw.evaluate(version, r, "nginx")[0], expected)

    def test_targets(self):
        self.assertEqual(rule("JAVA4SHELL").target_for("21.0.5"), "21.0.13.1")
        self.assertEqual(rule("JAVA4SHELL").target_for("17.0.10"), "17.0.21.1")
        self.assertEqual(rule("NGINX2ROOT").target_for("1.31.4"), "1.31.9")
        self.assertEqual(rule("NGINX2ROOT").target_for("1.27.3"), "1.30.7")

    def test_bad_range(self):
        with self.assertRaises(vw.ConfigError):
            vw.parse_range("<=1.2.3")


class ParsingTests(unittest.TestCase):
    def test_dockerfile_multistage_and_args(self):
        stages = vw.dockerfile_stages((FIX / "front-angular" / "Dockerfile").read_text())
        self.assertEqual([s["image"] for s in stages], ["node:22.11-alpine", "nginx:1.27.3-alpine"])
        self.assertEqual([s["final"] for s in stages], [False, True])
        self.assertEqual(stages[1]["line"], 8)

    def test_dockerfile_alias_base(self):
        stages = vw.dockerfile_stages((FIX / "fixed-app" / "Dockerfile").read_text())
        self.assertEqual([(s["image"], s["final"]) for s in stages], [("eclipse-temurin:21.0.13.1_1-jre", True)])

    def test_classify_image(self):
        self.assertEqual(vw.classify_image("nginx:1.27.3-alpine"), [("nginx", "1.27.3", [])])
        self.assertEqual(vw.classify_image("eclipse-temurin:21.0.5_11-jre")[0][:2], ("java", "21.0.5"))
        self.assertEqual(vw.classify_image("maven:3.9.9-eclipse-temurin-21")[0][:2], ("java", "21"))
        self.assertEqual(vw.classify_image("gcr.io/distroless/java21-debian12")[0][:2], ("java", "21"))
        self.assertIsNone(vw.classify_image("nginx:stable-alpine")[0][1])
        self.assertEqual(vw.classify_image("node:22-alpine"), [])
        self.assertEqual(vw.classify_image("registry.example/bpi/back-java:2026.11.0"), [])
        self.assertEqual(vw.classify_image("quay.io/keycloak/keycloak:26.0")[0][:2], ("java", None))
        self.assertEqual(vw.classify_image("registry.k8s.io/ingress-nginx/controller:v1.12.1")[0][:2], ("nginx", None))

    def test_manifest_images(self):
        refs = [r for _, r in vw.manifest_images((FIX / "back-java" / "k8s" / "deployment.yaml").read_text())]
        self.assertEqual(refs, ["registry.example/bpi/back-java:2026.11.0", "nginxinc/nginx-unprivileged:1.31.9-alpine"])
        helm = [r for _, r in vw.manifest_images((FIX / "back-java" / "values.yaml").read_text())]
        self.assertEqual(helm, ["quay.io/keycloak/keycloak:26.0", "registry.k8s.io/ingress-nginx/controller:v1.12.1"])
        ci = [r for _, r in vw.manifest_images((FIX / "back-java" / ".gitlab-ci.yml").read_text())]
        self.assertEqual(ci, ["maven:3.9.9-eclipse-temurin-21"])

    def test_http2_detection(self):
        hits = vw.nginx_http2_lines("default.conf", (FIX / "front-angular" / "nginx" / "default.conf").read_text())
        self.assertEqual(hits, ["default.conf:2"])

    def test_probe(self):
        obs = vw.probe_observations("probe.txt", (FIX / "probe" / "probe.txt").read_text())
        self.assertEqual([(o.component, o.version, o.image) for o in obs],
                         [("java", "21.0.5", "registry.example/bpi/back-java:2026.11.0"),
                          ("nginx", "1.27.3", "registry.example/vps/front:2026.11.2")])
        self.assertIn("distribution : Eclipse Adoptium", obs[0].notes)

    def test_sbom(self):
        obs = vw.sbom_observations("image.cdx.json", (FIX / "sbom" / "image.cdx.json").read_text(), {"npm:demo-lib"})
        self.assertEqual(sorted((o.component, o.version, o.distro_package) for o in obs),
                         [("java", "17.0.13+11-2~deb12u1", True), ("java", "21.0.13.1+1", False),
                          ("nginx", "1.26.2-r0", True), ("npm:demo-lib", "1.4.2", False)])


class ScanTests(unittest.TestCase):
    def scan(self, name, **kw):
        return vw.scan_source(vw.LocalSource(FIX / name), rules(), name, **kw)

    def test_front_angular(self):
        findings, _ = self.scan("front-angular")
        runtime = [f for f in findings if f.obs.context == "runtime"]
        self.assertEqual([(f.rule.id, f.obs.version, f.verdict) for f in runtime], [("NGINX2ROOT", "1.27.3", V)])
        self.assertTrue(any(n.startswith("HTTP/2 activé") for n in runtime[0].notes))
        self.assertFalse(any("node_modules" in f.obs.location for f in findings))
        self.assertTrue(vw.should_fail(findings, "vulnerable"))

    def test_back_java(self):
        findings, _ = self.scan("back-java")
        got = sorted((f.obs.context, f.rule.id, f.obs.version or "", f.verdict) for f in findings)
        self.assertEqual(got, sorted([
            ("runtime", "JAVA4SHELL", "21.0.5", V),   # étape finale du Dockerfile
            ("build", "JAVA4SHELL", "21", U),        # étape de build maven
            ("runtime", "NGINX2ROOT", "1.31.9", OK),  # sidecar Kubernetes
            ("runtime", "JAVA4SHELL", "", U),         # Keycloak (valeurs Helm)
            ("runtime", "NGINX2ROOT", "", U),         # ingress-nginx
            ("ci", "JAVA4SHELL", "21", U),           # image du job CI
        ]))
        vulnerable = next(f for f in findings if f.verdict == V)
        self.assertTrue(any(n.startswith("contournement repéré") for n in vulnerable.notes))

    def test_fixed_app(self):
        findings, _ = self.scan("fixed-app")
        self.assertEqual(sorted((f.rule.id, f.obs.version, f.verdict) for f in findings),
                         [("JAVA4SHELL", "21.0.13.1", OK), ("NGINX2ROOT", "1.30.7", OK)])
        self.assertFalse(vw.should_fail(findings, "unknown"))

    def test_probe_and_sbom(self):
        findings, _ = self.scan("fixed-app", probes=[FIX / "probe" / "probe.txt"], sboms=[FIX / "sbom" / "image.cdx.json"])
        probe = sorted((f.rule.id, f.obs.version, f.verdict) for f in findings if f.obs.source == "probe")
        self.assertEqual(probe, [("JAVA4SHELL", "21.0.5", V), ("NGINX2ROOT", "1.27.3", V)])
        sbom = sorted((f.rule.id, f.obs.version, f.verdict) for f in findings if f.obs.source == "sbom")
        self.assertEqual(sbom, [("JAVA4SHELL", "17.0.13+11-2~deb12u1", U), ("JAVA4SHELL", "21.0.13.1+1", OK),
                                ("NGINX2ROOT", "1.26.2-r0", U)])

    def test_npm_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            wl = Path(tmp) / "watchlist.toml"
            wl.write_text(WATCHLIST.read_text(encoding="utf-8") + NPM_RULE, encoding="utf-8")
            selected = vw.select_rules(vw.load_watchlist(wl), ["CVE-0000-0001"])
            findings, _ = vw.scan_source(vw.LocalSource(FIX / "front-angular"), selected, "front")
            self.assertEqual(sorted((f.obs.version, f.verdict) for f in findings), [("1.2.0", V), ("1.4.2", OK)])

    def test_self_scan_ignores_fixtures(self):
        findings, _ = vw.scan_source(vw.LocalSource(ROOT), rules(), "vuln-watch")
        self.assertEqual(findings, [])

    def test_select_rules(self):
        with self.assertRaises(vw.ConfigError):
            vw.select_rules(rules(), ["CVE-1999-0001"])
        self.assertEqual([r.id for r in vw.select_rules(rules(), ["cve-2026-123007"])], ["NGINX2ROOT"])
        self.assertEqual([r.id for r in vw.select_rules(rules(), ["java4shell", "JAVA4SHELL"])], ["JAVA4SHELL"])


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = vw.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_scan_reports_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = run_cli("scan", str(FIX / "front-angular"), "--out", tmp, "--project", "bpi/front")
            self.assertEqual(code, 1)
            self.assertIn("1 VULNÉRABLE", out)
            with open(Path(tmp) / "vuln-watch-recensement.csv", encoding="utf-8-sig", newline="") as fh:
                rows = list(csv.reader(fh, delimiter=";"))
            self.assertEqual(len(rows[0]), 19)
            self.assertEqual((rows[1][0], rows[1][3], rows[1][10], rows[1][11]),
                             ("NGINX2Root (5 CVE)", "bpi/front", "1.30.7", "À qualifier"))
            data = json.loads((Path(tmp) / "vuln-watch-report.json").read_text(encoding="utf-8"))
            self.assertEqual(data["summary"]["runtime"]["VULNERABLE"], 1)
            self.assertIn("## VULNÉRABLE — en exécution", (Path(tmp) / "vuln-watch-report.md").read_text(encoding="utf-8"))
            code, _, _ = run_cli("scan", str(FIX / "front-angular"), "--out", tmp, "--fail-on", "never")
            self.assertEqual(code, 0)

    def test_unknown_cve(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err = run_cli("scan", str(FIX / "fixed-app"), "--cve", "CVE-1999-0001", "--out", tmp)
        self.assertEqual(code, 2)
        self.assertIn("absent de la watchlist", err)

    def test_rules_command(self):
        code, out, _ = run_cli("rules")
        self.assertEqual(code, 0)
        self.assertIn("JAVA4SHELL", out)
        self.assertIn("NGINX2ROOT", out)

    def test_missing_probe_is_a_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err = run_cli("scan", str(FIX / "fixed-app"), "--probe", "absent.txt", "--out", tmp)
        self.assertEqual(code, 0)
        self.assertIn("probe absent", err)

    def test_bad_fail_on(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err = run_cli("scan", str(FIX / "fixed-app"), "--fail-on", "parfois", "--out", tmp)
        self.assertEqual(code, 2)


class FakeGitLab(http.server.BaseHTTPRequestHandler):
    projects = [{"id": 1, "path_with_namespace": "bpi/cia/front", "default_branch": "main"},
                {"id": 2, "path_with_namespace": "bpi/fbi/batch", "default_branch": "main"},
                {"id": 3, "path_with_namespace": "bpi/fbi/vide", "default_branch": None}]
    trees = {1: ["Dockerfile", "nginx/default.conf", "node_modules/x/Dockerfile", "README.md"], 2: ["Dockerfile"]}
    files = {(1, "Dockerfile"): (FIX / "front-angular" / "Dockerfile").read_text(),
             (1, "nginx/default.conf"): (FIX / "front-angular" / "nginx" / "default.conf").read_text(),
             (2, "Dockerfile"): "FROM eclipse-temurin:21.0.13.1_1-jre\n"}
    throttled = {"count": 0}

    def log_message(self, *args):
        pass

    def send_json(self, code, obj, headers=None):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.headers.get("PRIVATE-TOKEN") != "secret":
            return self.send_json(401, {"message": "401 Unauthorized"})
        url = urllib.parse.urlparse(self.path)
        page = int(urllib.parse.parse_qs(url.query).get("page", ["1"])[0])
        if url.path == "/api/v4/groups/bpi/projects":
            items = self.projects[:2] if page == 1 else self.projects[2:]
            return self.send_json(200, items, {"X-Next-Page": "2" if page == 1 else ""})
        m = re.match(r"/api/v4/projects/(\d+)/repository/tree$", url.path)
        if m:
            blobs = [{"type": "blob", "path": p} for p in self.trees.get(int(m.group(1)), [])]
            return self.send_json(200, blobs + [{"type": "tree", "path": "nginx"}])
        m = re.match(r"/api/v4/projects/(\d+)/repository/files/(.+)/raw$", url.path)
        if m:
            pid, path = int(m.group(1)), urllib.parse.unquote(m.group(2))
            if (pid, path) == (1, "Dockerfile") and self.throttled["count"] == 0:
                self.throttled["count"] += 1
                return self.send_json(429, {"message": "Retry later"}, {"Retry-After": "0"})
            body = self.files.get((pid, path))
            if body is None:
                return self.send_json(404, {"message": "404 File Not Found"})
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return None
        return self.send_json(404, {"message": "404 Not Found"})


class GroupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeGitLab)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_group_scan(self):
        os.environ["VW_TEST_TOKEN"] = "secret"
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = run_cli("group", "--gitlab-url", self.url, "--group", "bpi", "--token-env", "VW_TEST_TOKEN",
                                     "--out", tmp)
            self.assertEqual(code, 0, err)
            data = json.loads((Path(tmp) / "vuln-watch-report.json").read_text(encoding="utf-8"))
        runtime = sorted((f["project"], f["rule"], f["version"], f["verdict"]) for f in data["findings"]
                         if f["context"] == "runtime")
        self.assertEqual(runtime, [("bpi/cia/front", "NGINX2ROOT", "1.27.3", V), ("bpi/fbi/batch", "JAVA4SHELL", "21.0.13.1", OK)])
        self.assertEqual([p["project"] for p in data["projects"]], ["bpi/cia/front", "bpi/fbi/batch"])
        self.assertEqual(FakeGitLab.throttled["count"], 1)
        self.assertNotIn("secret", out + err)

    def test_bad_token(self):
        os.environ["VW_TEST_TOKEN"] = "mauvais"
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err = run_cli("group", "--gitlab-url", self.url, "--group", "bpi", "--token-env", "VW_TEST_TOKEN", "--out", tmp)
        self.assertEqual(code, 3)
        self.assertIn("accès refusé", err)

    def test_missing_token(self):
        os.environ.pop("VW_TEST_ABSENT", None)
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err = run_cli("group", "--gitlab-url", self.url, "--group", "bpi", "--token-env", "VW_TEST_ABSENT", "--out", tmp)
        self.assertEqual(code, 2)
        self.assertIn("jeton absent", err)


if __name__ == "__main__":
    unittest.main()
