"""Tests for the pure analysis functions. No network; stdlib unittest only.

Run: python3 -m unittest services/drive-audit/test_drive_audit.py
"""
import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))
import drive_audit as da  # noqa: E402

NOW = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)
HOME = {"pi0.co"}


def f(i, name="x.txt", mime="text/plain", owned=True, perms=None, mod="2026-09-01T00:00:00Z",
      md5=None, parents=None, viewed=None, size="10"):
    return {"id": i, "name": name, "mimeType": mime, "ownedByMe": owned, "permissions": perms,
            "modifiedTime": mod, "md5Checksum": md5, "parents": parents, "size": size,
            "quotaBytesUsed": size, "viewedByMeTime": viewed,
            "owners": [{"emailAddress": "p@pi0.co"}], "lastModifyingUser": {"emailAddress": "p@pi0.co"}}


class Exposure(unittest.TestCase):
    def test_anyone_with_link_vs_public(self):
        self.assertEqual(da.classify_exposure({"permissions": [{"type": "anyone"}]}, HOME), ["anyone-with-link"])
        self.assertEqual(da.classify_exposure({"permissions": [{"type": "anyone", "allowFileDiscovery": True}]}, HOME),
                         ["public-searchable"])

    def test_external_person_but_not_the_owner(self):
        perms = [{"type": "user", "role": "owner", "emailAddress": "p@gmail.com"},
                 {"type": "user", "role": "writer", "emailAddress": "x@other.com"}]
        self.assertEqual(da.classify_exposure({"permissions": perms}, HOME), ["external-people"])

    def test_insiders_only_is_not_exposure(self):
        perms = [{"type": "user", "role": "writer", "emailAddress": "e@pi0.co"}]
        self.assertEqual(da.classify_exposure({"permissions": perms}, HOME), [])

    def test_domain_share_home_vs_other(self):
        self.assertEqual(da.classify_exposure({"permissions": [{"type": "domain", "domain": "pi0.co"}]}, HOME),
                         ["whole-domain"])
        self.assertEqual(da.classify_exposure({"permissions": [{"type": "domain", "domain": "acme.com"}]}, HOME),
                         ["other-domain"])


class VersionKey(unittest.TestCase):
    def test_collapses_version_noise(self):
        k = da.version_key("budget.xlsx")
        for n in ("Copy of Budget.xlsx", "Budget FINAL.xlsx", "Budget v3.xlsx", "Budget (2).xlsx",
                  "Copy of Budget final v2 (1).xlsx", "budget_2026-09-01.xlsx"):
            self.assertEqual(da.version_key(n), k, n)

    def test_keeps_different_extensions_apart(self):
        self.assertNotEqual(da.version_key("Budget.xlsx"), da.version_key("Budget.pdf"))

    def test_does_not_eat_noise_words_inside_real_words(self):
        # Regression: without a leading anchor these became "househ", "g", "sc", "re".
        for word in ("household", "gold", "scaffold", "renew", "threshold"):
            self.assertEqual(da.version_key(f"{word}.txt"), f"{word}.txt", word)


class Analyse(unittest.TestCase):
    def build(self):
        files = [
            f("fold", name="Clients", mime=da.FOLDER, parents=["root"]),
            f("a", name="Acme contract.pdf", mime="application/pdf", parents=["fold"], md5="m1",
              perms=[{"type": "anyone"}], viewed="2026-09-02T00:00:00Z"),
            f("b", name="Copy of Acme contract.pdf", mime="application/pdf", parents=["fold"], md5="m1",
              perms=[{"type": "user", "role": "owner", "emailAddress": "p@pi0.co"}]),
            f("c", name="Old plan.gdoc", mime="application/vnd.google-apps.document",
              mod="2020-01-01T00:00:00Z", parents=["fold"]),                     # no perms visible, no md5
            f("d", name="shared thing", owned=False, parents=["elsewhere"]),     # parent not visible
            f("e", name="Empty", mime=da.FOLDER, parents=["root"]),
        ]
        return da.analyse(files, {"files": 2, "bytes": 30}, "pi0.co", NOW, None)

    def test_totals_split_files_and_folders(self):
        t = self.build()["totals"]
        self.assertEqual((t["items"], t["files"], t["folders"]), (6, 4, 2))
        self.assertEqual((t["owned"], t["shared_with_me"]), (3, 1))

    def test_every_coverage_row_has_a_true_denominator(self):
        cov = {row[0]: (row[1], row[2]) for row in self.build()["coverage"]}
        self.assertEqual(cov["files and folders scanned"], (6, 6))
        self.assertEqual(cov["sharing assessable"], (2, 4))          # c and d show no permissions
        self.assertEqual(cov["exact-duplicate checkable"], (2, 4))   # only the uploaded pdfs have md5
        self.assertEqual(cov["'last opened by you' known"], (1, 4))
        self.assertEqual(cov["folder placement visible"], (3, 6))    # a,b,c sit in a scanned folder

    def test_findings(self):
        a = self.build()
        self.assertEqual([x["id"] for x in a["exposure"]["anyone-with-link"]], ["a"])
        self.assertEqual(len(a["exact_dups"]), 1)
        self.assertEqual(a["exact_waste"], 10)
        self.assertEqual([x["id"] for x in a["stale_3y"]], ["c"])
        self.assertEqual([x["id"] for x in a["empty_folders"]], ["e"])

    def test_console_never_prints_a_file_name(self):
        a = self.build()
        proof = {"attempts": [{"attempt": "export a Google Doc", "http": 403, "reason": "insufficientPermissions"}]}
        out = da.console_summary(a, proof, NOW, "/tmp/x")
        for name in ("Acme", "contract", "Old plan", "shared thing", "Clients", "Empty"):
            self.assertNotIn(name, out, f"console leaked a file name: {name}")


class RootGrants(unittest.TestCase):
    def test_folder_share_is_one_setting_not_many_files(self):
        link = [{"type": "anyone"}]
        files = [
            f("top", name="Shared", mime=da.FOLDER, perms=link, parents=["root"]),
            f("sub", name="Sub", mime=da.FOLDER, perms=link, parents=["top"]),   # inherits
            f("k1", perms=link, parents=["top"]),                                # inherits
            f("k2", perms=link, parents=["sub"]),                                # inherits, two deep
            f("solo", perms=link, parents=["root"]),                             # its own setting
            f("priv", perms=[{"type": "user", "role": "owner", "emailAddress": "p@pi0.co"}], parents=["top"]),
        ]
        by_id = {x["id"]: x for x in files}
        roots = da.root_grants(files, by_id, HOME)["anyone-with-link"]
        self.assertEqual(sorted((r["id"], n) for r, n in roots), [("solo", 1), ("top", 4)])

    def test_two_classes_are_rooted_independently(self):
        files = [
            f("top", mime=da.FOLDER, parents=["root"],
              perms=[{"type": "user", "role": "writer", "emailAddress": "x@other.com"}]),
            f("k", parents=["top"], perms=[{"type": "user", "role": "writer", "emailAddress": "x@other.com"},
                                            {"type": "anyone"}]),
        ]
        roots = da.root_grants(files, {x["id"]: x for x in files}, HOME)
        self.assertEqual([r["id"] for r, _ in roots["external-people"]], ["top"])
        self.assertEqual([r["id"] for r, _ in roots["anyone-with-link"]], ["k"])  # its own link share

    def test_cycle_in_parents_does_not_hang(self):
        link = [{"type": "anyone"}]
        files = [f("a", perms=link, parents=["b"]), f("b", perms=link, parents=["a"])]
        roots = da.root_grants(files, {x["id"]: x for x in files}, HOME)
        self.assertEqual(sum(n for _, n in roots["anyone-with-link"]), 2)


class Guard(unittest.TestCase):
    def test_refuses_a_token_wider_than_metadata(self):
        class FakeResp:
            def __init__(self, body): self.body = body
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return self.body
        import json, urllib.request
        orig = urllib.request.urlopen
        try:
            urllib.request.urlopen = lambda *a, **k: FakeResp(json.dumps(
                {"scope": da.META_SCOPE + " https://www.googleapis.com/auth/documents"}).encode())
            with self.assertRaises(da.AuditAbort):
                da.verify_scope_is_metadata_only("tok")
        finally:
            urllib.request.urlopen = orig


class Consent(unittest.TestCase):
    """The sign-in flow. No test here talks to Google."""

    def test_pkce_challenge_is_s256_of_the_verifier(self):
        import base64, hashlib
        v, c = da.pkce_pair()
        self.assertTrue(43 <= len(v) <= 128)
        want = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
        self.assertEqual(c, want)

    def test_auth_url_asks_for_exactly_the_metadata_scope(self):
        import urllib.parse as up
        q = up.parse_qs(up.urlparse(da.auth_url("cid", "http://127.0.0.1:5/", "chal", "st")).query)
        self.assertEqual(q["scope"], [da.META_SCOPE], "one scope, and only the metadata one")
        self.assertEqual(q["code_challenge_method"], ["S256"])
        self.assertEqual((q["access_type"], q["state"]), (["offline"], ["st"]))

    def test_callback_refuses_error_forged_state_and_no_code(self):
        with self.assertRaises(da.AuditAbort):
            da.validate_callback({"error": ["access_denied"]}, "st")
        with self.assertRaises(da.AuditAbort):
            da.validate_callback({"code": ["c"], "state": ["forged"]}, "st")
        with self.assertRaises(da.AuditAbort):
            da.validate_callback({"state": ["st"]}, "st")
        self.assertEqual(da.validate_callback({"code": ["c"], "state": ["st"]}, "st"), "c")

    def test_grant_wider_than_metadata_is_refused(self):
        wide = {"scope": da.META_SCOPE + " https://www.googleapis.com/auth/drive.readonly", "refresh_token": "r"}
        with self.assertRaises(da.AuditAbort):
            da.validate_granted(wide)
        with self.assertRaises(da.AuditAbort):
            da.validate_granted({"scope": da.META_SCOPE})  # no refresh token
        self.assertEqual(da.validate_granted({"scope": da.META_SCOPE, "refresh_token": "r"}), "r")

    def test_token_file_is_owner_only_even_over_an_existing_file(self):
        import tempfile, stat
        d = tempfile.mkdtemp()
        p = os.path.join(d, "token.json")
        open(p, "w").close(); os.chmod(p, 0o644)  # a pre-existing, too-open file
        da.write_token(p, "cid", "sec", "r")
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
        import json
        body = json.load(open(p))
        self.assertEqual((body["refresh_token"], body["scopes"]), ("r", [da.META_SCOPE]))

    def test_a_web_client_is_refused_with_a_pointer_to_desktop(self):
        import tempfile, json
        p = os.path.join(tempfile.mkdtemp(), "cs.json")
        json.dump({"web": {"client_id": "x"}}, open(p, "w"))
        with self.assertRaises(da.AuditAbort) as cm:
            da.load_client(p)
        self.assertIn("Desktop app", str(cm.exception))

    def _consent(self, forge_state=False):
        """Drive run_consent end to end: capture the URL, play the browser, fake the exchange."""
        import tempfile, json, threading, urllib.parse as up, urllib.request as ur
        d = tempfile.mkdtemp()
        cs = os.path.join(d, "cs.json")
        json.dump({"installed": {"client_id": "cid", "client_secret": "sec"}}, open(cs, "w"))
        tok = os.path.join(d, "t", "token.json")
        seen = {}

        def fake_browser(url):
            q = up.parse_qs(up.urlparse(url).query)
            seen["verifier_challenge"] = q["code_challenge"][0]
            state = "forged" if forge_state else q["state"][0]
            target = q["redirect_uri"][0] + "?" + up.urlencode({"code": "authcode", "state": state})
            threading.Timer(0.2, lambda: ur.urlopen(target).read()).start()
            return True

        def fake_post(url, data):
            seen["post"] = data
            return {"scope": da.META_SCOPE, "refresh_token": "refresh-xyz"}

        orig = (da.webbrowser.open, da._post_form)
        da.webbrowser.open, da._post_form = fake_browser, fake_post
        try:
            import io, contextlib
            with contextlib.redirect_stdout(io.StringIO()):
                path = da.run_consent(cs, tok, timeout_s=10)
        finally:
            da.webbrowser.open, da._post_form = orig
        return path, tok, seen

    def test_end_to_end_loopback_sign_in_writes_a_metadata_only_token(self):
        import json, base64, hashlib
        path, tok, seen = self._consent()
        self.assertEqual(path, tok)
        self.assertEqual(json.load(open(tok))["refresh_token"], "refresh-xyz")
        p = seen["post"]
        self.assertEqual((p["code"], p["grant_type"]), ("authcode", "authorization_code"))
        # the verifier sent at exchange must hash to the challenge sent at sign-in
        got = base64.urlsafe_b64encode(hashlib.sha256(p["code_verifier"].encode()).digest()).rstrip(b"=").decode()
        self.assertEqual(got, seen["verifier_challenge"])

    def test_forged_state_writes_no_token(self):
        with self.assertRaises(da.AuditAbort):
            self._consent(forge_state=True)


class Cli(unittest.TestCase):
    def test_dispatch(self):
        calls = []
        orig = (da.cmd_auth, da.cmd_run)
        da.cmd_auth = lambda a: calls.append(("auth", a)) or 0
        da.cmd_run = lambda a: calls.append(("run", a)) or 0
        try:
            da.main(["auth", "--client-secrets", "x"])
            da.main(["run", "--pdf"])
            da.main(["--token", "t", "--out", "o"])  # the legacy form deployments already use
        finally:
            da.cmd_auth, da.cmd_run = orig
        self.assertEqual(calls, [("auth", ["--client-secrets", "x"]), ("run", ["--pdf"]),
                                 ("run", ["--token", "t", "--out", "o"])])

    def test_run_without_a_token_says_run_auth_first(self):
        import io, contextlib
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = da.cmd_run(["--token", "/nonexistent/token.json"])
        self.assertEqual(rc, 2)
        self.assertIn("auth", err.getvalue())

    def test_pdf_returns_promptly_and_owner_only_when_chrome_never_exits(self):
        # Regression, measured 2026-09-21: real Chrome wrote a complete PDF and then never
        # exited, so waiting on the process reported failure after the full timeout AND
        # left the PDF world-readable. This fake Chrome does exactly that.
        import tempfile, stat, time as _t
        d = tempfile.mkdtemp()
        fake = os.path.join(d, "fake-chrome")
        open(fake, "w").write(
            "#!/usr/bin/env python3\n"
            "import sys, time\n"
            "out = [a.split('=', 1)[1] for a in sys.argv if a.startswith('--print-to-pdf=')][0]\n"
            "open(out, 'wb').write(b'%PDF-1.4 fake ' + b'x' * 2000)\n"
            "time.sleep(600)\n")
        os.chmod(fake, 0o755)
        html = os.path.join(d, "r.html"); open(html, "w").write("<p>x</p>")
        pdf = os.path.join(d, "r.pdf")
        orig = da.find_chrome
        da.find_chrome = lambda: fake
        try:
            t = _t.monotonic()
            got = da.render_pdf(html, pdf, timeout_s=30)
            elapsed = _t.monotonic() - t
        finally:
            da.find_chrome = orig
        self.assertEqual(got, pdf, "a written PDF must be reported, not lost to a hung process")
        self.assertLess(elapsed, 10, "must not wait out the timeout for a process that never exits")
        self.assertEqual(stat.S_IMODE(os.stat(pdf).st_mode), 0o600, "the PDF lists file names")

    def test_pdf_is_none_without_chrome(self):
        orig = da.find_chrome
        da.find_chrome = lambda: None
        try:
            self.assertIsNone(da.render_pdf("/tmp/x.html", "/tmp/x.pdf"))
        finally:
            da.find_chrome = orig


if __name__ == "__main__":
    unittest.main()
