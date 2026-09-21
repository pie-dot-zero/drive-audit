#!/usr/bin/env python3
"""drive-audit v1 — a Google Drive landscape audit that never opens a file.

WHAT IT DOES
  Maps a Google Drive from METADATA ONLY — names, folders, owners, sharing,
  dates, sizes, checksums — and writes a report on the machine it runs on:
  who can see what, what has gone stale, who the files depend on, where the
  duplication and sprawl are, and what a content-level pass would add.

WHY "NEVER OPENS A FILE" IS ENFORCED, NOT PROMISED
  It asks Google for a token scoped to drive.metadata.readonly and nothing else,
  confirms with Google's tokeninfo endpoint that the token carries exactly that
  scope, and then ATTEMPTS to read one document's content. Google must refuse
  (HTTP 403). If it does not, the audit aborts before scanning. The result of
  that attempt is printed at the top of the report, so the claim is re-checkable.

WHAT THE OPERATOR SEES VS. WHAT THE REPORT HOLDS
  The report (report.html, findings.json) contains file names and stays on this
  machine. The console prints COUNTS ONLY — no file names — so whoever runs it,
  human or agent, never pulls the contents of the Drive into their own session.

EVERY NUMBER STATES ITS DENOMINATOR
  Drive does not return every field for every file: permissions are hidden on
  files you can only view, checksums exist only for uploaded files, and "last
  viewed" only exists for files you opened. Each finding says how many files it
  could assess and why the rest could not be — nothing is silently dropped.

WHOSE OAUTH APP
  drive.metadata.readonly is a RESTRICTED Google scope: an app someone else owns
  shows "Google hasn't verified this app" until it passes restricted-scope review
  and a security assessment. So the client creates the OAuth app in their own
  Google Workspace as Internal (exempt from that review), sets the one scope
  themselves, and no third party ever holds a grant to their Drive.
  docs/oauth-setup.md walks through it.

Pure standard library. No network except Google's OAuth and Drive APIs.

Usage:
  python3 drive_audit.py auth --client-secrets client_secret.json   # once
  python3 drive_audit.py run                                         # the audit
  python3 drive_audit.py run --pdf --taxonomy taxonomy/business.json
  python3 drive_audit.py --token TOKEN.json --out DIR                # same as run
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import http.server
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from collections import Counter, defaultdict
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

META_SCOPE = "https://www.googleapis.com/auth/drive.metadata.readonly"
DRIVE = "https://www.googleapis.com/drive/v3"
ET = ZoneInfo("America/New_York")
FOLDER = "application/vnd.google-apps.folder"
NATIVE = "application/vnd.google-apps."

FILE_FIELDS = (
    "id,name,mimeType,size,quotaBytesUsed,md5Checksum,createdTime,modifiedTime,"
    "viewedByMeTime,ownedByMe,owners(emailAddress),lastModifyingUser(emailAddress),"
    "shared,parents,webViewLink,"
    "permissions(type,role,emailAddress,domain,allowFileDiscovery)"
)


class AuditAbort(Exception):
    """A precondition failed. The audit must not run past it."""


# ── auth: a token Google itself limits to metadata ────────────────────────────

def _post_form(url: str, data: dict) -> dict:
    body = urllib.parse.urlencode(data).encode()
    try:
        with urllib.request.urlopen(url, body, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        raise AuditAbort(f"token endpoint refused: HTTP {e.code} {e.read().decode()[:200]}")


def mint_metadata_token(token_path: str) -> str:
    """Exchange a stored refresh token for an access token scoped to ONLY metadata.

    The stored grant may be broader (e.g. it also holds documents or gmail). Google
    lets a refresh request ask for a strict subset of what was granted, and the
    access token it returns is limited to that subset — so the breadth of the
    stored grant never reaches this program.
    """
    tok = json.load(open(os.path.expanduser(token_path)))
    for k in ("client_id", "client_secret", "refresh_token"):
        if not tok.get(k):
            raise AuditAbort(f"token file lacks {k}")
    resp = _post_form("https://oauth2.googleapis.com/token", {
        "client_id": tok["client_id"], "client_secret": tok["client_secret"],
        "refresh_token": tok["refresh_token"], "grant_type": "refresh_token",
        "scope": META_SCOPE,
    })
    return resp["access_token"]


def verify_scope_is_metadata_only(access_token: str) -> list[str]:
    """Ask Google — not our own request — what this token may do. Refuse anything wider."""
    url = "https://oauth2.googleapis.com/tokeninfo?access_token=" + urllib.parse.quote(access_token)
    with urllib.request.urlopen(url, timeout=30) as r:
        scopes = json.load(r).get("scope", "").split()
    if scopes != [META_SCOPE]:
        raise AuditAbort(f"token carries {scopes}, not exactly [{META_SCOPE}] — refusing to run")
    return scopes


# ── consent: the client's own OAuth app, granting metadata and nothing else ───

AUTH_URI = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URI = "https://oauth2.googleapis.com/token"
DEFAULT_TOKEN = "~/.config/drive-audit/token.json"


def pkce_pair() -> tuple[str, str]:
    """RFC 7636 S256: a random verifier and its challenge."""
    verifier = secrets.token_urlsafe(64)  # 86 chars, inside the 43-128 bound
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def load_client(path: str) -> tuple[str, str]:
    """client_id and client_secret from a Google 'Desktop app' client JSON."""
    try:
        cs = json.load(open(os.path.expanduser(path)))
    except (OSError, ValueError) as e:
        raise AuditAbort(f"cannot read client secrets {path}: {e}")
    c = cs.get("installed")
    if not c:
        kind = next(iter(cs), "unknown")
        raise AuditAbort(f"this is a '{kind}' OAuth client; create a 'Desktop app' client instead "
                         "(Google Auth platform > Clients > Create Client) - see docs/oauth-setup.md")
    return c["client_id"], c.get("client_secret", "")


def auth_url(client_id: str, redirect_uri: str, challenge: str, state: str) -> str:
    return AUTH_URI + "?" + urllib.parse.urlencode({
        "client_id": client_id, "redirect_uri": redirect_uri, "response_type": "code",
        "scope": META_SCOPE,  # exactly one scope, and it is the metadata one
        "code_challenge": challenge, "code_challenge_method": "S256",
        "state": state, "access_type": "offline", "prompt": "consent",
    })


def validate_callback(query: dict, expected_state: str) -> str:
    """The authorization code, or an abort. state guards against a forged redirect."""
    if query.get("error"):
        raise AuditAbort(f"Google returned '{query['error'][0]}' - consent was not given")
    if query.get("state", [None])[0] != expected_state:
        raise AuditAbort("state mismatch on the sign-in redirect - refusing it")
    code = query.get("code", [None])[0]
    if not code:
        raise AuditAbort("the sign-in redirect carried no authorization code")
    return code


def validate_granted(resp: dict) -> str:
    """Refuse a grant that is not exactly the metadata scope. Returns the refresh token."""
    granted = resp.get("scope", "").split()
    if granted != [META_SCOPE]:
        raise AuditAbort(f"Google granted {granted or 'nothing'}, not exactly [{META_SCOPE}] - no token "
                         "written. If the OAuth app asks for more, narrow it under Data Access.")
    if not resp.get("refresh_token"):
        raise AuditAbort("Google returned no refresh token - remove the app's access in your Google "
                         "Account's security settings, under third-party connections, and run auth again")
    return resp["refresh_token"]


def write_token(path: str, client_id: str, client_secret: str, refresh_token: str) -> str:
    path = os.path.expanduser(path)
    os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
    body = {"type": "authorized_user", "client_id": client_id, "client_secret": client_secret,
            "refresh_token": refresh_token, "scopes": [META_SCOPE], "token_uri": TOKEN_URI}
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as fh:
        json.dump(body, fh, indent=1)
    os.chmod(path, 0o600)  # O_CREAT's mode is ignored when the file already existed
    return path


def run_consent(client_secrets: str, token_out: str, port: int = 0, open_browser: bool = True,
                timeout_s: int = 300) -> str:
    """Loopback sign-in: the browser returns to a one-shot server bound to 127.0.0.1."""
    client_id, client_secret = load_client(client_secrets)
    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(24)
    got: dict = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if "code" not in q and "error" not in q:  # a favicon request or a stray probe
                self.send_response(404)
                self.end_headers()
                return
            got.update(q)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<p>Signed in. You can close this tab and return to the terminal.</p>")

        def log_message(self, *a):  # keep the terminal quiet
            pass

    srv = http.server.HTTPServer(("127.0.0.1", port), Handler)
    srv.timeout = 5
    redirect = f"http://127.0.0.1:{srv.server_address[1]}/"
    url = auth_url(client_id, redirect, challenge, state)
    print("Open this URL, sign in, and approve read-only access to file metadata:\n\n  " + url + "\n")
    if port:
        print(f"Headless machine? From your laptop run: ssh -L {port}:127.0.0.1:{port} <this-machine>\n"
              "then open the URL there.\n")
    if open_browser:
        webbrowser.open(url)
    deadline = time.monotonic() + timeout_s
    try:
        while not got and time.monotonic() < deadline:
            srv.handle_request()
    finally:
        srv.server_close()
    if not got:
        raise AuditAbort(f"no sign-in within {timeout_s}s")
    code = validate_callback(got, state)
    resp = _post_form(TOKEN_URI, {
        "code": code, "client_id": client_id, "client_secret": client_secret,
        "redirect_uri": redirect, "grant_type": "authorization_code", "code_verifier": verifier,
    })
    return write_token(token_out, client_id, client_secret, validate_granted(resp))


# ── PDF: optional, via a local headless Chrome ────────────────────────────────

CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
]


def find_chrome() -> str | None:
    for c in CHROME_CANDIDATES:
        p = c if os.path.isabs(c) else shutil.which(c)
        if p and os.path.exists(p):
            return p
    return None


def _pdf_done(path: str, last: list) -> bool:
    """True once the PDF exists, is non-empty, and has not grown since the last look."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return False
    done = size > 0 and last and last[-1] == size
    last.append(size)
    return bool(done)


def render_pdf(report_html: str, pdf_path: str, timeout_s: int = 60) -> str | None:
    """Print the report to PDF with headless Chrome, if one is installed.

    Does NOT wait for Chrome to exit. Measured 2026-09-21 on macOS: Chrome wrote a
    complete 4-page PDF in seconds and then never exited, so waiting for the process
    reported failure after the full timeout — and left the PDF world-readable, because
    the permission step never ran. So this watches for the file to appear and stop
    growing, then shuts Chrome down, and locks the PDF to its owner however Chrome ended.

    The report references nothing external. Chrome runs on a throwaway profile (no
    collision with a Chrome already open) with background networking off. Returns the
    PDF path, or None if nothing usable was written."""
    chrome = find_chrome()
    if not chrome:
        return None
    if os.path.exists(pdf_path):
        os.remove(pdf_path)  # never mistake a previous run's file for this one's
    with tempfile.TemporaryDirectory() as profile:
        proc = subprocess.Popen(
            [chrome, "--headless=new", "--disable-gpu", f"--user-data-dir={profile}",
             "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
             "--disable-component-update", "--disable-sync", "--no-pdf-header-footer",
             f"--print-to-pdf={pdf_path}", "file://" + os.path.abspath(report_html)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sizes: list = []
        deadline = time.monotonic() + timeout_s
        try:
            while time.monotonic() < deadline and proc.poll() is None and not _pdf_done(pdf_path, sizes):
                time.sleep(0.5)
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
    if os.path.exists(pdf_path):
        os.chmod(pdf_path, 0o600)  # before any early return: the file lists names
        if os.path.getsize(pdf_path) > 0:
            return pdf_path
    return None


# ── Drive calls ───────────────────────────────────────────────────────────────

class Drive:
    def __init__(self, access_token: str):
        self.h = {"Authorization": f"Bearer {access_token}"}
        self.calls = 0

    def get(self, path: str, params: dict | None = None, raw: bool = False):
        url = f"{DRIVE}/{path}" + (("?" + urllib.parse.urlencode(params)) if params else "")
        for attempt in range(6):
            self.calls += 1
            req = urllib.request.Request(url, headers=self.h)
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    data = r.read()
                    return (r.status, data) if raw else json.loads(data)
            except urllib.error.HTTPError as e:
                if raw:
                    return e.code, e.read()
                if e.code in (429, 500, 502, 503, 504) and attempt < 5:
                    time.sleep(min(2 ** attempt, 30))
                    continue
                raise AuditAbort(f"Drive {path} -> HTTP {e.code}: {e.read().decode()[:200]}")
        raise AuditAbort(f"Drive {path}: retries exhausted")

    def prove_cannot_read_content(self, files: list[dict]) -> dict:
        """Try to read one document. Google must say no. Returns the evidence."""
        doc = next((f for f in files if f["mimeType"] == "application/vnd.google-apps.document"), None)
        upl = next((f for f in files if not f["mimeType"].startswith(NATIVE)), None)
        evidence = []
        for label, f, path, params in (
            ("export a Google Doc", doc, lambda i: f"files/{i}/export", {"mimeType": "text/plain"}),
            ("download an uploaded file", upl, lambda i: f"files/{i}", {"alt": "media"}),
        ):
            if not f:
                continue
            status, body = self.get(path(f["id"]), params, raw=True)
            reason = "?"
            try:
                reason = json.loads(body)["error"]["errors"][0].get("reason", "?")
            except Exception:
                pass
            if status == 200:
                raise AuditAbort(f"content read SUCCEEDED ({label}) — the metadata-only guarantee "
                                 "does not hold for this token; aborting before any scan")
            evidence.append({"attempt": label, "http": status, "reason": reason})
        if not evidence:
            raise AuditAbort("found no file to test content refusal against")
        return {"refused": True, "attempts": evidence}


def scan(drive: Drive) -> tuple[list[dict], dict]:
    """Every non-trashed file visible to the account, plus a trash tally."""
    files, token = [], None
    while True:
        p = {"pageSize": 1000, "q": "trashed = false",
             "fields": f"nextPageToken,files({FILE_FIELDS})"}
        if token:
            p["pageToken"] = token
        page = drive.get("files", p)
        files.extend(page.get("files", []))
        token = page.get("nextPageToken")
        if not token:
            break
    trash, token = {"files": 0, "bytes": 0}, None
    while True:
        p = {"pageSize": 1000, "q": "trashed = true", "fields": "nextPageToken,files(quotaBytesUsed)"}
        if token:
            p["pageToken"] = token
        page = drive.get("files", p)
        for f in page.get("files", []):
            trash["files"] += 1
            trash["bytes"] += int(f.get("quotaBytesUsed") or 0)
        token = page.get("nextPageToken")
        if not token:
            break
    return files, trash


# ── analysis (pure functions: files in, findings out) ─────────────────────────

def _dt(s: str | None):
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


def _domain(email: str | None) -> str:
    return (email or "").rsplit("@", 1)[-1].lower()


def classify_exposure(f: dict, home_domains: set[str]) -> list[str]:
    """Which sharing classes apply. Empty list = private to named insiders."""
    out = set()
    for p in f.get("permissions") or []:
        t = p.get("type")
        if t == "anyone":
            out.add("public-searchable" if p.get("allowFileDiscovery") else "anyone-with-link")
        elif t == "domain":
            out.add("whole-domain" if p.get("domain", "").lower() in home_domains else "other-domain")
        elif t in ("user", "group") and p.get("role") != "owner":
            if _domain(p.get("emailAddress")) not in home_domains:
                out.add("external-people")
    return sorted(out)


# A noise word only counts at the start or after a separator — without that anchor,
# "household" collapses to "househ" and "gold" to "g", inventing version groups.
def root_grants(files: list[dict], by_id: dict, home: set[str]) -> dict:
    """The sharing SETTINGS behind the exposure, not the files it reaches.

    A folder shared by link passes that permission to everything beneath it, and
    Drive reports the inherited permission on each file. So a raw count of exposed
    files overstates the work: 774 exposed files may come from a couple of dozen
    settings. A root is an exposed item whose parent folder is not exposed the same
    way; every exposed item descends from exactly one root, so fixing the roots
    fixes the rest. Returns {class: [(root_item, items_reached_including_itself)]}.
    """
    cls = {f["id"]: set(classify_exposure(f, home)) for f in files if f.get("permissions")}

    def exposed_parent(f, c):
        return next((p for p in (f.get("parents") or []) if p in by_id and c in cls.get(p, ())), None)

    out = {}
    for c in sorted({c for s in cls.values() for c in s}):
        reached = Counter()
        for f in files:
            if c not in cls.get(f["id"], ()):
                continue
            node, seen = f, {f["id"]}
            while (p := exposed_parent(node, c)) and p not in seen:  # guard cycles
                seen.add(p)
                node = by_id[p]
            reached[node["id"]] += 1
        out[c] = sorted(((by_id[i], n) for i, n in reached.items()), key=lambda t: t[1], reverse=True)
    return out


_VERSION_NOISE = re.compile(
    r"^(?:copy of\s+)+|\s*\(\d+\)$"
    r"|(?:^|[\s_-]+)(?:final|draft|v\d+(?:\.\d+)*|rev\d*|copy|new|old|\d{4}[-_.]\d{2}[-_.]\d{2})\b",
    re.I)


def version_key(name: str) -> str:
    """Collapse 'Copy of Budget FINAL v3 (2).xlsx' and 'budget.xlsx' to one key."""
    stem, ext = os.path.splitext(name)
    prev = None
    s = stem.lower().strip()
    while prev != s:
        prev, s = s, _VERSION_NOISE.sub("", s).strip(" _-.")
    return f"{re.sub(r'[^a-z0-9]+', ' ', s).strip()}{ext.lower()}"


_STOP = set("""a an and the of for to in on at by with from is are be or as it its this that
copy final draft new old v1 v2 v3 doc docs untitled document sheet file files img image pdf
xlsx docx pptx csv txt png jpg jpeg 2019 2020 2021 2022 2023 2024 2025 2026""".split())


def name_terms(name: str) -> list[str]:
    stem = os.path.splitext(name)[0].lower()
    return [t for t in re.findall(r"[a-z][a-z0-9]{2,}", stem) if t not in _STOP]


def analyse(files: list[dict], trash: dict, me_domain: str, now: datetime,
            taxonomy: dict | None) -> dict:
    home = {me_domain}
    total = len(files)
    by_id = {f["id"]: f for f in files}
    folders = [f for f in files if f["mimeType"] == FOLDER]
    docs = [f for f in files if f["mimeType"] != FOLDER]
    owned = [f for f in docs if f.get("ownedByMe")]

    # census
    def cat(m: str) -> str:
        if m.startswith(NATIVE):
            return "Google " + m[len(NATIVE):]
        return {"application/pdf": "PDF"}.get(m, m.split("/")[0])
    census = Counter(cat(f["mimeType"]) for f in docs)
    owned_bytes = sum(int(f.get("quotaBytesUsed") or 0) for f in owned)

    # exposure — denominator is files whose permissions Drive let us see
    perm_visible = [f for f in docs if f.get("permissions")]
    exposure = defaultdict(list)
    for f in perm_visible:
        for c in classify_exposure(f, home):
            exposure[c].append(f)
    roots = root_grants(files, by_id, home)

    # staleness — modifiedTime exists on every file
    buckets = Counter()
    stale = []
    for f in docs:
        age = (now - _dt(f["modifiedTime"])).days
        b = ("under 30 days" if age < 30 else "30 days – 1 year" if age < 365
             else "1 – 3 years" if age < 1095 else "over 3 years")
        buckets[b] += 1
        if age >= 1095:
            stale.append(f)
    never_opened = [f for f in owned if not f.get("viewedByMeTime")]

    # ownership / key-person
    owner_dom = Counter(_domain((f.get("owners") or [{}])[0].get("emailAddress")) for f in docs)
    editors = Counter(_domain((f.get("lastModifyingUser") or {}).get("emailAddress")) for f in docs)
    not_mine = [f for f in docs if not f.get("ownedByMe")]

    # duplication — md5 exists only on uploaded binaries
    with_md5 = [f for f in docs if f.get("md5Checksum")]
    md5g = defaultdict(list)
    for f in with_md5:
        md5g[f["md5Checksum"]].append(f)
    exact = sorted((g for g in md5g.values() if len(g) > 1), key=len, reverse=True)
    exact_waste = sum(int(g[0].get("size") or 0) * (len(g) - 1) for g in exact)
    vg = defaultdict(list)
    for f in docs:
        k = version_key(f["name"])
        if k and len(k) > 3:
            vg[k].append(f)
    sprawl = sorted((g for g in vg.values() if len(g) > 2), key=len, reverse=True)

    # structure
    child_count = Counter(p for f in files for p in (f.get("parents") or []))
    visible_parent = sum(1 for f in files if any(p in by_id for p in (f.get("parents") or [])))

    def depth(f, seen=None):
        seen = seen or set()
        ps = [p for p in (f.get("parents") or []) if p in by_id and p not in seen]
        if not ps:
            return 0
        seen.add(f["id"])
        return 1 + depth(by_id[ps[0]], seen)
    depths = Counter(min(depth(f), 12) for f in docs)
    empty_folders = [f for f in folders if child_count.get(f["id"], 0) == 0]
    crowded = sorted(((child_count[f["id"]], f) for f in folders), key=lambda t: t[0], reverse=True)[:15]

    # what's in here — filename terms (local, no model)
    terms = Counter(t for f in docs for t in name_terms(f["name"]))

    # optional taxonomy profile: {category: [keywords]} over name + parent-folder names
    tax = None
    if taxonomy:
        hits, unmapped = Counter(), 0
        for f in docs:
            words = set(name_terms(f["name"]))
            for p in f.get("parents") or []:
                if p in by_id:
                    words |= set(name_terms(by_id[p]["name"]))
            matched = [c for c, kws in taxonomy.items() if words & {k.lower() for k in kws}]
            for c in matched:
                hits[c] += 1
            unmapped += not matched
        tax = {"coverage": dict(hits), "unmapped": unmapped, "categories": list(taxonomy)}

    coverage = [  # the reconciliation: every finding's denominator, and why the rest is missing
        ("files and folders scanned", total, total, "every non-trashed item visible to the account"),
        ("sharing assessable", len(perm_visible), len(docs),
         "Drive hides permissions on files you can view but not manage"),
        ("exact-duplicate checkable", len(with_md5), len(docs),
         "checksums exist only on uploaded files; native Google Docs/Sheets carry none"),
        ("'last opened by you' known", len([f for f in docs if f.get("viewedByMeTime")]), len(docs),
         "only recorded for files you have opened"),
        ("folder placement visible", visible_parent, total,
         "items in My Drive root, or in folders shared from elsewhere, have no visible parent"),
    ]

    return {
        "totals": {"items": total, "files": len(docs), "folders": len(folders),
                   "owned": len(owned), "shared_with_me": len(not_mine),
                   "owned_bytes": owned_bytes, "trash_files": trash["files"],
                   "trash_bytes": trash["bytes"]},
        "census": census.most_common(),
        "exposure": {k: v for k, v in sorted(exposure.items())},
        "exposure_denominator": len(perm_visible),
        "roots": roots,
        "staleness": buckets, "stale_3y": stale, "never_opened": never_opened,
        "owner_domains": owner_dom.most_common(), "editor_domains": editors.most_common(),
        "exact_dups": exact, "exact_waste": exact_waste, "sprawl": sprawl,
        "depths": sorted(depths.items()), "empty_folders": empty_folders, "crowded": crowded,
        "terms": terms.most_common(40), "taxonomy": tax, "coverage": coverage,
    }


# ── console: counts only, never a file name ───────────────────────────────────

def console_summary(a: dict, proof: dict, started: datetime, out_dir: str, pdf: str | None = None) -> str:
    t = a["totals"]
    ex = {k: len(v) for k, v in a["exposure"].items()}
    lines = [
        f"drive-audit v1 — {started.astimezone(ET):%Y-%m-%d %H:%M} ET",
        f"content-read refusal: " + "; ".join(f"{e['attempt']} -> HTTP {e['http']} ({e['reason']})"
                                               for e in proof["attempts"]),
        f"scanned {t['items']:,} items: {t['files']:,} files, {t['folders']:,} folders "
        f"({t['owned']:,} owned, {t['shared_with_me']:,} shared with you)",
        f"exposure (of {a['exposure_denominator']:,} with visible sharing): "
        + (", ".join(f"{k} {v:,}" for k, v in ex.items()) or "none found"),
        "  caused by these settings: " + (", ".join(
            f"{k} {len(r):,} ({sum(1 for f, _ in r if f['mimeType'] == FOLDER):,} folders, "
            f"{sum(1 for f, _ in r if f['mimeType'] != FOLDER):,} files)"
            for k, r in a["roots"].items()) or "none"),
        f"stale >3y: {len(a['stale_3y']):,} | owned & never opened: {len(a['never_opened']):,}",
        f"exact-duplicate sets: {len(a['exact_dups']):,} | version-sprawl groups: {len(a['sprawl']):,}",
        f"empty folders: {len(a['empty_folders']):,} | trash: {t['trash_files']:,} files",
        "coverage:",
        *[f"  {label}: {n:,} / {d:,}" for label, n, d, _ in a["coverage"]],
        f"report (contains file names, stays on this machine): {out_dir}/report.html",
        *([f"pdf: {pdf}"] if pdf else []),
    ]
    return "\n".join(lines)


# ── report ────────────────────────────────────────────────────────────────────

def _h(s) -> str:
    return html.escape(str(s))


def _bytes(n: int) -> str:
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:,.0f} {u}" if u == "B" else f"{n:,.1f} {u}"
        n /= 1024
    return f"{n:,.1f} PB"


def _link(f: dict) -> str:
    return f'<a href="{_h(f.get("webViewLink", "#"))}">{_h(f["name"])}</a>'


def _table(rows: list[list[str]], head: list[str], limit: int = 50, total: int | None = None) -> str:
    total = len(rows) if total is None else total
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows[:limit])
    more = (f'<p class="more">Showing {min(limit, len(rows)):,} of {total:,}. '
            f'The full list is in findings.json.</p>' if total > limit else "")
    return (f'<table><thead><tr>{"".join(f"<th>{_h(x)}</th>" for x in head)}</tr></thead>'
            f"<tbody>{body}</tbody></table>{more}")


def render_report(a: dict, proof: dict, started: datetime, me_domain: str, taxonomy_name: str | None) -> str:
    t = a["totals"]
    ex = a["exposure"]
    order = ["public-searchable", "anyone-with-link", "external-people", "other-domain", "whole-domain"]
    label = {"public-searchable": "Public and searchable on the web",
             "anyone-with-link": "Anyone with the link",
             "external-people": "Shared with people outside your domain",
             "other-domain": "Shared with another organisation's whole domain",
             "whole-domain": "Shared with everyone in your domain"}
    risky = sum(len(ex.get(k, [])) for k in order[:3])

    def tile(n, cap, warn=False):
        return f'<div class="tile{" warn" if warn else ""}"><b>{n}</b><span>{_h(cap)}</span></div>'

    exposure_html = ""
    for k in order:
        fs = ex.get(k, [])
        if not fs:
            continue
        rs = a["roots"].get(k, [])
        nf = sum(1 for f, _ in rs if f["mimeType"] == FOLDER)
        root_rows = [[_link(f), "Folder" if f["mimeType"] == FOLDER else "File",
                      f"{n - 1:,} more beneath it" if f["mimeType"] == FOLDER else "—"] for f, n in rs]
        exposure_html += (
            f"<h3>{_h(label[k])} — {len(fs):,} files, caused by {len(rs):,} "
            f"setting{'s' if len(rs) != 1 else ''}</h3>"
            f"<p>{nf:,} shared folder{'s' if nf != 1 else ''} and {len(rs) - nf:,} individually shared "
            f"file{'s' if len(rs) - nf != 1 else ''}. A folder shared this way passes the permission to "
            f"everything inside it, so <b>these {len(rs):,} settings are where the {len(fs):,} come from</b>. "
            f"Drive does not report whether a file inside a shared folder also carries a share of its own, "
            f"so re-run this audit after changing them: anything still listed has its own setting.</p>"
            + _table(root_rows, ["Change this", "Type", "Reach"], 40))
    if not exposure_html:
        exposure_html = "<p>No file with visible sharing is exposed beyond named people in your domain.</p>"

    stale_rows = [[_link(f), _h(_dt(f["modifiedTime"]).astimezone(ET).strftime("%Y-%m-%d"))]
                  for f in sorted(a["stale_3y"], key=lambda f: f["modifiedTime"])]
    exact_rows = [[_h(g[0]["name"]), f"{len(g)} copies", _bytes(int(g[0].get("size") or 0) * (len(g) - 1))]
                  for g in a["exact_dups"]]
    sprawl_rows = [[_h(version_key(g[0]["name"])), f"{len(g)} versions",
                    ", ".join(_h(f["name"]) for f in g[:4]) + (" …" if len(g) > 4 else "")]
                   for g in a["sprawl"]]
    crowded_rows = [[_link(f), f"{n:,}"] for n, f in a["crowded"] if n]
    stale_b = a["staleness"]
    bucket_order = ["under 30 days", "30 days – 1 year", "1 – 3 years", "over 3 years"]
    bar_max = max(stale_b.values() or [1])
    bars = "".join(
        f'<div class="bar"><span class="bl">{_h(b)}</span><span class="bt" style="width:{100*stale_b.get(b,0)/bar_max:.1f}%"></span>'
        f'<span class="bn">{stale_b.get(b,0):,}</span></div>' for b in bucket_order)

    tax_html = ""
    if a["taxonomy"]:
        tx = a["taxonomy"]
        rows = [[_h(c), f"{tx['coverage'].get(c, 0):,}"] for c in tx["categories"]]
        rows.append(["<i>No category matched</i>", f"{tx['unmapped']:,}"])
        tax_html = (f"<h3>Against the {_h(taxonomy_name)} profile</h3>"
                    "<p>Matched on file and folder names only — v1 does not read content, so this is a "
                    "first pass at structure, not a classification.</p>" + _table(rows, ["Category", "Files"], 100))

    cov_rows = [[_h(lbl), f"{n:,} of {d:,}", f"{(100*n/d if d else 0):.0f}%", _h(why)]
                for lbl, n, d, why in a["coverage"]]
    proof_rows = "".join(f"<li>Tried to {_h(e['attempt'])}: <b>refused by Google, HTTP {e['http']}</b> "
                         f"({_h(e['reason'])})</li>" for e in proof["attempts"])

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Drive Landscape Audit</title>
<style>
:root{{--paper:#FAF8F3;--paper2:#F2EFE7;--rule:#D9D4C8;--mute:#8A8577;--soft:#5C574E;--ink:#22201D;--acc:#A6402B}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--paper);color:var(--ink);font:17px/1.55 Spectral,Georgia,serif}}
main{{max-width:980px;margin:0 auto;padding:40px 20px 80px}}
h1,h2,h3{{font-family:'Roboto Slab',Georgia,serif;font-weight:600;line-height:1.2}}
h1{{font-size:34px;margin:0 0 6px}} h2{{font-size:24px;margin:48px 0 10px;padding-top:18px;border-top:1px solid var(--rule)}}
h3{{font-size:18px;margin:26px 0 8px}}
.sub{{color:var(--soft);margin:0}}
.proof{{background:var(--paper2);border-left:4px solid var(--acc);padding:14px 18px;margin:24px 0}}
.proof ul{{margin:6px 0 0;padding-left:20px}}
.tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:22px 0}}
.tile{{background:var(--paper2);padding:14px 16px;border-radius:4px}}
.tile b{{display:block;font:600 26px 'Roboto Slab',Georgia,serif}} .tile span{{color:var(--soft);font-size:14px}}
.tile.warn b{{color:var(--acc)}}
table{{width:100%;border-collapse:collapse;font-size:15px;margin:6px 0}}
th{{text-align:left;color:var(--soft);font-weight:600;border-bottom:1px solid var(--rule);padding:6px 8px}}
td{{border-bottom:1px solid var(--paper2);padding:6px 8px;vertical-align:top;overflow-wrap:anywhere}}
a{{color:var(--ink)}} a:hover{{color:var(--acc)}}
.more,.note{{color:var(--mute);font-size:14px}}
.bar{{display:grid;grid-template-columns:150px 1fr 70px;align-items:center;gap:10px;margin:5px 0}}
.bl{{color:var(--soft);font-size:14px}} .bt{{display:block;height:14px;background:var(--acc);border-radius:2px;min-width:2px}}
.bn{{text-align:right;font-variant-numeric:tabular-nums}}
.terms{{display:flex;flex-wrap:wrap;gap:6px}} .terms span{{background:var(--paper2);padding:3px 9px;border-radius:3px;font-size:14px}}
@page{{margin:14mm}}
@media print{{
  body{{background:#fff;font-size:11pt;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
  main{{max-width:none;padding:0}}
  a{{text-decoration:none;color:var(--ink)}}
  h2,h3{{break-after:avoid}}
  .proof,.tiles,.bar,tr{{break-inside:avoid}}
  .more{{display:none}}
}}
</style></head><body><main>
<h1>Drive Landscape Audit</h1>
<p class="sub">{_h(me_domain)} · run {started.astimezone(ET):%Y-%m-%d %H:%M} ET · metadata only</p>

<div class="proof"><b>This audit could not read your documents, and that was tested.</b>
It ran with a Google token limited to <code>drive.metadata.readonly</code>, confirmed by Google's
own token check. Before scanning, it tried to open files:<ul>{proof_rows}</ul></div>

<div class="tiles">
{tile(f"{t['files']:,}", "files")}{tile(f"{t['folders']:,}", "folders")}
{tile(f"{t['owned']:,}", "owned by you")}{tile(f"{t['shared_with_me']:,}", "shared with you")}
{tile(_bytes(t['owned_bytes']), "storage you own")}
{tile(f"{risky:,}", "exposed beyond your domain", warn=risky > 0)}
</div>

<h2>Who can see what</h2>
<p>Of the {a['exposure_denominator']:,} files whose sharing Drive let this account see
(see Coverage, below).</p>
{exposure_html}

<h2>What has gone stale</h2>
<p>By last change, across all {t['files']:,} files.</p>{bars}
<h3>Untouched for over three years — {len(a['stale_3y']):,}</h3>
{_table(stale_rows, ["File", "Last changed (ET)"], 30)}
<p class="note">{len(a['never_opened']):,} files you own have no record of you ever opening them.</p>

<h2>Who your files depend on</h2>
<h3>Owners, by domain</h3>
{_table([[_h(d or "(unknown)"), f"{n:,}"] for d, n in a['owner_domains']], ["Owner domain", "Files"], 20)}
<h3>Last edited by, by domain</h3>
{_table([[_h(d or "(unknown)"), f"{n:,}"] for d, n in a['editor_domains']], ["Editor domain", "Files"], 20)}

<h2>Duplication and version sprawl</h2>
<h3>Exact duplicates — {len(a['exact_dups']):,} sets, {_bytes(a['exact_waste'])} recoverable</h3>
<p class="note">Exact matching uses Drive's checksum, which exists only for uploaded files. Native Google
Docs and Sheets carry none, so their duplicates cannot be proven from metadata — see version sprawl.</p>
{_table(exact_rows, ["File", "Copies", "Recoverable"], 25)}
<h3>Version sprawl — {len(a['sprawl']):,} groups of three or more</h3>
<p class="note">Names that collapse to the same thing once "Copy of", "final", "v2", dates and "(1)"
are stripped. A signal to look at, not proof of duplication.</p>
{_table(sprawl_rows, ["Name", "Versions", "Examples"], 25)}

<h2>Structure and sprawl</h2>
<p>{len(a['empty_folders']):,} empty folders. {t['trash_files']:,} files ({_bytes(t['trash_bytes'])}) sit in the trash.</p>
<h3>Most crowded folders</h3>{_table(crowded_rows, ["Folder", "Items directly inside"], 15)}
<h3>Nesting depth</h3>
{_table([[str(d) + ("+" if d == 12 else ""), f"{n:,}"] for d, n in a['depths']], ["Folders deep", "Files"], 20)}

<h2>What is in here</h2>
<p>The most frequent words in file names — a rough map of subject matter, drawn from names alone.</p>
<div class="terms">{"".join(f"<span>{_h(w)} · {n:,}</span>" for w, n in a['terms'])}</div>
{tax_html}

<h2>Coverage</h2>
<p>Every number above rests on one of these. Drive does not return every field for every file,
and this audit reports what it could not assess rather than leaving it out.</p>
{_table(cov_rows, ["Finding", "Assessable", "", "Why the rest cannot be"], 20)}

<h2>What a content-level pass would add</h2>
<p>This audit reads no documents. A second pass that does — run on this same machine, with no
cloud model — could group files by what they are actually about rather than by name, find
near-duplicates among Google Docs that metadata cannot prove, and build a searchable map of the
whole Drive. It needs a broader permission and a separate decision.</p>
</main></body></html>"""


# ── main ──────────────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["auth"]:
        return cmd_auth(argv[1:])
    if argv[:1] == ["run"]:
        argv = argv[1:]
    return cmd_run(argv)  # a bare invocation is `run`, the form existing deployments already use


def cmd_auth(argv) -> int:
    ap = argparse.ArgumentParser(prog="drive_audit.py auth",
                                 description="Sign in once and store a metadata-only token.")
    ap.add_argument("--client-secrets", required=True,
                    help="the 'Desktop app' OAuth client JSON from YOUR Google Cloud project")
    ap.add_argument("--token-out", default=DEFAULT_TOKEN, help=f"where to store the token (default {DEFAULT_TOKEN})")
    ap.add_argument("--port", type=int, default=0,
                    help="fixed loopback port, for signing in to a headless machine over an SSH tunnel")
    ap.add_argument("--no-browser", action="store_true", help="print the sign-in URL without opening it")
    args = ap.parse_args(argv)
    try:
        path = run_consent(args.client_secrets, args.token_out, args.port, not args.no_browser)
    except AuditAbort as e:
        print(f"ABORTED: {e}", file=sys.stderr)
        return 2
    print(f"Token stored at {path} (readable only by you). It can see file metadata and nothing else.")
    print("Next: python3 drive_audit.py run")
    return 0


def cmd_run(argv) -> int:
    ap = argparse.ArgumentParser(prog="drive_audit.py run",
                                 description="Google Drive landscape audit - metadata only.")
    ap.add_argument("--token", default=DEFAULT_TOKEN, help=f"token from `auth` (default {DEFAULT_TOKEN})")
    ap.add_argument("--out", default="./drive-audit-reports", help="where reports are written")
    ap.add_argument("--taxonomy", help="optional JSON {category: [keywords]} profile")
    ap.add_argument("--pdf", action="store_true", help="also write report.pdf, if Chrome is installed")
    args = ap.parse_args(argv)
    if not os.path.exists(os.path.expanduser(args.token)):
        print(f"ABORTED: no token at {args.token} - run `python3 drive_audit.py auth "
              "--client-secrets client_secret.json` first", file=sys.stderr)
        return 2

    started = datetime.now(timezone.utc)
    try:
        at = mint_metadata_token(args.token)
        verify_scope_is_metadata_only(at)
        drive = Drive(at)
        me = drive.get("about", {"fields": "user(emailAddress)"})["user"]["emailAddress"]
        me_domain = _domain(me)
        # Prove the guarantee on a small sample BEFORE the full scan, so that if
        # Google would let this token read content, no inventory is ever collected.
        sample = drive.get("files", {"pageSize": 100, "q": "trashed = false",
                                     "fields": "files(id,mimeType)"}).get("files", [])
        proof = drive.prove_cannot_read_content(sample)
        files, trash = scan(drive)
    except AuditAbort as e:
        print(f"ABORTED: {e}", file=sys.stderr)
        return 2

    taxonomy, tax_name = None, None
    if args.taxonomy:
        taxonomy = json.load(open(args.taxonomy))
        tax_name = os.path.splitext(os.path.basename(args.taxonomy))[0]

    a = analyse(files, trash, me_domain, datetime.now(timezone.utc), taxonomy)
    out = os.path.join(os.path.expanduser(args.out), started.astimezone(ET).strftime("%Y-%m-%d_%H%M"))
    os.makedirs(out, mode=0o700, exist_ok=True)

    report = os.path.join(out, "report.html")
    with open(os.open(report, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as fh:
        fh.write(render_report(a, proof, started, me_domain, tax_name))

    slim = lambda f: {k: f.get(k) for k in ("id", "name", "mimeType", "modifiedTime", "webViewLink")}
    findings = {
        "run_started_utc": started.isoformat(), "scope": META_SCOPE, "content_refusal": proof,
        "api_calls": drive.calls, "totals": a["totals"], "census": a["census"],
        "coverage": [{"finding": l, "assessable": n, "of": d, "why": w} for l, n, d, w in a["coverage"]],
        "exposure": {k: [slim(f) for f in v] for k, v in a["exposure"].items()},
        "exposure_root_grants": {k: [{**slim(f), "items_reached": n} for f, n in r]
                                 for k, r in a["roots"].items()},
        "stale_over_3y": [slim(f) for f in a["stale_3y"]],
        "exact_duplicates": [[slim(f) for f in g] for g in a["exact_dups"]],
        "version_sprawl": [[slim(f) for f in g] for g in a["sprawl"]],
        "empty_folders": [slim(f) for f in a["empty_folders"]],
        "taxonomy": a["taxonomy"],
    }
    with open(os.open(os.path.join(out, "findings.json"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as fh:
        json.dump(findings, fh, indent=1, default=str)

    pdf = None
    if args.pdf:
        pdf = render_pdf(report, os.path.join(out, "report.pdf"))
        if not pdf:
            print("No PDF: Chrome was not found or did not render. Open report.html and use "
                  "Print > Save as PDF - the report has print styles.", file=sys.stderr)
    print(console_summary(a, proof, started, out, pdf))
    return 0


if __name__ == "__main__":
    sys.exit(main())
