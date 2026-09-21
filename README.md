# drive-audit

**A Google Drive audit that never opens a file.** It maps a Drive from metadata
alone — names, folders, owners, sharing, dates, sizes — and writes a report that
answers four questions:

- **Who can see what.** Files shared with anyone who has the link, with people outside
  your domain, or with another organisation — and, more usefully, **the handful of
  sharing settings those files inherit from**, because a shared folder passes its
  permission to everything inside it. Fixing the settings fixes the files.
- **What has gone stale.** Everything by last change, and what nobody has opened.
- **Who your files depend on.** Owners and last editors, by domain.
- **Where the duplication and sprawl are.** Exact duplicates (and the storage they
  waste), version sprawl, empty folders, and what is sitting in the trash.

Every number states how many files it could assess and why the rest could not be.

## The guarantee is enforced, not promised

The audit cannot read the contents of your documents, and every report proves it:

1. It holds a Google token limited to `drive.metadata.readonly` — nothing else.
2. It asks Google, not itself, what that token may do, and stops if the answer is wider.
3. **Before scanning anything, it tries to open a document.** Google must refuse. If
   Google ever allows it, the audit stops before scanning and writes nothing.
4. That refusal is printed at the top of the report, so anyone can check it.

The report stays on the machine that ran it, readable only by you. The terminal shows
counts, never file names. The only network traffic is to Google. See [SECURITY.md](SECURITY.md).

## You own the Google sign-in

`drive.metadata.readonly` is a *restricted* Google scope, so an app owned by someone
else would show you "Google hasn't verified this app". Instead **you create the sign-in
app in your own Google account** and set its one permission yourself. For a Google
Workspace organisation, an Internal app needs no Google review. Nobody outside your
organisation ever holds access to your Drive.

It is a one-time setup: **[docs/oauth-setup.md](docs/oauth-setup.md)**.

## Run it

Python 3.12 or newer. No packages to install. Tested on macOS and Linux.

```bash
# 1. once: sign in with the app you created, and store a metadata-only token
python3 drive_audit.py auth --client-secrets client_secret.json

# 2. the audit
python3 drive_audit.py run
python3 drive_audit.py run --pdf                               # also write a PDF (needs Chrome)
python3 drive_audit.py run --taxonomy taxonomy/business.json   # group by a category profile
```

Reports land in `./drive-audit-reports/<date>_<time ET>/` as `report.html` and
`findings.json`. Open the HTML in any browser; its print styles make **Print → Save as
PDF** clean if you would rather not use `--pdf`.

**On a machine with no browser** (a server, a small box on your network): sign in over
an SSH tunnel.

```bash
python3 drive_audit.py auth --client-secrets client_secret.json --port 8765 --no-browser
# from your laptop:  ssh -L 8765:127.0.0.1:8765 <that-machine>   then open the printed URL
```

When you are finished, you can remove the app's access from your Google Account's
security settings, under third-party connections.

## What it cannot tell you

It reads metadata, so it can say a file exists, who can reach it and when it last
changed — not what it says. Specifically:

- **Duplicates** are proven by checksum, which Google keeps only for uploaded files, not
  native Google Docs and Sheets. Duplication among those shows up as version sprawl, a
  signal to look at rather than proof.
- **Sharing** is hidden on files you can view but not manage, so they are counted, not assessed.
- **Grouping by name** (the taxonomy profile) works well on document-heavy Drives and
  poorly on photo-heavy ones, whose file names carry no subject words.
- **Google Drive only.** A Microsoft 365 version is planned, not built.

## Taxonomy profiles

General by default. `--taxonomy` takes a JSON of `{category: [keywords]}` matched
against file and folder names. `taxonomy/business.json` is a generic starting point.

## Tests

```bash
python3 -m unittest test_drive_audit.py
```

No test talks to Google. The sign-in flow is tested end to end against a local loopback
server with a simulated browser, including a forged redirect that must be refused.
