# Security

This document describes exactly what `drive-audit` can and cannot do, and how to check
each claim yourself. The program is one file of standard-library Python, written to be
read in a sitting: `drive_audit.py`.

## What it asks Google for

One OAuth scope: `https://www.googleapis.com/auth/drive.metadata.readonly` —
"View metadata for files in your Drive." Google classifies it as **restricted**. It
covers names, folders, owners, sharing settings, dates, sizes and checksums. It does
**not** cover file contents.

## How "cannot read your documents" is enforced

Each step is a check the program performs, not a promise it makes:

| Step | What happens | Where |
|---|---|---|
| Sign-in | Requests exactly one scope, with PKCE and a `state` check against forged redirects | `auth_url`, `validate_callback` |
| Storing | **Refuses to write a token** if Google granted anything other than exactly that scope | `validate_granted` |
| Each run | Mints an access token limited to the metadata scope, even from a broader grant | `mint_metadata_token` |
| Each run | Asks Google's `tokeninfo` endpoint what the token may do; stops unless the answer is exactly the metadata scope | `verify_scope_is_metadata_only` |
| **Before any scan** | **Tries to read a document's content and requires Google to refuse.** If the read succeeds, the run aborts before scanning and writes nothing | `prove_cannot_read_content` |
| Report | Prints that refusal — the HTTP status and Google's reason — at the top | `render_report` |

## Where data goes

- **Network:** only `accounts.google.com`, `oauth2.googleapis.com` and `www.googleapis.com`.
  No telemetry, no analytics, no third party.
- **The report** (`report.html`, `findings.json`, and `report.pdf` if requested) is written
  to the machine that ran it, mode `0600` in a `0700` directory. It contains file names
  and sharing details, so treat it as confidential.
- **The token** is stored mode `0600` in a `0700` directory (default
  `~/.config/drive-audit/token.json`). It can read metadata and nothing else.
- **The terminal** prints counts only, never a file name — enforced by a test — so an
  operator running the audit, person or automated agent, does not pull the Drive's
  contents into their own session.
- **PDF** rendering, when asked for, uses a local Chrome on a throwaway profile with
  background networking disabled. The report loads nothing external.

## Whose sign-in app

Because the scope is restricted, an OAuth app owned by anyone other than you would show
"Google hasn't verified this app" until it passed Google's restricted-scope review. The
supported setup is that **you create the app in your own Google Cloud project** —
Internal, for a Google Workspace organisation — and set its one scope yourself.
Google states that an Internal app's use of restricted scopes does not require further
review. No one outside your organisation holds a grant to your Drive.
Setup: [docs/oauth-setup.md](docs/oauth-setup.md).

## How to verify it yourself

1. **Read it.** One file, standard library only, no dependencies to audit.
2. **Read the report's first box.** It shows Google refusing the content read, with the reason.
3. **Watch the network.** Run it behind a proxy or an outbound firewall and confirm the
   only destinations are the three Google hosts above.
4. **Check the grant.** Your Google Account's security settings list the app and its one
   permission. Remove it when you are done.
5. **Run the tests.** `python3 -m unittest test_drive_audit.py` — none of them call Google.

## Reporting a problem

patrick@pi0.co. If you find a way for this program to read file contents, or to reach any
host other than the three above, that is a bug of the highest severity.
