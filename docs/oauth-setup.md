# Create your own sign-in app (once)

`drive-audit` signs in to Google with an app **you** own, so no one outside your
organisation ever holds access to your Drive. You need a Google account with access to
the [Google Cloud console](https://console.cloud.google.com). On a Google Workspace
domain, you may need an administrator for step 3.

Menu names below follow Google's documentation as of September 2026. Google renames
these screens from time to time; if one has moved, search the console for the name.

## 1. Pick or create a project

In the Google Cloud console, choose a project from the selector at the top, or create
one. It holds nothing but this sign-in app.

## 2. Enable the Google Drive API

**APIs & Services → Library** → search for **Google Drive API** → **Enable**.

## 3. Describe the app and choose who can use it

**Google Auth platform → Branding**: give the app a name (for example, *Drive audit*)
and a support email.

Then **Audience**:

- **Google Workspace organisation — choose Internal.** Only people in your organisation
  can sign in, and Google states that an Internal app's use of restricted scopes does
  not require further review. There is no "unverified app" warning.
- **Personal Gmail account — choose External**, leave it in testing, and add your own
  address as a test user. Google will show an "unverified app" screen when you sign in:
  that is Google describing the app you just created yourself. A testing app is fine for
  a one-off audit.

## 4. Allow exactly one permission

**Data Access → Add or Remove Scopes** → add

```
https://www.googleapis.com/auth/drive.metadata.readonly
```

and nothing else → **Save**. This is the ceiling: the app can never ask for more than
you set here. (`drive-audit` also refuses to store a token that grants anything else.)

## 5. Create the client and download it

**Google Auth platform → Clients → Create Client** → **Application type: Desktop app** →
give it a name → **Create**. Download the client's JSON file from its details and save
it as `client_secret.json` next to `drive_audit.py`.

It must be a **Desktop app** client: `drive-audit` signs in through a one-time address on
your own machine (`127.0.0.1`), which is how Desktop clients work. If you choose another
type, `drive-audit` will say so and stop.

Keep `client_secret.json` out of shared folders and version control.

## 6. Sign in

```bash
python3 drive_audit.py auth --client-secrets client_secret.json
```

A browser opens, you sign in and approve, and the token is stored at
`~/.config/drive-audit/token.json`, readable only by you. Then:

```bash
python3 drive_audit.py run
```

## If something goes wrong

- **"this is a 'web' OAuth client"** — recreate the client as **Desktop app** (step 5).
- **"Google granted … not exactly [drive.metadata.readonly]"** — the app has more than one
  scope. Remove the extras under **Data Access** (step 4) and sign in again.
- **"Google returned no refresh token"** — remove the app's access in your Google Account's
  security settings, under third-party connections, then sign in again.
- **Your administrator blocks the sign-in** — some Workspace domains restrict API access in
  the Admin console. An administrator can allow the app you created.
