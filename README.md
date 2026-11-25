# SAML Reflector

A minimal SAML 2.0 service provider for federation troubleshooting. It initiates an SP-initiated sign-in, validates the returned response against the configured IdP signing certificate, and displays the Name ID, session index, and all returned attributes in an escaped HTML table.

The app does not save SAML responses or attributes. They can still contain personal or sensitive information, so run this only for trusted testers and restrict network access.

## Configure

Python 3.10+ and the `xmlsec1` system library are required by `python3-saml`. Install dependencies:

```sh
python3 -m pip install -r requirements.txt
```

Set these values using the IdP's federation configuration:

| Variable | Description |
| --- | --- |
| `IDP_ENTITY_ID` | IdP issuer/entity ID |
| `IDP_SSO_URL` | IdP HTTP-Redirect single sign-on URL |
| `IDP_CERT` | Path to the IdP signing certificate in PEM format |
| `PUBLIC_BASE_URL` | Public origin for this app, including any reverse-proxy path prefix; defaults to `https://localhost:5000` |
| `SECRET_KEY` | Optional stable Flask session-signing key; otherwise generated for this process |
| `PORT` | Optional local listening port; defaults to `5000` |

The IdP must trust the SP entity ID at `${PUBLIC_BASE_URL}/metadata` and send HTTP-POST responses to `${PUBLIC_BASE_URL}/acs`. Configure the IdP to sign assertions. SP-initiated login is at `/login`; SP metadata is at `/metadata`.

Run behind HTTPS, including during local testing, because the session cookie must accompany the cross-site SAML POST back to `/acs`. The built-in Flask server binds only to `127.0.0.1` and is for local diagnostics, not production hosting.

```sh
export IDP_ENTITY_ID='https://idp.example.org/entity'
export IDP_SSO_URL='https://idp.example.org/sso'
export IDP_CERT='/path/to/idp-signing-cert.pem'
export PUBLIC_BASE_URL='https://localhost:5000'
python3 app.py
```

Open `https://localhost:5000`, complete sign-in, and inspect the attribute table. A rejected or unsolicited response is not displayed as a successful sign-in; start a fresh SP-initiated flow after any failure.
