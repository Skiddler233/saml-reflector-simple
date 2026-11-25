import binascii
import os
import secrets
from urllib.parse import urlparse

from flask import Flask, redirect, render_template_string, request, session
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.errors import OneLogin_Saml2_Error
from onelogin.saml2.settings import OneLogin_Saml2_Settings


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="None",
)

BASE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }} · SAML Reflector</title>
  <style>
    :root { color-scheme: light; font: 16px/1.5 system-ui, sans-serif; color: #172033; background: #f3f6fb; }
    body { margin: 0; }
    main { max-width: 920px; margin: 48px auto; padding: 0 20px; }
    .card { background: white; border: 1px solid #dce3ee; border-radius: 12px; padding: 28px; box-shadow: 0 8px 24px #1720330b; }
    h1 { margin: 0 0 8px; font-size: 1.65rem; }
    p { color: #4a5870; }
    .muted { color: #66748a; font-size: .92rem; }
    .button { display: inline-block; margin-top: 12px; padding: 10px 16px; border-radius: 7px; color: white; background: #155eef; text-decoration: none; font-weight: 650; }
    .button:hover { background: #104dcc; }
    .notice { margin: 20px 0; padding: 12px 14px; background: #fff8e6; border-left: 4px solid #e6a700; border-radius: 4px; }
    .error { background: #fff0f0; border-left-color: #d92d20; }
    table { width: 100%; border-collapse: collapse; margin: 18px 0 8px; table-layout: fixed; }
    th, td { padding: 11px 12px; text-align: left; vertical-align: top; border-bottom: 1px solid #e6eaf0; overflow-wrap: anywhere; }
    th { width: 34%; color: #344054; background: #f8fafc; }
    td { white-space: pre-wrap; }
    code { overflow-wrap: anywhere; }
    .tag { display: inline-block; padding: 2px 9px; border-radius: 99px; background: #e8f7ed; color: #176b36; font-size: .85rem; font-weight: 650; }
    footer { margin-top: 18px; }
  </style>
</head>
<body>
  <main>
    <section class="card">
      {{ content|safe }}
    </section>
  </main>
</body>
</html>
"""

HOME_CONTENT = """
<h1>SAML Reflector</h1>
<p>Start a sign-in with your configured identity provider, then inspect the attributes returned to this service provider.</p>
{% if configured %}
  <p><span class="tag">Configured</span></p>
  <a class="button" href="{{ url_for('login') }}">Start SAML sign-in</a>
  <p class="muted">SP metadata: <a href="{{ url_for('metadata') }}">{{ metadata_url }}</a></p>
{% else %}
  <div class="notice error"><strong>Setup required.</strong> Set <code>IDP_ENTITY_ID</code>, <code>IDP_SSO_URL</code>, and <code>IDP_CERT</code> as described in README.md.</div>
{% endif %}
<div class="notice"><strong>Diagnostic tool:</strong> returned attributes may contain personal or sensitive data. This app displays them in your browser and does not save SAML responses or attributes. Restrict access to trusted testers and use HTTPS.</div>
"""

RESULT_CONTENT = """
<h1>Sign-in result</h1>
{% if errors %}
  <div class="notice error"><strong>SAML response was rejected.</strong>
    <ul>{% for error in errors %}<li>{{ error }}</li>{% endfor %}</ul>
    {% if reason %}<p>{{ reason }}</p>{% endif %}
  </div>
{% else %}
  <p><span class="tag">Response validated</span></p>
  <table aria-label="SAML identity details">
    <tbody>
      <tr><th scope="row">Name ID</th><td>{{ name_id or "Not provided" }}</td></tr>
      <tr><th scope="row">Session index</th><td>{{ session_index or "Not provided" }}</td></tr>
      {% for name, values in attributes|dictsort %}
        <tr><th scope="row">{{ name }}</th><td>{% for value in values %}{{ value }}{% if not loop.last %}
{% endif %}{% endfor %}</td></tr>
      {% else %}
        <tr><th scope="row">Attributes</th><td>No attributes were returned.</td></tr>
      {% endfor %}
    </tbody>
  </table>
{% endif %}
<a class="button" href="{{ url_for('login') }}">Run another sign-in</a>
<footer><a href="{{ url_for('index') }}">Home</a></footer>
"""


def public_base_url():
    value = os.environ.get("PUBLIC_BASE_URL", "https://localhost:5000").rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.query or parsed.fragment:
        raise RuntimeError("PUBLIC_BASE_URL must be an absolute http(s) URL without a query or fragment.")
    return value, parsed


def saml_settings():
    base_url, parsed_base = public_base_url()
    idp_entity_id = os.environ.get("IDP_ENTITY_ID")
    idp_sso_url = os.environ.get("IDP_SSO_URL")
    idp_cert_path = os.environ.get("IDP_CERT")
    if not idp_entity_id or not idp_sso_url or not idp_cert_path:
        raise RuntimeError("Set IDP_ENTITY_ID, IDP_SSO_URL, and IDP_CERT before starting a SAML flow.")
    try:
        with open(idp_cert_path, encoding="utf-8") as cert_file:
            idp_cert = cert_file.read().strip()
    except OSError as exc:
        raise RuntimeError(f"Unable to read the IdP signing certificate at IDP_CERT: {exc}") from exc
    if not idp_cert:
        raise RuntimeError("The IdP signing certificate file is empty.")

    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": f"{base_url}/metadata",
            "assertionConsumerService": {
                "url": f"{base_url}/acs",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        },
        "idp": {
            "entityId": idp_entity_id,
            "singleSignOnService": {
                "url": idp_sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": idp_cert,
        },
        "security": {
            "authnRequestsSigned": False,
            "wantAssertionsSigned": True,
            "wantMessagesSigned": False,
            "wantAssertionsEncrypted": False,
        },
    }


def prepare_request_data():
    _, base = public_base_url()
    return {
        "https": "on" if base.scheme == "https" else "off",
        "http_host": base.netloc,
        "server_port": str(base.port or (443 if base.scheme == "https" else 80)),
        "script_name": request.path,
        "get_data": request.args.to_dict(flat=True),
        "post_data": request.form.to_dict(flat=True),
    }


def new_auth():
    settings = OneLogin_Saml2_Settings(saml_settings())
    return OneLogin_Saml2_Auth(prepare_request_data(), old_settings=settings)


def result_page(errors, reason=None, attributes=None, name_id=None, session_index=None):
    content = render_template_string(
        RESULT_CONTENT,
        errors=errors,
        reason=reason,
        attributes=attributes or {},
        name_id=name_id,
        session_index=session_index,
    )
    return (
        render_template_string(
            BASE_TEMPLATE, title="Rejected" if errors else "Result", content=content
        ),
        400 if errors else 200,
    )


@app.after_request
def prevent_sensitive_caching(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/")
def index():
    try:
        saml_settings()
        configured = True
        base_url, _ = public_base_url()
        metadata_url = f"{base_url}/metadata"
    except RuntimeError:
        configured = False
        metadata_url = ""
    content = render_template_string(
        HOME_CONTENT, configured=configured, metadata_url=metadata_url
    )
    return render_template_string(BASE_TEMPLATE, title="Home", content=content)


@app.get("/login")
def login():
    auth = new_auth()
    redirect_url = auth.login()
    request_id = auth.get_last_request_id()
    if not request_id:
        raise RuntimeError("The SAML toolkit did not create an authentication request ID.")
    session["saml_request_id"] = request_id
    return redirect(redirect_url)


@app.post("/acs")
def acs():
    request_id = session.pop("saml_request_id", None)
    if not request_id:
        return result_page(
            ["No matching sign-in request was found. Start a new sign-in and retry."]
        )
    if not request.form.get("SAMLResponse"):
        return result_page(["The SAML POST did not include a SAMLResponse."])

    auth = new_auth()
    try:
        auth.process_response(request_id=request_id)
    except binascii.Error:
        return result_page(
            ["SAMLResponse could not be decoded; verify it is Base64-encoded."]
        )
    except OneLogin_Saml2_Error as exc:
        return result_page([f"The SAML toolkit rejected the response: {exc}"])
    errors = auth.get_errors()
    reason = auth.get_last_error_reason()
    attributes = auth.get_attributes() if not errors else {}
    return result_page(
        errors,
        reason=reason,
        attributes=attributes,
        name_id=auth.get_nameid() if not errors else None,
        session_index=auth.get_session_index() if not errors else None,
    )


@app.get("/metadata")
def metadata():
    auth = new_auth()
    metadata_xml = auth.get_settings().get_sp_metadata()
    errors = auth.get_settings().validate_metadata(metadata_xml)
    if errors:
        return "Invalid SP metadata: " + ", ".join(errors), 500, {"Content-Type": "text/plain"}
    return metadata_xml, 200, {"Content-Type": "application/samlmetadata+xml"}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
