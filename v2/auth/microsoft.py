"""Microsoft Entra ID OpenID Connect helpers."""

import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable

import msal


_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_VALID_AUTH_MODES = {"magic_link", "hybrid", "microsoft"}


@dataclass(frozen=True)
class MicrosoftAuthConfig:
    auth_mode: str
    tenant_id: str
    client_id: str
    redirect_uri: str
    client_credential: Any
    max_auth_age_seconds: int

    @property
    def microsoft_enabled(self) -> bool:
        return self.auth_mode in {"hybrid", "microsoft"}

    @property
    def magic_link_enabled(self) -> bool:
        return self.auth_mode in {"magic_link", "hybrid"}

    @property
    def authority(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}"


def load_config(public_base_url: str, production: bool) -> MicrosoftAuthConfig:
    """Load and validate authentication settings without exposing credentials."""
    auth_mode = os.getenv("AUTH_MODE", "magic_link").strip().lower()
    if auth_mode not in _VALID_AUTH_MODES:
        raise RuntimeError("AUTH_MODE must be magic_link, hybrid, or microsoft.")

    tenant_id = os.getenv("ENTRA_TENANT_ID", "").strip()
    client_id = os.getenv("ENTRA_CLIENT_ID", "").strip()
    redirect_uri = os.getenv("ENTRA_REDIRECT_URI", "").strip()
    if not redirect_uri and public_base_url:
        redirect_uri = f"{public_base_url.rstrip('/')}/auth/microsoft/callback"

    private_key = os.getenv("ENTRA_CLIENT_CERTIFICATE_PRIVATE_KEY", "").replace("\\n", "\n").strip()
    thumbprint = os.getenv("ENTRA_CLIENT_CERTIFICATE_THUMBPRINT", "").strip()
    client_secret = os.getenv("ENTRA_CLIENT_SECRET", "").strip()
    if private_key and thumbprint:
        credential: Any = {"private_key": private_key, "thumbprint": thumbprint}
    else:
        credential = client_secret

    try:
        max_auth_age = int(os.getenv("ENTRA_MAX_AUTH_AGE_SECONDS", "3600"))
    except ValueError as exc:
        raise RuntimeError("ENTRA_MAX_AUTH_AGE_SECONDS must be an integer.") from exc
    if max_auth_age < 300 or max_auth_age > 28800:
        raise RuntimeError("ENTRA_MAX_AUTH_AGE_SECONDS must be between 300 and 28800.")

    if auth_mode in {"hybrid", "microsoft"}:
        if not _GUID_RE.fullmatch(tenant_id):
            raise RuntimeError("ENTRA_TENANT_ID must be the MLFA tenant GUID.")
        if not _GUID_RE.fullmatch(client_id):
            raise RuntimeError("ENTRA_CLIENT_ID must be the sign-in application GUID.")
        if not credential:
            raise RuntimeError("A Microsoft sign-in client credential must be configured.")
        if not redirect_uri:
            raise RuntimeError("ENTRA_REDIRECT_URI or APP_BASE_URL must be configured.")
        if production and not redirect_uri.startswith("https://"):
            raise RuntimeError("The production Microsoft redirect URI must use HTTPS.")

    return MicrosoftAuthConfig(
        auth_mode=auth_mode,
        tenant_id=tenant_id,
        client_id=client_id,
        redirect_uri=redirect_uri,
        client_credential=credential,
        max_auth_age_seconds=max_auth_age,
    )


def build_client(config: MicrosoftAuthConfig):
    """Create a tenant-specific confidential MSAL client."""
    return msal.ConfidentialClientApplication(
        client_id=config.client_id,
        authority=config.authority,
        client_credential=config.client_credential,
        exclude_scopes=["offline_access"],
    )


def start_flow(config: MicrosoftAuthConfig) -> Dict[str, Any]:
    """Create a state-, nonce-, and PKCE-protected authorization-code flow."""
    return build_client(config).initiate_auth_code_flow(
        scopes=["email"],
        redirect_uri=config.redirect_uri,
        max_age=config.max_auth_age_seconds,
    )


def complete_flow(
    config: MicrosoftAuthConfig,
    flow: Dict[str, Any],
    auth_response: Dict[str, str],
) -> Dict[str, Any]:
    """Validate the callback and return the verified ID-token claims."""
    result = build_client(config).acquire_token_by_auth_code_flow(
        flow,
        auth_response,
        scopes=["email"],
    )
    claims = result.get("id_token_claims")
    if not isinstance(claims, dict):
        raise ValueError("Microsoft did not return a valid identity token.")

    tenant_id = str(claims.get("tid") or "")
    if tenant_id.lower() != config.tenant_id.lower():
        raise ValueError("The identity token came from an unauthorized tenant.")
    if not _GUID_RE.fullmatch(str(claims.get("oid") or "")):
        raise ValueError("The identity token is missing an immutable user ID.")
    return claims


def claim_email_candidates(claims: Dict[str, Any]) -> Iterable[str]:
    """Return plausible login addresses for first-time OID binding."""
    seen = set()
    for key in ("email", "preferred_username", "upn"):
        value = str(claims.get(key) or "").strip().lower()
        if not value or "@" not in value or "#ext#" in value or value in seen:
            continue
        seen.add(value)
        yield value
