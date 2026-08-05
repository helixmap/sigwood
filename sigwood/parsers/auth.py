"""Pure authentication and authorization decision grammar extraction.

The extractor consumes the canonical syslog ``message`` and ``program`` fields.
It returns only grammar-derived facts; row timestamps, hosts, aggregation, and
detector policy remain outside this module.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum

from sigwood.parsers.syslog import strip_program


class AuthOutcome(StrEnum):
    """Outcome stated by one recognized access-decision grammar."""

    GRANTED = "granted"
    DENIED = "denied"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True, slots=True)
class AuthDecision:
    """Grammar-derived authentication or authorization observation."""

    outcome: AuthOutcome
    gate: str
    actor: str | None = None
    actor_namespace: str | None = None
    target: str | None = None
    source: str | None = None
    auid: str | None = None
    terminal: str | None = None
    exe: str | None = None
    audit_type: str | None = None
    res: str | None = None
    session: str | None = None
    serial: str | None = None

    @property
    def is_eligible_decision(self) -> bool:
        """Return whether the observation states a grant or denial."""
        return self.outcome is not AuthOutcome.INDETERMINATE


_RECOGNIZED_PROGRAMS = frozenset(
    {
        "sshd",
        "sshd-session",
        "sshd(pam_unix)",
        "dropbear",
        "sudo",
        "su",
        "runuser",
        "kscreenlocker_greet",
        "gdm-password]",
        "--",
        "audisp-syslog",
        "audit",
    }
)

_GATE_TOKENS = frozenset(
    {"sshd", "dropbear", "sudo", "su", "runuser", "login", "audit"}
)
_PAM_GATES = frozenset({"sshd", "dropbear", "sudo", "su", "runuser"})
_IDENTITY_SENTINELS = frozenset({"?", "(unknown)", "4294967295"})


def is_recognized_program(program: str) -> bool:
    """Return whether ``program`` may reach an authentication grammar."""
    return program in _RECOGNIZED_PROGRAMS

_IDENTITY = r'(?P<{name}>"[^"]+"|\S+)'
_SOURCE_TOKEN = r"(?P<source>\[[^\]]+\](?::\d+)?|[0-9A-Fa-f:.]+)"

_SSH_ACCEPT_RE = re.compile(
    rf"^Accepted (?:password|publickey) for "
    rf"{_IDENTITY.format(name='actor')} from (?P<source>\S+) "
    r"port \d+(?:\s+.*)?$"
)
_SSH_FAILED_INVALID_RE = re.compile(
    rf"^Failed password for invalid user {_IDENTITY.format(name='actor')} "
    r"from (?P<source>\S+) port \d+(?:\s+.*)?$"
)
_SSH_FAILED_RE = re.compile(
    rf"^Failed password for {_IDENTITY.format(name='actor')} "
    r"from (?P<source>\S+) port \d+(?:\s+.*)?$"
)
_SSH_INVALID_RE = re.compile(
    rf"^Invalid user {_IDENTITY.format(name='actor')} "
    r"from (?P<source>\S+) port \d+(?:\s+.*)?$"
)
_SSH_MAX_ATTEMPTS_RE = re.compile(
    rf"^error: maximum authentication attempts exceeded for "
    rf"{_IDENTITY.format(name='actor')} from (?P<source>\S+)"
    r"(?: port \d+)?(?:\s+.*)?$"
)
_SSH_CLOSED_RE = re.compile(
    rf"^Connection closed by {_SOURCE_TOKEN}(?: port \d+)?"
    r"(?: \[preauth\])?$"
)
_SSH_KEX_RE = re.compile(
    rf"^error: kex_exchange_identification: Connection closed by "
    rf"{_SOURCE_TOKEN}(?: port \d+)?(?: \[preauth\])?$"
)

_DROPBEAR_EXIT_RE = re.compile(
    r"^Exit before auth from <(?P<source>[^>\s]+)>:(?:\s+.*)?$"
)
_DROPBEAR_CHILD_RE = re.compile(r"^Child connection from (?P<source>\S+)$")
_DROPBEAR_SUCCESS_RE = re.compile(
    rf"^Pubkey auth succeeded for {_IDENTITY.format(name='actor')} "
    r"(?:with key \S+ )?from (?P<source>\S+)(?:\s+.*)?$"
)

_PAM_SESSION_RE = re.compile(
    rf"^pam_unix\((?P<service>sudo|su|runuser):session\): "
    rf"session (?P<state>opened|closed) for user "
    rf"(?P<target>\"[^\"]+\"|[^\s(]+)(?:\(uid=\d+\))?"
    rf"(?: by (?:(?P<actor>\"[^\"]+\"|\S+))?\(uid=\d+\))?$"
)
_PAM_AUTH_RE = re.compile(
    r"^pam_unix\((?P<service>[^:()]+):auth\): "
    r"authentication failure;(?P<fields>.*)$"
)
_LEGACY_PAM_AUTH_RE = re.compile(
    r"^authentication failure;(?P<fields>.*)$"
)
_LEGACY_PAM_MORE_RE = re.compile(
    r"^\d+ more authentication failures;(?P<fields>.*)$"
)
_MODERN_PAM_MORE_RE = re.compile(
    r"^PAM \d+ more authentication failures;(?P<fields>.*)$"
)
_SUDO_PREFIX_RE = re.compile(
    rf"^{_IDENTITY.format(name='actor')}\s*:\s*(?P<body>.*)$"
)
_SUDO_PASSWORD_RE = re.compile(r"^\d+ incorrect password attempts$")
_FAILED_SU_RE = re.compile(
    rf"^FAILED SU \(to {_IDENTITY.format(name='target')}\) "
    rf"{_IDENTITY.format(name='actor')} on (?P<terminal>\S+)$"
)
_SU_GRANT_RE = re.compile(
    rf"^\(to {_IDENTITY.format(name='target')}\) "
    rf"{_IDENTITY.format(name='actor')} on (?P<terminal>\S+)$"
)
_ROOT_LOGIN_RE = re.compile(
    rf"^-- {_IDENTITY.format(name='actor')}\[\*\]: "
    r"ROOT LOGIN ON (?P<terminal>\S+)$"
)

_AUDIT_A_TYPES = frozenset(
    {
        "USER_AUTH",
        "USER_ERR",
        "USER_LOGIN",
        "USER_START",
        "USER_END",
        "USER_ACCT",
        "USER_CMD",
        "USER_ROLE_CHANGE",
        "CRED_ACQ",
        "CRED_DISP",
    }
)
_AUDIT_A_HEAD_RE = re.compile(r"^type=(?P<audit_type>[A-Z_]+)\b")
_AUDIT_B_HEAD_RE = re.compile(
    r"^(?P<audit_type>AUDIT\d+|BPF|SERVICE_START|SERVICE_STOP|"
    r"NETFILTER_CFG|MAC_POLICY_LOAD|SYSCALL)\b"
)
_AUDIT_EVENT_RE = re.compile(
    r"(?:^|\s)msg=audit\([^:)]*:(?P<serial>[^)]+)\):?"
)
_NESTED_MSG_RE = re.compile(r"(?:^|\s)msg='(?P<payload>[^']*)'")
_FIELD_RE = re.compile(
    r"(?<!\S)(?P<key>[A-Za-z_][\w-]*)="
    r"(?P<value>\"[^\"]*\"|'[^']*'|\S*)"
)
_INLINE_FIELD_RE = re.compile(r"(?P<key>[A-Za-z_][\w-]*)=(?P<value>\S*)")


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    return value or None


def _identity(value: str | None) -> str | None:
    candidate = _clean(value)
    if candidate in _IDENTITY_SENTINELS:
        return None
    return candidate


def _address_from_endpoint(value: str | None) -> str | None:
    token = _identity(value)
    if token is None:
        return None
    try:
        ipaddress.ip_address(token)
    except ValueError:
        pass
    else:
        return token

    bracketed = re.fullmatch(r"\[(?P<address>[^\]]+)\]:(?P<port>\d+)", token)
    if bracketed is not None:
        return bracketed.group("address")
    if token.count(":") == 1:
        address, port = token.rsplit(":", 1)
        if address and port.isdigit():
            return address
    return token


def _required_ip_from_endpoint(value: str | None) -> str | None:
    address = _address_from_endpoint(value)
    if address is None:
        return None
    try:
        ipaddress.ip_address(address)
    except ValueError:
        return None
    return address


def _with_identity(decision: AuthDecision) -> AuthDecision | None:
    if decision.actor is None and decision.target is None and decision.source is None:
        return None
    return decision


def _text_decision(
    outcome: AuthOutcome,
    gate: str,
    *,
    actor: str | None = None,
    actor_namespace: str | None = None,
    target: str | None = None,
    source: str | None = None,
    terminal: str | None = None,
) -> AuthDecision | None:
    clean_actor = _identity(actor)
    return _with_identity(
        AuthDecision(
            outcome=outcome,
            gate=gate,
            actor=clean_actor,
            actor_namespace=actor_namespace if clean_actor is not None else None,
            target=_identity(target),
            source=_address_from_endpoint(source),
            terminal=_clean(terminal),
        )
    )


def _extract_sshd(body: str) -> AuthDecision | None:
    match = _SSH_ACCEPT_RE.fullmatch(body)
    if match is not None:
        return _text_decision(
            AuthOutcome.GRANTED,
            "sshd",
            actor=match.group("actor"),
            actor_namespace="unix_user",
            source=match.group("source"),
        )

    match = _SSH_FAILED_INVALID_RE.fullmatch(body)
    if match is not None:
        return _text_decision(
            AuthOutcome.DENIED,
            "sshd",
            actor=match.group("actor"),
            actor_namespace="preauth_username",
            source=match.group("source"),
        )

    match = _SSH_FAILED_RE.fullmatch(body)
    if match is not None:
        return _text_decision(
            AuthOutcome.DENIED,
            "sshd",
            actor=match.group("actor"),
            actor_namespace="unix_user",
            source=match.group("source"),
        )

    match = _SSH_INVALID_RE.fullmatch(body)
    if match is not None:
        return _text_decision(
            AuthOutcome.INDETERMINATE,
            "sshd",
            actor=match.group("actor"),
            actor_namespace="preauth_username",
            source=match.group("source"),
        )

    match = _SSH_MAX_ATTEMPTS_RE.fullmatch(body)
    if match is not None:
        return _text_decision(
            AuthOutcome.DENIED,
            "sshd",
            actor=match.group("actor"),
            actor_namespace="unix_user",
            source=match.group("source"),
        )

    for pattern in (_SSH_CLOSED_RE, _SSH_KEX_RE):
        match = pattern.fullmatch(body)
        if match is not None:
            source = _required_ip_from_endpoint(match.group("source"))
            if source is None:
                return None
            return _text_decision(
                AuthOutcome.INDETERMINATE,
                "sshd",
                source=source,
            )
    return None


def _extract_dropbear(body: str) -> AuthDecision | None:
    match = _DROPBEAR_SUCCESS_RE.fullmatch(body)
    if match is not None:
        return _text_decision(
            AuthOutcome.GRANTED,
            "dropbear",
            actor=match.group("actor"),
            actor_namespace="unix_user",
            source=match.group("source"),
        )
    match = _DROPBEAR_EXIT_RE.fullmatch(body)
    if match is not None:
        source = _required_ip_from_endpoint(match.group("source"))
        if source is None:
            return None
        return _text_decision(
            AuthOutcome.INDETERMINATE,
            "dropbear",
            source=source,
        )
    match = _DROPBEAR_CHILD_RE.fullmatch(body)
    if match is not None:
        return _text_decision(
            AuthOutcome.INDETERMINATE,
            "dropbear",
            source=match.group("source"),
        )
    return None


def _extract_pam_session(body: str) -> AuthDecision | None:
    match = _PAM_SESSION_RE.fullmatch(body)
    if match is None:
        return None
    actor = _clean(match.group("actor"))
    return _text_decision(
        AuthOutcome.GRANTED
        if match.group("state") == "opened"
        else AuthOutcome.INDETERMINATE,
        match.group("service"),
        actor=actor,
        actor_namespace="unix_user" if actor is not None else None,
        target=match.group("target"),
    )


def _extract_pam_auth(
    body: str,
    *,
    services: frozenset[str] = _PAM_GATES,
) -> AuthDecision | None:
    match = _PAM_AUTH_RE.fullmatch(body)
    if match is None or match.group("service") not in services:
        return None
    values = {
        field.group("key"): field.group("value")
        for field in _INLINE_FIELD_RE.finditer(match.group("fields"))
    }
    return _text_decision(
        AuthOutcome.DENIED,
        match.group("service"),
        actor=values.get("user"),
        actor_namespace="unix_user",
        source=values.get("rhost"),
    )


def _extract_legacy_pam_auth(body: str) -> AuthDecision | None:
    match = _LEGACY_PAM_AUTH_RE.fullmatch(body)
    if match is None:
        return None
    values = {
        field.group("key"): field.group("value")
        for field in _INLINE_FIELD_RE.finditer(match.group("fields"))
    }
    return _text_decision(
        AuthOutcome.DENIED,
        "sshd",
        actor=values.get("user"),
        actor_namespace="unix_user",
        source=values.get("rhost"),
    )


def _semicolon_fields(body: str) -> tuple[str, dict[str, str]]:
    parts = [part.strip() for part in body.split(";")]
    preamble = parts[0] if "=" not in parts[0] else ""
    values: dict[str, str] = {}
    for part in parts:
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        values.setdefault(key.strip(), value.strip())
    return preamble, values


def _extract_sudo(body: str) -> AuthDecision | None:
    match = _SUDO_PREFIX_RE.fullmatch(body)
    if match is None:
        return None
    preamble, values = _semicolon_fields(match.group("body"))
    actor = match.group("actor")
    terminal = values.get("TTY")
    if preamble == "user NOT in sudoers" or _SUDO_PASSWORD_RE.fullmatch(preamble):
        return _text_decision(
            AuthOutcome.DENIED,
            "sudo",
            actor=actor,
            actor_namespace="unix_user",
            terminal=terminal,
        )
    if "USER" not in values or "COMMAND" not in values:
        return None
    return _text_decision(
        AuthOutcome.GRANTED,
        "sudo",
        actor=actor,
        actor_namespace="unix_user",
        target=values["USER"],
        terminal=terminal,
    )


def _extract_failed_su(body: str) -> AuthDecision | None:
    match = _FAILED_SU_RE.fullmatch(body)
    if match is None:
        return None
    return _text_decision(
        AuthOutcome.DENIED,
        "su",
        actor=match.group("actor"),
        actor_namespace="unix_user",
        target=match.group("target"),
        terminal=match.group("terminal"),
    )


def _extract_su_grant(body: str) -> AuthDecision | None:
    match = _SU_GRANT_RE.fullmatch(body)
    if match is None:
        return None
    return _text_decision(
        AuthOutcome.GRANTED,
        "su",
        actor=match.group("actor"),
        actor_namespace="unix_user",
        target=match.group("target"),
        terminal=match.group("terminal"),
    )


def _extract_root_login(body: str) -> AuthDecision | None:
    match = _ROOT_LOGIN_RE.fullmatch(body)
    if match is None:
        return None
    return _text_decision(
        AuthOutcome.GRANTED,
        "login",
        actor=match.group("actor"),
        actor_namespace="unix_user",
        terminal=match.group("terminal"),
    )


def _parse_fields(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for match in _FIELD_RE.finditer(text):
        if match.group("key") == "msg":
            continue
        result.setdefault(match.group("key"), match.group("value"))
    return result


def _audit_fields(text: str) -> tuple[dict[str, str], str | None]:
    nested = _NESTED_MSG_RE.search(text)
    payload = nested.group("payload") if nested is not None else ""
    outer_text = text
    if nested is not None:
        outer_text = f"{text[:nested.start()]} {text[nested.end():]}"

    outer = _parse_fields(outer_text)
    inner = _parse_fields(payload)
    merged = dict(inner)
    merged.update(outer)
    event = _AUDIT_EVENT_RE.search(text)
    return merged, _clean(event.group("serial")) if event is not None else None


def _audit_outcome(res: str | None) -> AuthOutcome:
    if res == "success":
        return AuthOutcome.GRANTED
    if res == "failed":
        return AuthOutcome.DENIED
    return AuthOutcome.INDETERMINATE


def _audit_decision(
    fields: dict[str, str],
    *,
    audit_type: str,
    serial: str | None,
) -> AuthDecision | None:
    acct = _identity(fields.get("acct"))
    auid = _clean(fields.get("auid"))
    actor_auid = _identity(fields.get("auid"))
    actor = acct if acct is not None else actor_auid
    namespace = (
        "unix_user"
        if acct is not None
        else "unix_auid"
        if auid is not None
        else None
    )
    res = _clean(fields.get("res"))
    return _with_identity(
        AuthDecision(
            outcome=_audit_outcome(res),
            gate="audit",
            actor=actor,
            actor_namespace=namespace,
            source=_address_from_endpoint(fields.get("addr")),
            auid=auid,
            terminal=_clean(fields.get("terminal") or fields.get("tty")),
            exe=_clean(fields.get("exe")),
            audit_type=audit_type,
            res=res,
            session=_clean(fields.get("session") or fields.get("ses")),
            serial=serial,
        )
    )


def _extract_audit_a(body: str) -> AuthDecision | None:
    head = _AUDIT_A_HEAD_RE.match(body)
    if head is None or head.group("audit_type") not in _AUDIT_A_TYPES:
        return None
    values, serial = _audit_fields(body)
    return _audit_decision(
        values,
        audit_type=head.group("audit_type"),
        serial=serial,
    )


def _extract_audit_b(body: str) -> AuthDecision | None:
    head = _AUDIT_B_HEAD_RE.match(body)
    if head is None:
        return None
    values, serial = _audit_fields(body)
    if "res" not in values:
        return None
    return _audit_decision(
        values,
        audit_type=head.group("audit_type"),
        serial=serial,
    )


def _extract_known(message: str, program: str) -> AuthDecision | None:
    body = strip_program(message)
    if program in {"sshd", "sshd-session"}:
        return _extract_sshd(body) or _extract_pam_auth(body)
    if program == "sshd(pam_unix)":
        return _extract_legacy_pam_auth(body)
    if program == "dropbear":
        return _extract_dropbear(body) or _extract_pam_auth(body)
    if program == "sudo":
        return _extract_pam_session(body) or _extract_pam_auth(body) or _extract_sudo(body)
    if program == "su":
        return (
            _extract_pam_session(body)
            or _extract_pam_auth(body)
            or _extract_su_grant(body)
            or _extract_failed_su(body)
        )
    if program == "runuser":
        return (
            _extract_pam_session(body)
            or _extract_pam_auth(body)
            or _extract_failed_su(body)
        )
    if program == "kscreenlocker_greet":
        return _extract_pam_auth(body, services=frozenset({"kde"}))
    if program == "gdm-password]":
        return _extract_pam_auth(body, services=frozenset({"gdm-password"}))
    if program == "--":
        return _extract_root_login(body)
    if program == "audisp-syslog":
        return _extract_audit_a(body)
    if program == "audit":
        return _extract_audit_b(body)
    return None


def _extract_untagged(_message: str) -> AuthDecision | None:
    return None


def extract_decision(message: str, *, program: str) -> AuthDecision | None:
    """Extract one access-decision observation from a canonical syslog message.

    ``None`` means no frozen grammar matched. An indeterminate decision means an
    authentication exchange was observed but its outcome was not established.
    """
    if program == "unknown":
        return _extract_untagged(message)
    if not is_recognized_program(program):
        return None
    return _extract_known(message, program)
