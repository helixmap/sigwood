"""Outbound TLS-setup surfacing from Zeek ssl.log.

The detector asks one question - does an outbound TLS session's setup look
unlike this estate's own norm? - over two measured legs, and delivers a fact
rather than a verdict.  It keeps row eligibility, pair aggregation, and
evidence derivation here; suppression, run-level disclosure, and rendering
belong to their respective owners.

Both legs are list-free and self-relative.  No fingerprint database, no
reputation lookup, and no cross-run state: the detector is batch and stateless,
so a first-ever session and a nightly one are measured the same way.
"""

from __future__ import annotations

import shlex
from datetime import datetime, timezone
from typing import Any

import numpy as np
import pandas as pd

from sigwood.common.finding import DetectorContext, Finding, MethodTag, Severity
from sigwood.common.topology import in_home_net, is_non_routable, parse_address

DETECTOR_NAME = "ssl"
STATUS = "available"
# Opt-in: the legs are calibrated against one estate, and default-hunt
# membership asks for a measured case across more than one.
IN_DEFAULT_HUNT: bool = False

REQUIRED_LOGS = [
    {"source": "zeek_dir", "pattern": "ssl*.log*"},
]

OPTIONAL_LOGS = [
    {"source": "zeek_dir", "pattern": "x509*.log*"},
]

DEFAULT_CONFIG = {
    "min_connections": 1,
}

DETECTOR_METHOD = MethodTag("heuristics", named=False)
DETECTOR_MISSION: str = (
    "Finds outbound TLS sessions whose setup looks unlike the rest of your "
    "estate's."
)

_SSL_PATTERN = "ssl*.log*"
_X509_PATTERN = "x509*.log*"

# The flow identity a finding cannot be made without. Every other canonical
# column is optional, and its absence retires the leg that reads it rather
# than failing the detector.
_REQUIRED_COLUMNS = ("ts", "src", "dst", "port")
_DEFAULT_HOME_NET = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

_LEG_SNI = "sni_absent"
_LEG_VALIDATION = "validation"

# Frozen calibration, not operator configuration.
_TUPLE_COLUMNS = ("version", "cipher", "curve", "alpn")
_NULL_TOKEN = "-"
_VALIDATION_OK = "ok"
_MIX_LIMIT = 3


def validate_config(cfg: dict) -> None:
    """Validate an overlaid ssl detector configuration without mutation."""
    if not isinstance(cfg, dict):
        raise ValueError("[detectors.ssl] must be a table")

    minimum = cfg.get("min_connections", DEFAULT_CONFIG["min_connections"])
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 1:
        raise ValueError(
            "[detectors.ssl].min_connections must be a positive integer"
        )


def _strict_bool(value: object, expected: bool) -> bool:
    """True iff ``value`` IS the boolean ``expected``.

    Truthiness is refused deliberately: an integer 1 or the string "T" is not a
    completed handshake, and reading one as a boolean would put a session in a
    leg on the strength of a coercion the sensor never made. numpy booleans are
    accepted because a bool-dtype column yields them.
    """
    if isinstance(value, (bool, np.bool_)):
        return bool(value) is expected
    return False


def _measured_status(value: object) -> str | None:
    """Return the stripped validation status, or None when it was not measured.

    A missing value is not a failed validation. Comparing an absent status
    against "ok" reads as unequal in pandas, which would fabricate a
    certificate-validation claim from a row that never carried one.
    """
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            return stripped
    return None


def _missing_columns(df: Any) -> tuple[str, ...]:
    """Return the required flow columns this frame does not carry."""
    if not isinstance(df, pd.DataFrame):
        return ()
    return tuple(c for c in _REQUIRED_COLUMNS if c not in df.columns)


def _empty_facts(**over: Any) -> dict[str, Any]:
    """The complete no-measurement fact shape, so a caller never reads a hole."""
    facts: dict[str, Any] = {
        "rows_total": 0,
        "rows_after_parse": 0,
        "rows_after_local": 0,
        "rows_dst_outside_home": 0,
        "rows_after_external": 0,
        "rows_eligible": 0,
        "cert_visible_rows": 0,
        "eligible_pairs": 0,
        "missing_columns": (),
    }
    facts.update(over)
    return facts


def _apply_eligibility(
    df: pd.DataFrame,
    home_net: list[str],
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Apply the ordered eligibility pipeline and return outbound rows.

    The ORDER decides correctness. Parsing precedes both direction gates because
    each of them fails open on an unparsable value: an unreadable destination is
    neither in home_net nor non-routable, so the two would compose into
    "external" and a finding would rest on a pair it could not read.
    """
    rows_total = len(df)
    if df.empty:
        return df.copy(), _empty_facts(rows_total=rows_total)

    missing = _missing_columns(df)
    if missing:
        return df.iloc[0:0].copy(), _empty_facts(
            rows_total=rows_total, missing_columns=missing,
        )

    prepared = df.copy()
    parsed_src = prepared["src"].map(parse_address)
    parsed_dst = prepared["dst"].map(parse_address)
    parse_mask = (parsed_src.notna() & parsed_dst.notna()).astype(bool)
    prepared = prepared[parse_mask]
    parsed_src = parsed_src[parse_mask]
    parsed_dst = parsed_dst[parse_mask]
    rows_after_parse = len(prepared)
    facts = _empty_facts(rows_total=rows_total, rows_after_parse=rows_after_parse)
    if prepared.empty:
        return prepared, facts

    local_mask = pd.Series(
        [in_home_net(address, home_net) for address in parsed_src],
        index=prepared.index,
    ).astype(bool)
    prepared = prepared[local_mask]
    parsed_dst = parsed_dst[local_mask]
    facts["rows_after_local"] = len(prepared)
    if prepared.empty:
        return prepared, facts

    # The destination gate is TWO facts, counted separately: a destination
    # inside home_net and a non-routable one are different reasons for an empty
    # run, and one sentence covering both tells an operator nothing they can act
    # on.
    outside_home = pd.Series(
        [not in_home_net(address, home_net) for address in parsed_dst],
        index=prepared.index,
    ).astype(bool)
    prepared = prepared[outside_home]
    parsed_dst = parsed_dst[outside_home]
    facts["rows_dst_outside_home"] = len(prepared)
    if prepared.empty:
        return prepared, facts

    routable = pd.Series(
        [not is_non_routable(address) for address in parsed_dst],
        index=prepared.index,
    ).astype(bool)
    prepared = prepared[routable]
    facts["rows_after_external"] = len(prepared)
    if prepared.empty:
        return prepared, facts

    ts_numeric = pd.to_numeric(prepared["ts"], errors="coerce")
    finite_mask = (ts_numeric.notna() & np.isfinite(ts_numeric)).astype(bool)
    prepared = prepared[finite_mask]
    facts["rows_eligible"] = len(prepared)
    if prepared.empty:
        return prepared, facts

    if "cert_fp" in prepared.columns:
        facts["cert_visible_rows"] = int(prepared["cert_fp"].notna().sum())
    facts["eligible_pairs"] = int(
        prepared[["src", "dst"]].drop_duplicates().shape[0]
    )
    return prepared, facts


def eligibility(df: Any, home_net: list[str] | None = None) -> dict[str, Any]:
    """Report the eligibility funnel without raising, for run-level disclosure.

    Defensive by contract: any unexpected input yields the complete
    no-measurement shape rather than an exception, because the runner calls this
    outside per-detector containment.
    """
    try:
        if not isinstance(df, pd.DataFrame):
            return _empty_facts()
        _, facts = _apply_eligibility(df, list(home_net or _DEFAULT_HOME_NET))
        return facts
    except Exception:  # pragma: no cover - defensive
        return _empty_facts()


def _leg_masks(frame: pd.DataFrame) -> tuple[pd.Series, pd.Series]:
    """Return the (sni-absent, validation) row masks for eligible rows."""
    index = frame.index
    false_mask = pd.Series(False, index=index)

    if {"established", "resumed", "sni"} <= set(frame.columns):
        sni_mask = (
            frame["established"].map(lambda v: _strict_bool(v, True))
            & frame["resumed"].map(lambda v: _strict_bool(v, False))
            & frame["sni"].isna()
        ).astype(bool)
    else:
        sni_mask = false_mask

    if {"cert_fp", "validation_status"} <= set(frame.columns):
        status = frame["validation_status"].map(_measured_status)
        validation_mask = (
            frame["cert_fp"].notna()
            & status.notna()
            & (status != _VALIDATION_OK)
        ).astype(bool)
    else:
        validation_mask = false_mask

    return sni_mask, validation_mask


def _tuple_series(frame: pd.DataFrame) -> pd.Series:
    """Render the (version, cipher, curve, alpn) tuple per row.

    A null renders as a token rather than being skipped, so a tuple carrying an
    unnegotiated parameter stays selectable and comparable against its peers.
    """
    parts = []
    for column in _TUPLE_COLUMNS:
        if column in frame.columns:
            series = frame[column]
            parts.append(series.where(series.notna(), _NULL_TOKEN).astype(str))
        else:
            parts.append(pd.Series(_NULL_TOKEN, index=frame.index))
    joined = parts[0]
    for part in parts[1:]:
        joined = joined + "|" + part
    return joined


def _mode_lexical(values: pd.Series) -> str | None:
    """The most frequent value, ties broken by the smallest lexical key.

    Input ORDER never decides: two values at the same count resolve the same way
    whichever arrived first.
    """
    if values.empty:
        return None
    counts = values.value_counts()
    top = counts.max()
    return min(str(v) for v, c in counts.items() if c == top)


def _ranked_mix(values: pd.Series, limit: int = _MIX_LIMIT) -> str:
    """Render the largest categories, count descending then key ascending."""
    counts = values.value_counts()
    ranked = sorted(counts.items(), key=lambda item: (-item[1], str(item[0])))
    return ", ".join(f"{key} ({count})" for key, count in ranked[:limit])


def _count_map(values: pd.Series) -> dict[str, int]:
    """A key-sorted count map, stable across input orderings."""
    counts = values.value_counts()
    return {str(k): int(v) for k, v in sorted(counts.items(), key=lambda i: str(i[0]))}


def _finite_ts_bounds(frame: pd.DataFrame) -> tuple[str | None, str | None, float | None]:
    """Finite timestamp bounds and span, or all None when unmeasurable.

    The zero epoch is a valid instant, so callers test identity against None
    rather than truthiness.
    """
    numeric = pd.to_numeric(frame["ts"], errors="coerce")
    numeric = numeric[numeric.notna() & np.isfinite(numeric)]
    if numeric.empty:
        return None, None, None
    first = float(numeric.min())
    last = float(numeric.max())
    return (
        datetime.fromtimestamp(first, tz=timezone.utc).isoformat(),
        datetime.fromtimestamp(last, tz=timezone.utc).isoformat(),
        last - first,
    )


def _finite(value: object) -> float | None:
    """A finite float, or None - so an unmeasured input never reads as zero."""
    numeric = pd.to_numeric(pd.Series([value]), errors="coerce").iloc[0]
    if pd.isna(numeric) or not np.isfinite(numeric):
        return None
    return float(numeric)


def _certificate_facts(
    fingerprint: str,
    first_use_ts: float | None,
    x509: pd.DataFrame | None,
) -> dict[str, Any]:
    """The five certificate facts for one fingerprint, or none of them.

    All five or nothing: a partial set invites a reader to compare certificates
    on a fact some of them silently lack.
    """
    if x509 is None or x509.empty or "fingerprint" not in x509.columns:
        return {}
    rows = x509[x509["fingerprint"] == fingerprint]
    if rows.empty or "ts" not in rows.columns:
        return {}
    # The representative is the EARLIEST row, so a row without a finite instant
    # cannot be ordered and cannot be chosen. Dropping them before the sort is
    # what keeps "earliest" a measurement rather than an artifact of input
    # order; with none left there is no representative and no fact to emit.
    order = pd.to_numeric(rows["ts"], errors="coerce")
    finite = (order.notna() & np.isfinite(order)).astype(bool)
    rows = rows[finite]
    if rows.empty:
        return {}
    rows = rows.assign(_order=order[finite]).sort_values("_order", kind="stable")
    row = rows.iloc[0]

    not_before = _finite(row.get("not_valid_before"))
    not_after = _finite(row.get("not_valid_after"))
    key_length = _finite(row.get("key_length"))
    key_alg = row.get("key_alg")
    self_signed = row.get("self_signed")

    if (
        not_before is None
        or not_after is None
        or key_length is None
        or not isinstance(key_alg, str)
        or not isinstance(self_signed, (bool, np.bool_))
        or first_use_ts is None
    ):
        return {}

    return {
        "cert_validity_days": round((not_after - not_before) / 86400.0, 1),
        "cert_key_alg": key_alg,
        "cert_key_length": int(key_length),
        "cert_self_signed": bool(self_signed),
        "cert_age_at_first_use_days": round((first_use_ts - not_before) / 86400.0, 1),
    }


def _severity_for(
    sni_fired: bool,
    validation_fired: bool,
) -> tuple[Severity, list[str]]:
    """The ladder, owned once: severity and basis are returned TOGETHER.

    Returning both from one call is what keeps them from drifting - a caller
    that built its own basis and asked only for a severity could disagree with
    the ladder and nothing would notice.

    One leg is a single evidence category and caps at LOW. Two legs are
    independent categories - client behavior and server infrastructure - and
    earn MEDIUM. HIGH is unreachable here by construction: it belongs to a
    corroborator that weighs evidence this detector does not hold.
    """
    basis: list[str] = []
    if sni_fired:
        basis.append(_LEG_SNI)
    if validation_fired:
        basis.append(_LEG_VALIDATION)
    severity = Severity.MEDIUM if len(basis) == 2 else Severity.LOW
    return severity, basis


def _pair_next_steps(src: str) -> list[str]:
    """Build pair pivots, local first, with ONE literal command.

    The destination-ownership lookup is prose rather than a second command
    deliberately: it would send the address to a third party, which is the
    operator's call to make, not a line for them to paste without reading.
    Every log-derived value in the retained command is quoted at composition,
    so a hostile value is inert in a shell rather than merely unlikely.
    """
    return [
        "Identify the local host and the software making the connection",
        "Review the other sessions this host opened to the same destination: "
        "zeek-cut id.orig_h id.resp_h server_name validation_status < ssl.log | "
        f"grep {shlex.quote(str(src))}",
        "Check who owns the destination address before treating it as unexpected",
        "Add an expected recurring pair to the allowlist",
    ]


def _pair_description(basis: list[str], status: str | None) -> str:
    """State what was observed, and the population a certificate fact covers.

    The measured status rides the sentence it qualifies: "did not validate" on
    its own withholds the one fact that tells an expired certificate from a
    self-signed one.

    The population disclosure names the MECHANISM that bounds it rather than a
    number measured elsewhere. TLS 1.3 encrypts the certificate message, so a
    session that presented a visible certificate negotiated something older -
    true wherever this runs, checkable by the reader, and it survives an
    estate whose protocol mix is nothing like the one the legs were calibrated
    against. It rides the leg-B sentence as a trailing clause so a two-leg
    finding stays within the two-sentence description shape.
    """
    sentences = []
    if _LEG_SNI in basis:
        sentences.append(
            "Established TLS sessions from this host to this external address "
            "carried no server name indication and were not resumptions."
        )
    if _LEG_VALIDATION in basis:
        qualifier = f" ({status})" if status else ""
        sentences.append(
            "The server certificate presented to this host did not "
            f"validate{qualifier}; because TLS 1.3 encrypts the certificate, "
            "these facts cover only the sessions that presented one."
        )
    return " ".join(sentences)


def _pair_finding(
    src: str,
    dst: str,
    evidence: dict[str, Any],
    basis: list[str],
    severity: Severity,
    context: DetectorContext,
) -> Finding:
    """Build one pair finding from its single measurement."""
    return Finding(
        detector=DETECTOR_NAME,
        severity=severity,
        title=f"{src} → {dst}",
        description=_pair_description(basis, evidence.get("validation_status")),
        evidence=evidence,
        next_steps=_pair_next_steps(src),
        ts_generated=datetime.now(tz=timezone.utc),
        data_window=context.data_window,
    )


def run(context: DetectorContext) -> list[Finding]:
    """Surface outbound TLS sessions whose setup is unlike the estate's norm."""
    df = context.logs.get(_SSL_PATTERN)
    if df is None or not isinstance(df, pd.DataFrame) or df.empty:
        return []

    home_net = list(context.home_net or _DEFAULT_HOME_NET)
    cfg = context.config or {}
    minimum = cfg.get("min_connections", DEFAULT_CONFIG["min_connections"])

    prepared, _facts = _apply_eligibility(df, home_net)
    if prepared.empty:
        return []

    # The tuple share's denominator is every loaded row in the window, so the
    # tuple series is built once over the whole frame and sliced per pair.
    window_tuples = _tuple_series(df)
    window_counts = window_tuples.value_counts()
    window_total = len(df)

    x509 = context.logs.get(_X509_PATTERN)
    sni_mask, validation_mask = _leg_masks(prepared)
    flagged = (sni_mask | validation_mask).astype(bool)
    if not bool(flagged.any()):
        return []

    findings: list[Finding] = []
    for (src, dst), group in prepared.groupby(["src", "dst"], sort=True):
        pair_flagged = flagged.loc[group.index]
        if not bool(pair_flagged.any()):
            continue
        legs = group[pair_flagged]
        if len(legs) < minimum:
            continue

        group_sni = sni_mask.loc[group.index]
        group_validation = validation_mask.loc[group.index]
        severity, basis = _severity_for(
            bool(group_sni.any()), bool(group_validation.any()),
        )

        first_seen, last_seen, span = _finite_ts_bounds(legs)
        pair_tuple = _mode_lexical(window_tuples.loc[group.index])
        evidence: dict[str, Any] = {
            "src": str(src),
            "dst": str(dst),
            "severity_basis": basis,
            "conn_count": int(len(legs)),
            "leg_a_count": int(group_sni.sum()),
            "leg_b_count": int(group_validation.sum()),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "span_seconds": span,
        }

        if pair_tuple is not None:
            evidence["tuple"] = pair_tuple
            evidence["tuple_share"] = (
                round(float(window_counts.get(pair_tuple, 0)) / window_total, 6)
                if window_total
                else None
            )

        if "version" in group.columns:
            evidence["tls_versions"] = _count_map(
                group["version"].where(group["version"].notna(), _NULL_TOKEN)
            )
        if "port" in group.columns:
            evidence["port_mix"] = _ranked_mix(
                group["port"].where(group["port"].notna(), _NULL_TOKEN).astype(str)
            )
        if "alpn" in group.columns:
            evidence["alpn_mix"] = _ranked_mix(
                group["alpn"].where(group["alpn"].notna(), _NULL_TOKEN).astype(str)
            )
        if "cert_fp" in group.columns:
            evidence["cert_visible_share"] = round(
                float(group["cert_fp"].notna().sum()) / len(group), 4
            )

        validation_rows = group[group_validation]
        if not validation_rows.empty:
            statuses = validation_rows["validation_status"].map(_measured_status)
            statuses = statuses[statuses.notna()]
            evidence["validation_status"] = _mode_lexical(statuses)
            evidence["validation_mix"] = _count_map(statuses)

            fingerprints = validation_rows["cert_fp"].dropna()
            if not fingerprints.empty:
                evidence["cert_count"] = int(fingerprints.nunique())
                representative = _mode_lexical(fingerprints.astype(str))
                if representative is not None:
                    own = validation_rows[
                        validation_rows["cert_fp"].astype(str) == representative
                    ]
                    first_use, _last, _span = _finite_ts_bounds(own)
                    first_use_ts = (
                        pd.to_numeric(own["ts"], errors="coerce").min()
                        if not own.empty
                        else None
                    )
                    evidence.update(
                        _certificate_facts(
                            representative,
                            _finite(first_use_ts),
                            x509,
                        )
                    )

        findings.append(
            _pair_finding(str(src), str(dst), evidence, basis, severity, context)
        )

    # Severity implements __lt__ with HIGH first, so it sorts directly; volume
    # then the pair break ties, and the pair makes the order total.
    findings.sort(
        key=lambda f: (
            f.severity,
            -f.evidence["conn_count"],
            f.evidence["src"],
            f.evidence["dst"],
        )
    )
    return findings
