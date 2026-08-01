"""Unit tests for sigwood.parsers.cloudtrail.parse_event.

Pure-function tests: no I/O, no DataFrames, no fixtures on disk. Every event is
built with the ``_event()`` helper so each test states only the field(s) it is
about. All values are synthetic per the privacy rail - RFC 5737 IPs only, AWS
documentation account ``123456789012``, and obvious-placeholder names.
"""

from __future__ import annotations

from sigwood.parsers.cloudtrail import parse_event


_DOCS_ACCOUNT = "123456789012"  # AWS documentation account id


def _event(**overrides) -> dict:
    """Build a minimal valid CloudTrail event dict with field overrides.

    Defaults model a single benign IAMUser GetObject call. Override anything you
    want to vary; everything else stays sane. Pass ``userIdentity={...}`` to
    replace the whole identity stanza, or use a nested key like
    ``userIdentity_type="AssumedRole"`` for shorthand isn't supported - give the
    full dict.
    """
    base: dict = {
        "eventTime":       "2026-06-01T12:00:00Z",
        "eventSource":     "s3.amazonaws.com",
        "eventName":       "GetObject",
        "eventID":         "11111111-1111-1111-1111-111111111111",
        "awsRegion":       "us-east-1",
        "sourceIPAddress": "192.0.2.10",
        "userIdentity": {
            "type":        "IAMUser",
            "userName":    "placeholder-user",
            "principalId": "AIDAEXAMPLE",
            "arn":         f"arn:aws:iam::{_DOCS_ACCOUNT}:user/placeholder-user",
        },
        "readOnly": True,
    }
    base.update(overrides)
    return base


# ── principal derivation ──────────────────────────────────────────────────────

def test_principal_assumed_role_uses_session_issuer_user_name() -> None:
    event = _event(userIdentity={
        "type":        "AssumedRole",
        "principalId": "AROAEXAMPLE:session-alpha",
        "arn":         f"arn:aws:sts::{_DOCS_ACCOUNT}:assumed-role/placeholder-role/session-alpha",
        "sessionContext": {
            "sessionIssuer": {
                "type":        "Role",
                "principalId": "AROAEXAMPLE",
                "userName":    "placeholder-role",
                "arn":         f"arn:aws:iam::{_DOCS_ACCOUNT}:role/placeholder-role",
            },
        },
    })
    assert parse_event(event)["principal"] == "placeholder-role"


def test_principal_assumed_role_falls_back_to_arn_last_segment_when_no_username() -> None:
    event = _event(userIdentity={
        "type":        "AssumedRole",
        "principalId": "AROAEXAMPLE:session-alpha",
        "sessionContext": {
            "sessionIssuer": {
                "type":        "Role",
                "principalId": "AROAEXAMPLE",
                "arn":         f"arn:aws:iam::{_DOCS_ACCOUNT}:role/placeholder-role",
                # userName intentionally omitted
            },
        },
    })
    assert parse_event(event)["principal"] == "placeholder-role"


def test_principal_assumed_role_is_stable_across_sessions_of_same_role() -> None:
    """Required: two events from different sessions of one role aggregate together."""
    issuer = {
        "type":        "Role",
        "principalId": "AROAEXAMPLE",
        "userName":    "placeholder-role",
        "arn":         f"arn:aws:iam::{_DOCS_ACCOUNT}:role/placeholder-role",
    }
    session_one = _event(userIdentity={
        "type":           "AssumedRole",
        "principalId":    "AROAEXAMPLE:session-alpha",
        "arn":            f"arn:aws:sts::{_DOCS_ACCOUNT}:assumed-role/placeholder-role/session-alpha",
        "sessionContext": {"sessionIssuer": issuer},
    })
    session_two = _event(userIdentity={
        "type":           "AssumedRole",
        "principalId":    "AROAEXAMPLE:session-beta",
        "arn":            f"arn:aws:sts::{_DOCS_ACCOUNT}:assumed-role/placeholder-role/session-beta",
        "sessionContext": {"sessionIssuer": issuer},
    })
    p1 = parse_event(session_one)["principal"]
    p2 = parse_event(session_two)["principal"]
    assert p1 == p2 == "placeholder-role"
    # Session name must never become the key.
    assert "session-alpha" not in p1 and "session-beta" not in p2


def test_principal_iam_user_uses_user_name() -> None:
    event = _event(userIdentity={
        "type":        "IAMUser",
        "userName":    "placeholder-user",
        "principalId": "AIDAEXAMPLE",
        "arn":         f"arn:aws:iam::{_DOCS_ACCOUNT}:user/placeholder-user",
    })
    assert parse_event(event)["principal"] == "placeholder-user"


def test_principal_iam_user_falls_back_to_arn_last_segment() -> None:
    event = _event(userIdentity={
        "type":        "IAMUser",
        "principalId": "AIDAEXAMPLE",
        "arn":         f"arn:aws:iam::{_DOCS_ACCOUNT}:user/arn-derived-name",
        # userName intentionally omitted
    })
    assert parse_event(event)["principal"] == "arn-derived-name"


def test_principal_aws_service_uses_invoked_by() -> None:
    event = _event(userIdentity={
        "type":      "AWSService",
        "invokedBy": "ec2.amazonaws.com",
    })
    assert parse_event(event)["principal"] == "ec2.amazonaws.com"


def test_principal_root_returns_root_literal() -> None:
    event = _event(userIdentity={
        "type":        "Root",
        "principalId": _DOCS_ACCOUNT,
        "arn":         f"arn:aws:iam::{_DOCS_ACCOUNT}:root",
    })
    assert parse_event(event)["principal"] == "root"


def test_principal_federated_user_falls_back_to_principal_id() -> None:
    event = _event(userIdentity={
        "type":        "FederatedUser",
        "principalId": f"{_DOCS_ACCOUNT}:placeholder-federated",
    })
    assert parse_event(event)["principal"] == f"{_DOCS_ACCOUNT}:placeholder-federated"


def test_principal_saml_user_falls_back_to_principal_id() -> None:
    event = _event(userIdentity={
        "type":        "SAMLUser",
        "principalId": "SAMLEXAMPLE:placeholder-saml",
    })
    assert parse_event(event)["principal"] == "SAMLEXAMPLE:placeholder-saml"


def test_principal_missing_user_identity_returns_unknown_without_raising() -> None:
    event = _event()
    event.pop("userIdentity")
    assert parse_event(event)["principal"] == "unknown"


def test_principal_non_dict_user_identity_returns_unknown_without_raising() -> None:
    event = _event(userIdentity="not-a-dict")
    assert parse_event(event)["principal"] == "unknown"


def test_principal_distinct_principal_ids_under_unknown_type_stay_distinct() -> None:
    event_a = _event(userIdentity={"type": "FutureUnknownType", "principalId": "AAA-EXAMPLE"})
    event_b = _event(userIdentity={"type": "FutureUnknownType", "principalId": "BBB-EXAMPLE"})
    assert parse_event(event_a)["principal"] == "AAA-EXAMPLE"
    assert parse_event(event_b)["principal"] == "BBB-EXAMPLE"
    assert parse_event(event_a)["principal"] != parse_event(event_b)["principal"]


# ── lane derivation ───────────────────────────────────────────────────────────

def _lane_for_assumed_role_invoked_by(invoked_by: str) -> str:
    """Return the lane from the invokedBy rule without another service shortcut."""
    event = _event(userIdentity={
        "type":      "AssumedRole",
        "invokedBy": invoked_by,
        "sessionContext": {"sessionIssuer": {
            "type":     "Role",
            "userName": "placeholder-role",
        }},
    })
    return parse_event(event)["lane"]


def test_lane_aws_service_type_is_service() -> None:
    event = _event(userIdentity={"type": "AWSService", "invokedBy": "lambda.amazonaws.com"})
    assert parse_event(event)["lane"] == "service"


def test_lane_aws_account_type_is_service() -> None:
    event = _event(userIdentity={"type": "AWSAccount", "principalId": "EXAMPLEACCT"})
    assert parse_event(event)["lane"] == "service"


def test_lane_invoked_by_amazonaws_com_is_service() -> None:
    event = _event(userIdentity={
        "type":      "AssumedRole",
        "invokedBy": "config.amazonaws.com",
        "sessionContext": {"sessionIssuer": {
            "type":     "Role",
            "userName": "placeholder-role",
        }},
    })
    assert parse_event(event)["lane"] == "service"


def test_lane_invoked_by_requires_dns_label_boundary() -> None:
    assert _lane_for_assumed_role_invoked_by(
        "not-a-host/amazonaws.com"
    ) == "interactive"


def test_lane_invoked_by_accepts_exact_and_dot_bounded_service_names() -> None:
    for invoked_by in (
        "ec2.amazonaws.com",
        "cloudtrail.amazonaws.com",
        "amazonaws.com",
    ):
        assert _lane_for_assumed_role_invoked_by(invoked_by) == "service"


def test_lane_invoked_by_comparison_is_case_sensitive() -> None:
    assert _lane_for_assumed_role_invoked_by(
        "Ec2.AmazonAWS.Com"
    ) == "interactive"


def test_lane_service_role_in_arn_is_service() -> None:
    event = _event(userIdentity={
        "type":        "AssumedRole",
        "principalId": "AROAEXAMPLE:session-x",
        "arn": (
            f"arn:aws:sts::{_DOCS_ACCOUNT}:assumed-role/"
            "AWSServiceRoleForPlaceholder/session-x"
        ),
    })
    assert parse_event(event)["lane"] == "service"


def test_lane_service_role_in_session_issuer_arn_is_service() -> None:
    event = _event(userIdentity={
        "type":        "AssumedRole",
        "principalId": "AROAEXAMPLE:session-x",
        "arn":         f"arn:aws:sts::{_DOCS_ACCOUNT}:assumed-role/innocuous/session-x",
        "sessionContext": {"sessionIssuer": {
            "type": "Role",
            "arn":  f"arn:aws:iam::{_DOCS_ACCOUNT}:role/aws-service-role/AWSServiceRoleForExample",
        }},
    })
    assert parse_event(event)["lane"] == "service"


def test_lane_plain_iam_user_is_interactive() -> None:
    assert parse_event(_event())["lane"] == "interactive"


def test_lane_human_assumed_role_is_interactive() -> None:
    event = _event(userIdentity={
        "type":        "AssumedRole",
        "principalId": "AROAEXAMPLE:session-x",
        "arn":         f"arn:aws:sts::{_DOCS_ACCOUNT}:assumed-role/placeholder-role/session-x",
        "sessionContext": {"sessionIssuer": {
            "type":     "Role",
            "userName": "placeholder-role",
            "arn":      f"arn:aws:iam::{_DOCS_ACCOUNT}:role/placeholder-role",
        }},
    })
    assert parse_event(event)["lane"] == "interactive"


def test_lane_root_is_interactive() -> None:
    event = _event(userIdentity={
        "type":        "Root",
        "principalId": _DOCS_ACCOUNT,
        "arn":         f"arn:aws:iam::{_DOCS_ACCOUNT}:root",
    })
    assert parse_event(event)["lane"] == "interactive"


# ── read_write derivation ─────────────────────────────────────────────────────

def test_read_write_boolean_true_is_read() -> None:
    assert parse_event(_event(readOnly=True))["read_write"] == "read"


def test_read_write_boolean_false_is_write() -> None:
    assert parse_event(_event(readOnly=False))["read_write"] == "write"


def test_read_write_string_true_is_read() -> None:
    assert parse_event(_event(readOnly="true"))["read_write"] == "read"


def test_read_write_string_false_is_write() -> None:
    assert parse_event(_event(readOnly="false"))["read_write"] == "write"


def test_read_write_absent_get_verb_is_read() -> None:
    event = _event(eventName="GetCallerIdentity")
    event.pop("readOnly")
    assert parse_event(event)["read_write"] == "read"


def test_read_write_absent_list_verb_is_read() -> None:
    event = _event(eventName="ListBuckets")
    event.pop("readOnly")
    assert parse_event(event)["read_write"] == "read"


def test_read_write_absent_put_verb_is_write() -> None:
    event = _event(eventName="PutObject")
    event.pop("readOnly")
    assert parse_event(event)["read_write"] == "write"


def test_read_write_absent_delete_verb_is_write() -> None:
    event = _event(eventName="DeleteBucket")
    event.pop("readOnly")
    assert parse_event(event)["read_write"] == "write"


def test_read_write_absent_run_instances_is_write() -> None:
    event = _event(eventName="RunInstances")
    event.pop("readOnly")
    assert parse_event(event)["read_write"] == "write"


def test_read_write_absent_empty_event_name_is_write() -> None:
    event = _event(eventName="")
    event.pop("readOnly")
    assert parse_event(event)["read_write"] == "write"


# ── ts derivation ─────────────────────────────────────────────────────────────

def test_ts_valid_event_time_parses_to_epoch_float() -> None:
    event = _event(eventTime="2026-06-01T12:00:00Z")
    ts = parse_event(event)["ts"]
    assert isinstance(ts, float)
    # 2026-06-01T12:00:00Z is well past the unix epoch; specific value documented
    # via fromisoformat reproducibility, not magic-numbered here.
    from datetime import datetime
    expected = datetime.fromisoformat("2026-06-01T12:00:00+00:00").timestamp()
    assert ts == expected


def test_ts_missing_event_time_is_none() -> None:
    event = _event()
    event.pop("eventTime")
    assert parse_event(event)["ts"] is None


def test_ts_garbage_event_time_is_none() -> None:
    event = _event(eventTime="not-a-timestamp")
    assert parse_event(event)["ts"] is None


# ── Carried fields ────────────────────────────────────────────────────────────

_ALL_KEYS = {
    "ts", "principal", "lane", "read_write",
    "event_source", "event_name", "identity_type",
    "source_ip", "error_code", "aws_region", "event_id", "raw",
}


def test_every_row_has_all_twelve_canonical_keys() -> None:
    row = parse_event(_event())
    assert set(row.keys()) == _ALL_KEYS


def test_error_code_is_none_on_success_events() -> None:
    # Default fixture has no errorCode key - success path.
    assert parse_event(_event())["error_code"] is None


def test_error_code_carried_when_present() -> None:
    assert parse_event(_event(errorCode="AccessDenied"))["error_code"] == "AccessDenied"


def test_event_source_carried_verbatim_no_suffix_strip() -> None:
    # The full suffix is part of the analyst's pivot - never strip "amazonaws.com".
    assert parse_event(_event(eventSource="s3.amazonaws.com"))["event_source"] == "s3.amazonaws.com"


def test_carried_fields_pass_through_unchanged() -> None:
    row = parse_event(_event())
    assert row["event_name"]    == "GetObject"
    assert row["identity_type"] == "IAMUser"
    assert row["source_ip"]     == "192.0.2.10"
    assert row["aws_region"]    == "us-east-1"
    assert row["event_id"]      == "11111111-1111-1111-1111-111111111111"


def test_raw_holds_original_event_dict() -> None:
    event = _event(extraField="future-detector-fodder")
    row = parse_event(event)
    assert row["raw"] is event
    assert row["raw"]["extraField"] == "future-detector-fodder"


def test_identity_type_none_when_user_identity_missing() -> None:
    event = _event()
    event.pop("userIdentity")
    assert parse_event(event)["identity_type"] is None


def test_identity_type_none_when_user_identity_not_dict() -> None:
    assert parse_event(_event(userIdentity=42))["identity_type"] is None


# ── Defensive non-dict input ──────────────────────────────────────────────────

def test_parse_event_returns_none_for_non_dict_input() -> None:
    assert parse_event(None) is None
    assert parse_event("string") is None
    assert parse_event([{"eventName": "GetObject"}]) is None
    assert parse_event(42) is None
