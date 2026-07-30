"""The primitives every other module trusts without re-checking.

``meaf.model`` sits at the bottom of the dependency stack, so a wrong answer
here is not reported as a wrong answer here: it surfaces as a gate that allowed
a deployment. The currency predicate is the sharpest case. Appendix A.5 states
it as a two-conjunct calendar test but qualifies it, in the sentences either
side of the formula, with artifact binding. An implementation that treats
binding as a separate advisory check still produces a package that validates,
still produces a gate result, and still allows a deployment whose evidence
describes a system that no longer exists. These tests therefore assert each
conjunct in isolation and assert their precedence over one another.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from meaf.model import (
    Currency,
    TimestampError,
    component_digests,
    digest_algorithm,
    evidence_currency,
    evidence_is_fresh,
    index_by_id,
    layer_number,
    objects,
    parse_date,
    parse_datetime,
    parse_duration,
    role_ids,
    subject_digests_for,
    unique_index,
)

from tests.conftest import FROZEN_NOW

#: A digest that appears in no example package, standing in for the artifact
#: that is actually deployed after a component was replaced.
SUPERSEDED_SUBJECT = "sha256:" + "0" * 64
DEPLOYED_SUBJECT = "sha256:" + "1" * 64


def evidence_item(**overrides) -> dict:
    """A minimal evidence item that is current at FROZEN_NOW, before overrides."""
    item = {
        "id": "ev-under-test",
        "class": "deterministic-observation",
        "subject-digests": [DEPLOYED_SUBJECT],
        "collected-at": "2026-07-15T00:00:00Z",
        "max-age": "P30D",
        "invalidated-at": None,
        "result": "pass",
    }
    item.update(overrides)
    return item


# --------------------------------------------------------------------------
# parse_duration
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("duration", "seconds"),
    [
        ("P30D", 30 * 86400.0),
        ("P0D", 0.0),
        ("PT12H", 12 * 3600.0),
        ("PT90M", 90 * 60.0),
        ("PT45S", 45.0),
        ("PT0S", 0.0),
        ("P1DT2H3M4S", 86400.0 + 7200.0 + 180.0 + 4.0),
        ("PT1M30S", 90.0),
    ],
)
def test_parse_duration_reads_the_day_hour_minute_and_second_designators(duration, seconds):
    assert parse_duration(duration) == seconds


def test_parse_duration_keeps_fractional_seconds():
    # Cadences are coarse, but an evidence max-age is compared against a
    # difference of two timestamps; truncating here would round a stale item
    # back inside its window.
    assert parse_duration("PT1.5S") == 1.5


@pytest.mark.parametrize("duration", ["P", "PT"])
def test_parse_duration_rejects_a_designator_with_no_quantity(duration):
    # "P" and "PT" match the shape of a duration while stating no length. A
    # zero-second reading would make every evidence item instantly stale; a
    # forever reading would make every evidence item permanently fresh. Neither
    # is a defensible guess, so the input is refused.
    with pytest.raises(TimestampError):
        parse_duration(duration)


@pytest.mark.parametrize(
    "duration",
    [
        "",
        "30D",  # missing the leading designator
        "P1W",  # weeks are outside the supported subset
        "P1Y",  # years are calendar-dependent and therefore not accepted
        "PT1S1M",  # components out of order
        "P30d",  # designators are case-sensitive
        "PT1.5H",  # fractions are permitted on seconds only
    ],
)
def test_parse_duration_rejects_malformed_input(duration):
    with pytest.raises(TimestampError):
        parse_duration(duration)


@pytest.mark.parametrize("value", [None, 30, 30.0, ["P30D"], {"days": 30}])
def test_parse_duration_rejects_non_strings(value):
    # A JSON package can carry any type in the max-age slot; a number here must
    # not be silently coerced into a unit nobody declared.
    with pytest.raises(TimestampError):
        parse_duration(value)


# --------------------------------------------------------------------------
# parse_datetime and parse_date
# --------------------------------------------------------------------------


def test_parse_datetime_accepts_the_z_suffix():
    assert parse_datetime("2026-07-15T00:00:00Z") == datetime(
        2026, 7, 15, 0, 0, tzinfo=timezone.utc
    )


def test_parse_datetime_normalizes_an_explicit_offset_to_utc():
    # Two collectors in different time zones must produce comparable ages.
    assert parse_datetime("2026-07-15T02:00:00+02:00") == datetime(
        2026, 7, 15, 0, 0, tzinfo=timezone.utc
    )
    assert parse_datetime("2026-07-14T19:00:00-05:00") == datetime(
        2026, 7, 15, 0, 0, tzinfo=timezone.utc
    )


def test_parse_datetime_treats_a_naive_timestamp_as_utc():
    parsed = parse_datetime("2026-07-15T00:00:00")
    assert parsed.tzinfo is timezone.utc
    assert parsed == datetime(2026, 7, 15, 0, 0, tzinfo=timezone.utc)


def test_parse_datetime_always_returns_an_aware_utc_datetime():
    # Downstream code subtracts these from an injected `now`; a naive result
    # would raise at the subtraction rather than at the parse.
    assert parse_datetime("2026-07-15T02:00:00+02:00").utcoffset() == timedelta(0)


@pytest.mark.parametrize(
    "value", ["", "2026-07-15T25:00:00Z", "yesterday", "15/07/2026", "2026-13-01T00:00:00Z"]
)
def test_parse_datetime_rejects_malformed_timestamps(value):
    with pytest.raises(TimestampError):
        parse_datetime(value)


@pytest.mark.parametrize("value", [None, 20260715, ["2026-07-15T00:00:00Z"]])
def test_parse_datetime_rejects_non_strings(value):
    with pytest.raises(TimestampError):
        parse_datetime(value)


def test_parse_date_reads_a_calendar_date():
    assert parse_date("2026-07-15").isoformat() == "2026-07-15"


@pytest.mark.parametrize(
    "value",
    ["2026-07-15T00:00:00Z", "2026-07-15T00:00:00", "2026-07-15 00:00:00"],
)
def test_parse_date_rejects_a_value_carrying_a_time_component(value):
    # A finding due-date and an exception expiry are calendar facts. Accepting a
    # timestamp there would make "expires on the 15th" mean different instants
    # in different time zones, which is exactly the ambiguity A.5's coherence
    # check exists to remove.
    with pytest.raises(TimestampError):
        parse_date(value)


@pytest.mark.parametrize("value", [None, 20260715, ["2026-07-15"]])
def test_parse_date_rejects_non_strings(value):
    with pytest.raises(TimestampError):
        parse_date(value)


# --------------------------------------------------------------------------
# layer_number and digest_algorithm
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("node", "expected"),
    [
        ("L1:biased-generation", 1),
        ("L2:corpus-retrieval", 2),
        ("L5:locally-benign-evaluation", 5),
        ("L7:user-or-institutional-decision", 7),
        ("L3:a", 3),
    ],
)
def test_layer_number_reads_the_maestro_layer_of_a_node(node, expected):
    assert layer_number(node) == expected


@pytest.mark.parametrize(
    "node",
    [
        "",
        "L0:zero-layer",  # MAESTRO has seven layers, numbered from one
        "L8:eighth-layer",
        "L1",  # a layer with no node label is not a node
        "L1:",
        "l1:lowercase-prefix",
        "L1:Uppercase-Node",
        "L1:-leading-hyphen",
        "L1:has spaces",
        "1:no-prefix",
    ],
)
def test_layer_number_returns_none_for_a_malformed_node(node):
    # None rather than an exception: level 3 wants to report every malformed
    # node in the package, not stop at the first one.
    assert layer_number(node) is None


@pytest.mark.parametrize("value", [None, 1, ["L1:node"]])
def test_layer_number_returns_none_for_non_strings(value):
    assert layer_number(value) is None


@pytest.mark.parametrize(
    ("digest", "expected"),
    [
        ("sha256:" + "a" * 64, "sha256"),
        ("sha384:" + "b" * 96, "sha384"),
        ("sha512:" + "c" * 128, "sha512"),
    ],
)
def test_digest_algorithm_reads_the_algorithm_prefix(digest, expected):
    assert digest_algorithm(digest) == expected


@pytest.mark.parametrize(
    "digest",
    [
        "",
        "a" * 64,  # no algorithm named at all
        "md5:" + "a" * 32,  # an algorithm outside the recognised set
        "sha256:",
        "sha256:" + "A" * 64,  # hex digits are lower-case
        "sha256:" + "z" * 64,
        "sha256:REPLACE_WITH_ATTESTED_DIGEST",
    ],
)
def test_digest_algorithm_returns_none_for_a_malformed_digest(digest):
    assert digest_algorithm(digest) is None


@pytest.mark.parametrize("value", [None, 256, ["sha256:" + "a" * 64]])
def test_digest_algorithm_returns_none_for_non_strings(value):
    assert digest_algorithm(value) is None


# --------------------------------------------------------------------------
# objects, index_by_id, unique_index
# --------------------------------------------------------------------------


def test_objects_returns_the_members_of_a_collection(covert):
    assert [item["id"] for item in objects(covert, "components")] == [
        component["id"] for component in covert["components"]
    ]


def test_objects_drops_non_dict_members_without_raising():
    # Level 1 has already reported these; every later level must keep running so
    # that one malformed member does not hide the rest of the package's problems.
    package = {"components": [{"id": "cmp-a"}, "cmp-b", None, 7, ["cmp-c"], {"id": "cmp-d"}]}
    assert objects(package, "components") == [{"id": "cmp-a"}, {"id": "cmp-d"}]


@pytest.mark.parametrize("package", [None, [], "package", 7])
def test_objects_tolerates_a_package_that_is_not_a_dict(package):
    assert objects(package, "components") == []


def test_objects_tolerates_a_missing_collection():
    assert objects({"meaf-version": "2.0.0"}, "components") == []


@pytest.mark.parametrize("collection", [None, {}, "cmp-a", 7])
def test_objects_tolerates_a_collection_that_is_not_a_list(collection):
    assert objects({"components": collection}, "components") == []


def test_index_by_id_keeps_duplicates_visible():
    # Referential integrity at level 2 is "resolves to exactly one object", so
    # the index must be able to say "two", not silently keep the last one.
    first = {"id": "cmp-a", "digest": "sha256:first"}
    second = {"id": "cmp-a", "digest": "sha256:second"}
    index = index_by_id([first, second, {"id": "cmp-b"}])
    assert index["cmp-a"] == [first, second]
    assert index["cmp-b"] == [{"id": "cmp-b"}]


def test_index_by_id_drops_objects_with_no_usable_identifier():
    assert index_by_id([{"digest": "sha256:x"}, {"id": 7}, {"id": None}]) == {}


def test_unique_index_keeps_the_first_occurrence_of_a_duplicated_identifier():
    first = {"id": "cmp-a", "digest": "sha256:first"}
    second = {"id": "cmp-a", "digest": "sha256:second"}
    assert unique_index([first, second]) == {"cmp-a": first}


def test_unique_index_drops_objects_with_no_usable_identifier():
    assert unique_index([{"digest": "sha256:x"}, {"id": 7}]) == {}


# --------------------------------------------------------------------------
# role_ids, component_digests, subject_digests_for
# --------------------------------------------------------------------------


def test_role_ids_collects_the_declared_responsible_roles(covert):
    # A.4 puts responsible roles in the system boundary; A.5 level 3 then
    # requires every contract and finding owner to resolve to one of them.
    expected = {role["id"] for role in covert["system"]["responsible-roles"]}
    assert role_ids(covert) == expected
    assert "role-ai-assurance-lead" in role_ids(covert)


@pytest.mark.parametrize(
    "package",
    [
        None,
        {},
        {"system": None},
        {"system": []},
        {"system": {"id": "sys-a"}},
        {"system": {"id": "sys-a", "responsible-roles": None}},
        {"system": {"id": "sys-a", "responsible-roles": {}}},
    ],
)
def test_role_ids_is_empty_when_no_roles_are_declared(package):
    assert role_ids(package) == frozenset()


def test_role_ids_drops_role_entries_with_no_string_identifier():
    package = {
        "system": {
            "responsible-roles": [
                {"id": "role-owner"},
                {"title": "no identifier"},
                {"id": 7},
                "role-owner",
            ]
        }
    }
    assert role_ids(package) == frozenset({"role-owner"})


def test_component_digests_collects_every_component_digest(covert):
    assert component_digests(covert) == frozenset(
        component["digest"] for component in covert["components"]
    )


def test_component_digests_ignores_components_with_no_string_digest():
    package = {"components": [{"id": "a", "digest": "sha256:x"}, {"id": "b"}, {"id": "c", "digest": None}]}
    assert component_digests(package) == frozenset({"sha256:x"})


def test_a_component_subject_binds_to_that_components_digest(covert):
    model = next(c for c in covert["components"] if c["id"] == "cmp-foundation-model")
    assert subject_digests_for(covert, "cmp-foundation-model") == frozenset({model["digest"]})


def test_a_system_subject_binds_to_every_component_digest(covert):
    """A.1 principle 3: "Assurance follows the deployed artifact."

    A system-level claim made before a component changed is a claim about a
    system that no longer exists, so the system binds to the whole inventory
    rather than to nothing.
    """
    assert subject_digests_for(covert, covert["system"]["id"]) == component_digests(covert)
    assert len(subject_digests_for(covert, covert["system"]["id"])) == len(covert["components"])


def test_an_unresolvable_subject_binds_to_nothing(covert):
    # Level 2 reports the dangling reference; guessing a binding here would turn
    # a referential-integrity error into a silently satisfied currency check.
    assert subject_digests_for(covert, "cmp-does-not-exist") == frozenset()


@pytest.mark.parametrize("subject_id", [None, 7, ["cmp-foundation-model"]])
def test_a_subject_that_is_not_a_string_binds_to_nothing(covert, subject_id):
    assert subject_digests_for(covert, subject_id) == frozenset()


def test_a_component_subject_with_no_digest_binds_to_nothing():
    package = {"system": {"id": "sys-a"}, "components": [{"id": "cmp-a"}]}
    assert subject_digests_for(package, "cmp-a") == frozenset()


def test_a_component_identifier_takes_precedence_over_an_identical_system_identifier():
    # Contrived, but it pins the resolution order: the narrower binding wins, so
    # a package cannot widen a component claim into a system claim by reusing an
    # identifier.
    package = {
        "system": {"id": "shared-id"},
        "components": [
            {"id": "shared-id", "digest": "sha256:one"},
            {"id": "cmp-other", "digest": "sha256:two"},
        ],
    }
    assert subject_digests_for(package, "shared-id") == frozenset({"sha256:one"})


# --------------------------------------------------------------------------
# evidence_is_fresh: the calendar half of the predicate
# --------------------------------------------------------------------------


def test_evidence_within_its_max_age_is_fresh():
    assert evidence_is_fresh("2026-07-15T00:00:00Z", "P30D", None, FROZEN_NOW) is True


def test_evidence_exactly_at_its_max_age_is_still_fresh():
    # A.5 writes the comparison as "t - e.collected_at <= e.max_age", so the
    # boundary instant is inside the window.
    collected = FROZEN_NOW - timedelta(days=30)
    assert evidence_is_fresh(collected.isoformat(), "P30D", None, FROZEN_NOW) is True


def test_evidence_one_second_past_its_max_age_is_not_fresh():
    collected = FROZEN_NOW - timedelta(days=30, seconds=1)
    assert evidence_is_fresh(collected.isoformat(), "P30D", None, FROZEN_NOW) is False


def test_invalidated_evidence_is_not_fresh_however_recently_it_was_collected():
    collected = (FROZEN_NOW - timedelta(minutes=1)).isoformat()
    assert evidence_is_fresh(collected, "P30D", "2026-07-28T11:59:30Z", FROZEN_NOW) is False


def test_evidence_freshness_answers_only_the_calendar_question():
    """Freshness is the part of currency that can be answered without knowing
    what is deployed, so it takes no digests and never consults binding."""
    collected = (FROZEN_NOW - timedelta(minutes=1)).isoformat()
    item = evidence_item(
        **{"collected-at": collected, "subject-digests": [SUPERSEDED_SUBJECT]}
    )
    assert evidence_is_fresh(collected, "P30D", None, FROZEN_NOW) is True
    # The same item, asked the full question against the deployed subject, is
    # not current. Freshness alone must never be used as the gate condition.
    currency = evidence_currency(
        item, now=FROZEN_NOW, required_digests=frozenset({DEPLOYED_SUBJECT})
    )
    assert currency.current is False


# --------------------------------------------------------------------------
# evidence_currency: the A.5 predicate, conjunct by conjunct
# --------------------------------------------------------------------------


def test_evidence_meeting_every_conjunct_is_current():
    currency = evidence_currency(
        evidence_item(), now=FROZEN_NOW, required_digests=frozenset({DEPLOYED_SUBJECT})
    )
    assert currency == Currency(
        current=True,
        binding_matches=True,
        within_max_age=True,
        not_invalidated=True,
        reasons=(),
    )


def test_the_max_age_conjunct_fails_on_its_own_when_evidence_has_aged_out():
    # current(e, t) = (t - e.collected_at <= e.max_age) AND ...
    collected = (FROZEN_NOW - timedelta(days=45)).isoformat()
    currency = evidence_currency(
        evidence_item(**{"collected-at": collected}),
        now=FROZEN_NOW,
        required_digests=frozenset({DEPLOYED_SUBJECT}),
    )
    assert currency.within_max_age is False
    assert currency.binding_matches is True
    assert currency.not_invalidated is True
    assert currency.current is False
    assert currency.reasons


def test_evidence_exactly_at_its_max_age_is_still_within_the_window():
    collected = (FROZEN_NOW - timedelta(days=30)).isoformat()
    currency = evidence_currency(evidence_item(**{"collected-at": collected}), now=FROZEN_NOW)
    assert currency.within_max_age is True
    assert currency.current is True


def test_the_invalidation_conjunct_fails_on_its_own():
    # ... AND (e.invalidated_at is null)
    currency = evidence_currency(
        evidence_item(**{"invalidated-at": "2026-07-20T00:00:00Z"}),
        now=FROZEN_NOW,
        required_digests=frozenset({DEPLOYED_SUBJECT}),
    )
    assert currency.not_invalidated is False
    assert currency.within_max_age is True
    assert currency.binding_matches is True
    assert currency.current is False
    assert any("invalidated" in reason for reason in currency.reasons)


def test_evidence_collected_one_minute_ago_against_a_superseded_subject_is_not_current():
    """A.5: "Artifact binding takes precedence over calendar freshness.

    Evidence collected one minute ago against a superseded prompt, adapter,
    model endpoint, graph, policy, or retrieval snapshot is stale." This is the
    manuscript's own worked example, and it is the single behaviour that makes
    binding a conjunct of currency rather than an advisory side-check.
    """
    collected = (FROZEN_NOW - timedelta(minutes=1)).isoformat()
    item = evidence_item(
        **{"collected-at": collected, "subject-digests": [SUPERSEDED_SUBJECT]}
    )
    currency = evidence_currency(
        item, now=FROZEN_NOW, required_digests=frozenset({DEPLOYED_SUBJECT})
    )
    assert currency.within_max_age is True
    assert currency.not_invalidated is True
    assert currency.binding_matches is False
    assert currency.current is False
    assert any(DEPLOYED_SUBJECT in reason for reason in currency.reasons)


def test_evidence_must_be_bound_to_every_digest_of_the_deployed_subject():
    # A system-level claim resolves to the whole inventory. Evidence covering
    # only part of it is evidence about a different system.
    item = evidence_item(**{"subject-digests": [DEPLOYED_SUBJECT]})
    currency = evidence_currency(
        item,
        now=FROZEN_NOW,
        required_digests=frozenset({DEPLOYED_SUBJECT, SUPERSEDED_SUBJECT}),
    )
    assert currency.binding_matches is False
    assert currency.current is False


def test_evidence_bound_to_more_than_the_deployed_subject_still_matches():
    # Extra digests are additional coverage, not a mismatch: the requirement is
    # that the deployed subject is covered, not that nothing else is.
    item = evidence_item(**{"subject-digests": [DEPLOYED_SUBJECT, SUPERSEDED_SUBJECT]})
    currency = evidence_currency(
        item, now=FROZEN_NOW, required_digests=frozenset({DEPLOYED_SUBJECT})
    )
    assert currency.binding_matches is True
    assert currency.current is True


def test_binding_is_not_asserted_when_no_deployed_subject_was_supplied():
    # Callers that have not resolved a subject are asking the calendar question
    # only; the predicate must not invent a binding failure out of nothing.
    item = evidence_item(**{"subject-digests": []})
    currency = evidence_currency(item, now=FROZEN_NOW)
    assert currency.binding_matches is True
    assert currency.current is True


@pytest.mark.parametrize("subject_digests", [None, "sha256:not-a-list", {}, 7])
def test_evidence_whose_subject_digests_are_not_a_list_is_not_bound(subject_digests):
    item = evidence_item(**{"subject-digests": subject_digests})
    currency = evidence_currency(
        item, now=FROZEN_NOW, required_digests=frozenset({DEPLOYED_SUBJECT})
    )
    assert currency.binding_matches is False
    assert currency.current is False


def test_every_conjunct_can_fail_at_once_and_each_is_reported_separately():
    # The Currency record exists so a report can say which conjunct failed;
    # collapsing them into one boolean loses the remediation instruction.
    item = evidence_item(
        **{
            "collected-at": (FROZEN_NOW - timedelta(days=90)).isoformat(),
            "subject-digests": [SUPERSEDED_SUBJECT],
            "invalidated-at": "2026-07-01T00:00:00Z",
        }
    )
    currency = evidence_currency(
        item, now=FROZEN_NOW, required_digests=frozenset({DEPLOYED_SUBJECT})
    )
    assert (currency.binding_matches, currency.not_invalidated, currency.within_max_age) == (
        False,
        False,
        False,
    )
    assert currency.current is False
    assert len(currency.reasons) == 3


def test_a_contract_override_can_tighten_the_freshness_a_contract_requires():
    # Collected 13 days ago: inside the item's own 30 day window, outside a
    # contract that demands 7 day evidence.
    item = evidence_item(**{"collected-at": (FROZEN_NOW - timedelta(days=13)).isoformat()})
    assert evidence_currency(item, now=FROZEN_NOW).current is True
    tightened = evidence_currency(item, now=FROZEN_NOW, max_age_override="P7D")
    assert tightened.within_max_age is False
    assert tightened.current is False


def test_a_contract_override_can_never_loosen_the_evidence_items_own_max_age():
    """The stricter of the two always wins.

    Otherwise a contract could rehabilitate expired evidence by asking for less
    freshness than the collector itself was willing to vouch for, which would
    make the evidence item's declared validity window unenforceable.
    """
    item = evidence_item(**{"collected-at": (FROZEN_NOW - timedelta(days=45)).isoformat()})
    loosened = evidence_currency(item, now=FROZEN_NOW, max_age_override="P90D")
    assert loosened.within_max_age is False
    assert loosened.current is False


def test_an_override_no_stricter_than_the_declared_max_age_changes_nothing():
    item = evidence_item(**{"collected-at": (FROZEN_NOW - timedelta(days=13)).isoformat()})
    assert evidence_currency(item, now=FROZEN_NOW, max_age_override="P90D").current is True


@pytest.mark.parametrize(
    "overrides",
    [
        {"collected-at": "not-a-timestamp"},
        {"collected-at": None},
        {"max-age": "P"},
        {"max-age": None},
        {"max-age": "thirty days"},
    ],
    ids=[
        "unparseable-collected-at",
        "missing-collected-at",
        "quantity-free-duration",
        "missing-max-age",
        "unparseable-max-age",
    ],
)
def test_an_unparseable_timestamp_yields_a_reason_rather_than_an_exception(overrides):
    # A malformed timestamp is a level 3 finding, not a crash: the evaluator has
    # to finish the package and report every contract's state.
    currency = evidence_currency(evidence_item(**overrides), now=FROZEN_NOW)
    assert currency.within_max_age is False
    assert currency.current is False
    assert currency.reasons


def test_an_unparseable_override_does_not_silently_apply_the_declared_max_age():
    # Failing open here would let a typo in a contract restore the looser window
    # the contract was written to tighten.
    currency = evidence_currency(evidence_item(), now=FROZEN_NOW, max_age_override="P")
    assert currency.within_max_age is False
    assert currency.current is False


def test_currency_serializes_with_the_packages_hyphenated_member_names():
    # The record is embedded in generated reports and OSCAL output, which use
    # hyphenated names throughout.
    currency = evidence_currency(evidence_item(), now=FROZEN_NOW)
    assert currency.to_dict() == {
        "current": True,
        "binding-matches": True,
        "within-max-age": True,
        "not-invalidated": True,
        "reasons": [],
    }


def test_the_shipped_reference_evidence_is_current_at_the_frozen_instant(covert):
    """The clean example must be clean at the instant the suite evaluates it.

    If this fails, every downstream expectation about the covert-influence
    package allowing the gate is testing the wrong thing.
    """
    for item in covert["evidence"]:
        currency = evidence_currency(item, now=FROZEN_NOW)
        assert currency.current is True, (item["id"], currency.reasons)


def test_the_shipped_reference_evidence_ages_out_at_the_stale_instant(covert):
    from tests.conftest import STALE_NOW

    for item in covert["evidence"]:
        assert evidence_currency(item, now=STALE_NOW).current is False
