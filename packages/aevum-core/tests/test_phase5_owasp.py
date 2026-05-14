# SPDX-License-Identifier: Apache-2.0
import dataclasses
import json

import pytest

from aevum.core.compliance.owasp_crosswalk import (
    OWASP_CROSSWALK,
    OWASPEntry,
    render_crosswalk,
)


class TestOWASPCrosswalk:
    def test_ten_entries(self) -> None:
        assert len(OWASP_CROSSWALK) == 10

    def test_all_codes_present(self) -> None:
        codes = {e.code for e in OWASP_CROSSWALK}
        for i in range(1, 11):
            assert f"ASI{i:02d}" in codes

    def test_all_entries_frozen_dataclass(self) -> None:
        for entry in OWASP_CROSSWALK:
            assert dataclasses.is_dataclass(entry)
            with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
                entry.coverage = "none"  # type: ignore[misc]

    def test_coverage_values_valid(self) -> None:
        valid = {"full", "partial", "indirect"}
        for entry in OWASP_CROSSWALK:
            assert entry.coverage in valid, f"{entry.code} has invalid coverage: {entry.coverage}"

    def test_asi01_has_trifecta_or_taint_mechanism(self) -> None:
        asi01 = next(e for e in OWASP_CROSSWALK if e.code == "ASI01")
        mechanisms_text = " ".join(asi01.aevum_mechanisms).lower()
        assert "trifecta" in mechanisms_text or "taint" in mechanisms_text

    def test_asi06_is_full_coverage(self) -> None:
        asi06 = next(e for e in OWASP_CROSSWALK if e.code == "ASI06")
        assert asi06.coverage == "full"

    def test_asi07_mentions_exfiltration(self) -> None:
        asi07 = next(e for e in OWASP_CROSSWALK if e.code == "ASI07")
        notes_lower = asi07.notes.lower()
        assert "exfil" in notes_lower or "trifecta" in notes_lower

    def test_asi01_has_barriers(self) -> None:
        asi01 = next(e for e in OWASP_CROSSWALK if e.code == "ASI01")
        assert len(asi01.aevum_barriers) > 0

    def test_asi08_has_no_barriers(self) -> None:
        asi08 = next(e for e in OWASP_CROSSWALK if e.code == "ASI08")
        assert len(asi08.aevum_barriers) == 0

    def test_all_mechanisms_are_nonempty_strings(self) -> None:
        for entry in OWASP_CROSSWALK:
            for mechanism in entry.aevum_mechanisms:
                assert isinstance(mechanism, str) and len(mechanism) > 0

    def test_all_notes_are_nonempty_strings(self) -> None:
        for entry in OWASP_CROSSWALK:
            assert isinstance(entry.notes, str) and len(entry.notes) > 0

    def test_all_titles_are_nonempty_strings(self) -> None:
        for entry in OWASP_CROSSWALK:
            assert isinstance(entry.title, str) and len(entry.title) > 0

    def test_codes_are_in_order(self) -> None:
        codes = [e.code for e in OWASP_CROSSWALK]
        assert codes == sorted(codes)

    def test_mechanisms_are_tuples(self) -> None:
        for entry in OWASP_CROSSWALK:
            assert isinstance(entry.aevum_mechanisms, tuple)
            assert isinstance(entry.aevum_barriers, tuple)

    def test_full_coverage_entries_count(self) -> None:
        full_count = sum(1 for e in OWASP_CROSSWALK if e.coverage == "full")
        assert full_count >= 5  # at least 5 full-coverage entries (ASI01,02,03,04,06,07)

    def test_render_text_contains_all_codes(self) -> None:
        text = render_crosswalk("text")
        for i in range(1, 11):
            assert f"ASI{i:02d}" in text

    def test_render_text_contains_coverage_markers(self) -> None:
        text = render_crosswalk("text")
        assert "Coverage: FULL" in text
        assert "Coverage: PARTIAL" in text

    def test_render_json_is_valid(self) -> None:
        json_str = render_crosswalk("json")
        parsed = json.loads(json_str)
        assert "owasp_agentic_top_10_crosswalk" in parsed
        assert len(parsed["owasp_agentic_top_10_crosswalk"]) == 10

    def test_render_json_each_entry_has_required_fields(self) -> None:
        json_str = render_crosswalk("json")
        parsed = json.loads(json_str)
        for entry in parsed["owasp_agentic_top_10_crosswalk"]:
            for field in ("code", "title", "aevum_mechanisms", "coverage", "notes"):
                assert field in entry

    def test_render_default_is_text(self) -> None:
        text = render_crosswalk()
        assert "AEVUM" in text
        assert "ASI01" in text

    def test_owasp_entry_is_not_dict(self) -> None:
        for entry in OWASP_CROSSWALK:
            assert isinstance(entry, OWASPEntry)
