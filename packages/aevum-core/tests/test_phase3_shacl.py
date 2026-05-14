# SPDX-License-Identifier: Apache-2.0
import pytest

from aevum.core.shacl_validator import SHACLValidationError, validate_fact_rdf

VALID_FACT_TTL = """
@prefix aevum: <https://aevum.build/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

<https://aevum.build/fact/1> a aevum:TypedFact ;
    aevum:subject "user:alice"^^xsd:string ;
    aevum:predicate "schema:name"^^xsd:string ;
    aevum:objectValue "Alice" ;
    aevum:sourceType "user" .
"""

INVALID_FACT_TTL = """
@prefix aevum: <https://aevum.build/ontology#> .

<https://aevum.build/fact/2> a aevum:TypedFact ;
    aevum:subject "user:bob" .
"""
# Missing predicate, objectValue, sourceType

INVALID_SOURCE_TYPE_TTL = """
@prefix aevum: <https://aevum.build/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

<https://aevum.build/fact/3> a aevum:TypedFact ;
    aevum:subject "user:carol"^^xsd:string ;
    aevum:predicate "schema:email"^^xsd:string ;
    aevum:objectValue "carol@example.com" ;
    aevum:sourceType "invalid_type" .
"""


class TestSHACLValidator:
    def test_valid_fact_passes(self):
        validate_fact_rdf(VALID_FACT_TTL)  # must not raise

    def test_invalid_fact_raises_shacl_error(self):
        with pytest.raises(SHACLValidationError):
            validate_fact_rdf(INVALID_FACT_TTL)

    def test_empty_graph_does_not_raise(self):
        validate_fact_rdf("")  # must not raise

    def test_whitespace_only_graph_does_not_raise(self):
        validate_fact_rdf("   \n\t  ")  # must not raise

    def test_invalid_source_type_raises(self):
        with pytest.raises(SHACLValidationError):
            validate_fact_rdf(INVALID_SOURCE_TYPE_TTL)

    def test_multiple_valid_facts_pass(self):
        multi = VALID_FACT_TTL + """
<https://aevum.build/fact/99> a aevum:TypedFact ;
    aevum:subject "user:dave" ;
    aevum:predicate "schema:age" ;
    aevum:objectValue "30" ;
    aevum:sourceType "tool" .
"""
        validate_fact_rdf(multi)  # must not raise

    def test_shacl_validation_error_is_exception(self):
        assert issubclass(SHACLValidationError, Exception)

    def test_shacl_error_message_contains_useful_info(self):
        with pytest.raises(SHACLValidationError, match="SHACL"):
            validate_fact_rdf(INVALID_FACT_TTL)

    def test_tool_source_type_valid(self):
        ttl = VALID_FACT_TTL.replace('aevum:sourceType "user"', 'aevum:sourceType "tool"')
        validate_fact_rdf(ttl)  # must not raise

    def test_inference_source_type_valid(self):
        ttl = VALID_FACT_TTL.replace('aevum:sourceType "user"', 'aevum:sourceType "inference"')
        validate_fact_rdf(ttl)  # must not raise

    def test_system_source_type_valid(self):
        ttl = VALID_FACT_TTL.replace('aevum:sourceType "user"', 'aevum:sourceType "system"')
        validate_fact_rdf(ttl)  # must not raise

    def test_custom_shapes_path(self, tmp_path):
        """validate_fact_rdf with a non-existent shapes path skips validation."""
        fake_path = tmp_path / "nonexistent.ttl"
        # Should not raise (logs warning and returns)
        validate_fact_rdf(VALID_FACT_TTL, shapes_path=fake_path)
