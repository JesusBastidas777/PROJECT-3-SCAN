"""Scan Plan 1.0 semantic validator."""
from collections.abc import Mapping
def validate_plan(value: Mapping) -> None:
    required={"plan_schema_version","document_type","plan_id","target","ports","phases","effective_configuration","measurement_scope","execution_policy","potential_maximum_network_attempts","privacy","expected_output_contracts"}
    if required-value.keys() or value.get("plan_schema_version")!="1.0" or value.get("document_type")!="scan_plan" or not str(value.get("plan_id","")).startswith("plan_"): raise ValueError("invalid scan plan 1.0")
    if value.get("potential_maximum_network_attempts",{}).get("kind")!="structural_upper_bound_not_prediction": raise ValueError("plan attempts must not be a prediction")
