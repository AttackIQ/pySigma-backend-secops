import json

import pytest

from sigma.pipelines.secops import secops_udm_pipeline
from sigma.pipelines.secops.errors import InvalidUDMFieldError
from sigma.pipelines.secops.transformations import (
    EnsureValidUDMFieldsTransformation,
)
from sigma.rule import SigmaRule


@pytest.fixture
def udm_schema():
    with open("sigma/pipelines/secops/udm_field_schema.json", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def secops_pipeline():
    return secops_udm_pipeline(prepend_metadata=False)


def test_convert_enum_value_transformation(secops_pipeline):
    rule = SigmaRule.from_yaml(
        """
        title: Test Enum Conversion
        logsource:
            category: network_connection
            product: windows
        detection:
            selection:
                Initiated: 'true'
            condition: selection
    """
    )
    secops_pipeline.apply(rule)
    assert rule.detection.detections["selection"].detection_items[0].value[0] == "OUTBOUND"


def test_ensure_valid_udm_fields_transformation(udm_schema):
    rule = SigmaRule.from_yaml(
        """
        title: Test Valid Fields
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                Image: cmd.exe
                InvalidField: value
            condition: selection
    """
    )

    transform = EnsureValidUDMFieldsTransformation(udm_schema)
    with pytest.raises(InvalidUDMFieldError):
        transform.apply(rule)


def test_event_type_field_mapping_transformation(secops_pipeline):
    rule = SigmaRule.from_yaml(
        """
        title: Test Event Type Mapping
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                EventID: 4688
            condition: selection
    """
    )
    secops_pipeline.apply(rule)
    assert "event_types" in rule.custom_attributes
