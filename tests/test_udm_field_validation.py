import json

import pytest

from sigma.pipelines.secops.mappings import get_field_mappings
from sigma.pipelines.secops.validators import (
    check_value_type,
    is_valid_udm_field,
    is_valid_udm_field_value,
)


@pytest.fixture
def udm_schema():
    with open("sigma/pipelines/secops/udm_field_schema.json", encoding="utf-8") as f:
        return json.load(f)


def test_is_valid_udm_field(udm_schema):
    assert is_valid_udm_field("security_result.alert_state", udm_schema)
    assert is_valid_udm_field("metadata.event_type", udm_schema)
    assert is_valid_udm_field("target.process.file.names", udm_schema)
    assert is_valid_udm_field("target.process.file.full_path", udm_schema)
    assert is_valid_udm_field("network.application_protocol", udm_schema)
    assert is_valid_udm_field("target.asset.hostname", udm_schema)
    assert is_valid_udm_field("src.ip", udm_schema)
    assert is_valid_udm_field("principal.user.userid", udm_schema)
    assert not is_valid_udm_field("invalid.field.path", udm_schema)


def test_field_empty_string(udm_schema):
    assert not is_valid_udm_field("", udm_schema)


def test_is_valid_udm_field_value(udm_schema):
    assert is_valid_udm_field_value("security_result.alert_state", "ALERTING", udm_schema)
    assert not is_valid_udm_field_value("security_result.alert_state", "INVALID_STATE", udm_schema)
    assert is_valid_udm_field_value("metadata.event_type", "PROCESS_LAUNCH", udm_schema)
    assert not is_valid_udm_field_value("metadata.event_type", "INVALID_EVENT_TYPE", udm_schema)
    assert is_valid_udm_field_value("target.process.file.names", "example.exe", udm_schema)
    assert is_valid_udm_field_value("target.process.file.full_path", "/path/to/example.exe", udm_schema)
    assert is_valid_udm_field_value("network.application_protocol", "HTTP", udm_schema)
    assert is_valid_udm_field_value("target.asset.hostname", "server01", udm_schema)
    assert is_valid_udm_field_value("src.ip", "192.168.1.1", udm_schema)
    assert is_valid_udm_field_value("principal.user.userid", "john.doe", udm_schema)


def test_check_value_type():
    """Test value type checking with various inputs"""
    # Test string values
    assert check_value_type("test", "string")
    assert not check_value_type(123, "string")

    # Test integer values
    assert check_value_type(123, "integer")
    assert check_value_type("123", "integer")  # String that can be converted
    assert not check_value_type("not a number", "integer")

    # Test number values
    assert check_value_type(123.45, "number")
    assert check_value_type(123, "number")  # Integers are valid numbers

    # Test boolean values
    assert check_value_type(True, "boolean")
    assert check_value_type(False, "boolean")
    assert check_value_type("true", "boolean")
    assert check_value_type("false", "boolean")
    assert not check_value_type("not a boolean", "boolean")

    # Test array/list values
    assert check_value_type(["test"], "array")
    assert check_value_type([], "array")

    # Test object/dict values
    assert check_value_type({"key": "value"}, "object")
    assert check_value_type({}, "object")


def test_is_valid_udm_field_edge_cases(udm_schema):
    assert not is_valid_udm_field("", udm_schema)
    assert not is_valid_udm_field(".", udm_schema)
    assert not is_valid_udm_field("invalid", udm_schema)
    assert not is_valid_udm_field("security_result.", udm_schema)


def test_is_valid_udm_field_value_edge_cases(udm_schema):
    assert not is_valid_udm_field_value("security_result.alert_state", "", udm_schema)
    assert not is_valid_udm_field_value("security_result.alert_state", None, udm_schema)
    assert not is_valid_udm_field_value("metadata.event_type", 123, udm_schema)
    assert not is_valid_udm_field_value("invalid.field", "value", udm_schema)


def test_is_valid_udm_field_no_schema(udm_schema):
    assert is_valid_udm_field("security_result.alert_state", udm_schema)
    assert not is_valid_udm_field("invalid.field.path", udm_schema)


# Add these new test functions


def test_is_valid_udm_field_subtype(udm_schema):
    assert is_valid_udm_field("principal.ip", udm_schema)  # Assuming 'ip' is a subtype


def test_is_valid_udm_field_nested_subtype(udm_schema):
    assert is_valid_udm_field("principal.mac", udm_schema)  # Assuming 'mac' is a nested subtype


def test_is_valid_udm_field_value_subtype(udm_schema):
    assert is_valid_udm_field_value("principal.ip", "192.168.1.1", udm_schema)


def test_is_valid_udm_field_value_nested_subtype(udm_schema):
    assert is_valid_udm_field_value("principal.mac", "00:11:22:33:44:55", udm_schema)


def test_is_valid_udm_field_value_direct_enum(udm_schema):
    # Assuming 'network.direction' is a direct enum field
    assert is_valid_udm_field_value("network.direction", "INBOUND", udm_schema)
    assert not is_valid_udm_field_value("network.direction", "INVALID", udm_schema)


def test_check_value_type_edge_cases():
    assert check_value_type(0, "integer")
    assert check_value_type(False, "boolean")
    assert check_value_type([], "list")
    assert not check_value_type("", "integer")
    assert not check_value_type([], "boolean")  # This should now pass
    assert not check_value_type({}, "list")
    assert check_value_type("true", "boolean")
    assert check_value_type("false", "boolean")
    assert not check_value_type("not a boolean", "boolean")


# Add these new test functions at the end of the file


def test_is_valid_udm_field_noun(udm_schema):
    assert is_valid_udm_field("principal.hostname", udm_schema)  # 'principal' is a noun
    assert is_valid_udm_field("target.hostname", udm_schema)  # 'target' is a noun
    assert is_valid_udm_field("src.ip", udm_schema)  # 'src' is a noun


def test_is_valid_udm_field_enum(udm_schema):
    assert is_valid_udm_field("security_result.severity", udm_schema)  # Assuming 'severity' is an enum


def test_is_valid_udm_field_standard_types(udm_schema):
    assert is_valid_udm_field("metadata.product_name", udm_schema)  # Assuming 'name' is a string
    assert is_valid_udm_field("security_result.priority", udm_schema)  # Assuming 'priority' is an integer
    assert is_valid_udm_field("network.asn", udm_schema)  # Assuming 'initiated' is a boolean
    assert is_valid_udm_field("target.process.file.md5", udm_schema)  # Assuming 'hashes' is a list


def test_is_valid_udm_field_invalid_type(udm_schema):
    # Find a field that exists in the schema
    for top_level in udm_schema["TopLevelFields"]:
        if isinstance(udm_schema["TopLevelFields"][top_level], dict):
            for field in udm_schema["TopLevelFields"][top_level]:
                if isinstance(udm_schema["TopLevelFields"][top_level][field], str):
                    # Modify the schema temporarily to test an invalid field type
                    original_type = udm_schema["TopLevelFields"][top_level][field]
                    udm_schema["TopLevelFields"][top_level][field] = 123  # Invalid type
                    assert not is_valid_udm_field(f"{top_level}.{field}", udm_schema)
                    # Restore the original type
                    udm_schema["TopLevelFields"][top_level][field] = original_type
                    return  # Exit after testing one field

    pytest.fail("Could not find a suitable field to test invalid type")


def test_is_valid_udm_field_value_invalid_enum(udm_schema):
    assert is_valid_udm_field_value(
        "security_result.severity", "HIGH", udm_schema
    )  # Assuming 'HIGH' is a valid severity
    assert not is_valid_udm_field_value("security_result.severity", "INVALID_SEVERITY", udm_schema)


def test_is_valid_udm_field_value_invalid_subtype(udm_schema):
    assert is_valid_udm_field_value("principal.ip", "192.168.1.1", udm_schema)
    assert not is_valid_udm_field_value("principal.ip", 12345, udm_schema)  # Not a string, should fail


def test_check_value_type_comprehensive():
    assert check_value_type("test", "string")
    assert check_value_type(123, "integer")
    assert check_value_type("123", "integer")
    assert check_value_type(True, "boolean")
    assert check_value_type("true", "boolean")
    assert check_value_type("false", "boolean")
    assert check_value_type(["item1", "item2"], "list")
    assert check_value_type("unknown", "unknown_type")
    assert not check_value_type("not an int", "integer")
    assert not check_value_type("not a bool", "boolean")
    assert not check_value_type({}, "list")


def test_is_valid_udm_field_not_noun(udm_schema):
    assert not is_valid_udm_field("file.name", udm_schema)  # 'file' is not a noun


# Add these new test functions


def test_is_valid_udm_field_complex_path(udm_schema):
    assert is_valid_udm_field("target.process.file.md5", udm_schema)
    assert is_valid_udm_field("principal.process.file.sha256", udm_schema)
    assert not is_valid_udm_field("target.process.nonexistent", udm_schema)


def test_is_valid_udm_field_value_complex_path(udm_schema):
    assert is_valid_udm_field_value("target.process.file.md5", "d41d8cd98f00b204e9800998ecf8427e", udm_schema)
    assert is_valid_udm_field_value(
        "principal.process.file.sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", udm_schema
    )


def test_is_valid_udm_field_value_enum_types(udm_schema):
    assert is_valid_udm_field_value("security_result.severity", "HIGH", udm_schema)
    assert is_valid_udm_field_value("network.direction", "INBOUND", udm_schema)
    assert not is_valid_udm_field_value("security_result.severity", "INVALID", udm_schema)
    assert not is_valid_udm_field_value("network.direction", "INVALID", udm_schema)


def test_is_valid_udm_field_value_subtypes(udm_schema):
    assert is_valid_udm_field_value("src.ip", "192.168.1.1", udm_schema)
    assert is_valid_udm_field_value("target.mac", "00:11:22:33:44:55", udm_schema)


def test_is_valid_udm_field_value_complex_types(udm_schema):
    assert is_valid_udm_field_value("network.sent_packets", 100, udm_schema)
    assert is_valid_udm_field_value("network.received_packets", "100", udm_schema)
    assert is_valid_udm_field_value("security_result.action_details", "not_a_list", udm_schema)
    assert not is_valid_udm_field_value("network.sent_packets", "not_a_number", udm_schema)
    assert not is_valid_udm_field_value("network.received_packets", "not_a_number", udm_schema)
    assert not is_valid_udm_field_value("security_result.action_details", ["block", "alert"], udm_schema)


def test_network_packet_fields_exist(udm_schema):
    assert is_valid_udm_field("network.sent_packets", udm_schema)
    assert is_valid_udm_field("network.received_packets", udm_schema)


@pytest.mark.parametrize("event_type", ["process", "network", "file", "authentication", "registry", "dns"])
def test_event_type_field_mappings_validity(event_type, udm_schema):
    mappings = get_field_mappings().get(event_type)

    for sigma_field, udm_field in mappings.items():
        assert is_valid_udm_field(
            udm_field, udm_schema
        ), f"Invalid UDM field '{udm_field}' for Sigma field '{sigma_field}' in event type '{event_type}'"


def test_common_field_mappings_validity(udm_schema):
    mappings = get_field_mappings().get("common")
    for sigma_field, udm_field in mappings.items():
        assert is_valid_udm_field(
            udm_field, udm_schema
        ), f"Invalid UDM field '{udm_field}' for Sigma field '{sigma_field}' in event type 'common'"


def test_field_validation_edge_cases(udm_schema):
    # Test nested fields
    assert is_valid_udm_field("target.process.file.full_path", udm_schema)
    assert not is_valid_udm_field("target.invalid.path", udm_schema)

    # Test field with dots in name
    assert not is_valid_udm_field("target.process.file..path", udm_schema)

    # Test non-existent top-level field
    assert not is_valid_udm_field("nonexistent.field", udm_schema)
