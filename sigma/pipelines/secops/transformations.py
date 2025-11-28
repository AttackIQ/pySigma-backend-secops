import re
from collections.abc import Iterable
from dataclasses import dataclass

from sigma.correlations import SigmaCorrelationRule
from sigma.processing.transformations import (
    FieldMappingTransformation,
    Transformation,
)
from sigma.processing.transformations.base import (
    DetectionItemTransformation,
    ValueTransformation,
)
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule
from sigma.types import SigmaString, SigmaType

from .errors import InvalidUDMFieldError
from .mappings import enum_mappings, get_field_mappings_by_event_type
from .utils import determine_event_type_event_id, determine_event_type_logsource
from .validators import is_valid_udm_field


@dataclass
class PrependEventVariableTransformation(FieldMappingTransformation):
    """Prepend event variable to every field name for YARA_L output format/pipeline"""

    mapping = {}

    def apply_field_name(self, field: str) -> None | str | list[str]:
        return f"$event1.{field}"


@dataclass
class SetPrependMetadataTransformation(Transformation):
    prepend_metadata: bool

    def apply(self, rule: SigmaRule | SigmaCorrelationRule) -> None:
        self.processing_item_applied(rule)
        if self._pipeline.state.get("prepend_metadata", None) is None:
            self._pipeline.state["prepend_metadata"] = self.prepend_metadata


@dataclass
class RemoveHashAlgoFromValueTransformation(ValueTransformation):
    def apply_value(self, field: str, val: SigmaType) -> SigmaType:
        return SigmaString(val.to_plain().split("|")[-1])


@dataclass
class ConvertEnumValueTransformation(ValueTransformation):
    """
    Convert the value of a field to an enum value, with modified ValueTransformation.
    """

    def apply_detection_item(self, detection_item: SigmaDetectionItem):
        """Call apply_value for each value and integrate results into value list."""
        results = []
        modified = False
        if detection_item.field in enum_mappings:
            for value in detection_item.value:
                if self.value_types is None or isinstance(
                    value, self.value_types
                ):  # run replacement if no type annotation is defined or matching to type of value
                    res = self.apply_value(detection_item.field, value)
                    if res is None:  # no value returned: drop value
                        results.append(value)
                    elif isinstance(res, Iterable) and not isinstance(res, SigmaType):
                        results.extend(res)
                        modified = True
                    else:
                        results.append(res)
                        modified = True
                else:  # pass original value if type doesn't matches to apply_value argument type annotation
                    results.append(value)
            if modified:
                detection_item.value = results
                self.processing_item_applied(detection_item)

    def apply_value(self, field: str, val: SigmaType) -> SigmaType:
        return SigmaString(enum_mappings.get(field, {}).get(val.to_plain(), None)) or val


@dataclass
class EnsureValidUDMFieldsTransformation(DetectionItemTransformation):
    """
    Ensure that all fields in the detection item are valid UDM fields.
    """

    udm_schema: dict

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> None:
        if detection_item.field and not is_valid_udm_field(detection_item.field, self.udm_schema):
            raise InvalidUDMFieldError(f"Field {detection_item.field} is not a valid UDM field")


@dataclass
class SetRuleEventTypeFromLogsourceTransformation(Transformation):
    """Sets the `event_types` custom attribute on a rule for processing pipeline/backend.

    `event_types` is a set of event types the rule relates to.
    If already set from a previous pipeline, we ensure it's converted to a set.
    """

    def apply(
        self,
        rule: SigmaRule | SigmaCorrelationRule,
    ) -> None:
        if rule.custom_attributes.get("event_types", None):
            self.processing_item_applied(rule)
            if isinstance(rule.custom_attributes["event_types"], list | str):
                rule.custom_attributes["event_types"] = {rule.custom_attributes["event_types"]}
        else:
            rule.custom_attributes["event_types"] = set()
            if event_type := determine_event_type_logsource(rule):
                rule.custom_attributes["event_types"].add(event_type)
                self.processing_item_applied(rule)


@dataclass
class SetRuleEventTypeFromEventIDTransformation(DetectionItemTransformation):
    """Iterates through "selection" sections and sets event_type if EventID is present."""

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> str | None:
        """Apply transformation on detection item, returning event_type string if found."""
        event_types = set()
        if detection_item.field == "EventID":
            for value in detection_item.value:
                if event_type := determine_event_type_event_id(str(value.to_plain())):
                    event_types.add(event_type)
        if event_types:
            return event_types

    def apply_detection(self, detection: SigmaDetection) -> str | None:
        """Apply transformation on detection, returning event_type string if found."""
        for i, detection_item in enumerate(detection.detection_items):
            if isinstance(detection_item, SigmaDetection):  # recurse into nested detection items
                self.apply_detection(detection_item)
            else:
                if (self.processing_item is None or self.processing_item.match_detection_item(detection_item)) and (
                    r := self.apply_detection_item(detection_item)
                ) is not None:
                    self.processing_item_applied(detection.detection_items[i])
                    return r

    def apply(self, rule: SigmaRule | SigmaCorrelationRule) -> None:
        super().apply(rule)
        if isinstance(rule, SigmaRule):
            for section_title, detection in rule.detection.detections.items():
                if (
                    re.match(r"^sel.*", section_title)
                    and (r := self.apply_detection(detection)) is not None
                ):
                    rule.custom_attributes["event_types"].update(r)


class EventTypeFieldMappingTransformation(FieldMappingTransformation):
    """
    Dynamically sets the mapping dictionary based on the Sigma rule's custom attribute 'event_types'.
    """

    def __init__(self):
        super().__init__({})  # Initialize parent class with an empty mapping for now

    def apply(
        self,
        rule: SigmaRule | SigmaCorrelationRule,
    ) -> None:
        """Apply dynamic mapping before the field name transformations."""
        self.set_event_type_mapping(rule)  # Dynamically update the mapping
        super().apply(rule)  # Call parent method to continue the transformation process

    def set_event_type_mapping(self, rule: SigmaRule):
        """
        Set the mapping dynamically based on the rule's custom attribute 'event_types'.
        Update the mapping dict to ensure the first event type field mappings
        override the last ones in the event the same field is present in multiple event types mappings
        """
        event_types = rule.custom_attributes.get("event_types", set())
        if event_types:
            # Convert set to list and reverse it
            event_types_list = list(event_types)
            event_types_list.reverse()

            for event_type in event_types_list:
                if event_type_mappings := get_field_mappings_by_event_type(event_type):
                    self.mapping.update(event_type_mappings)
