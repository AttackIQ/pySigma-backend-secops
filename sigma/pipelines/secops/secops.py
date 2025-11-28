import json
from importlib import resources

from sigma.processing.conditions import (
    DetectionItemProcessingItemAppliedCondition,
    IncludeFieldCondition,
    RuleProcessingItemAppliedCondition,
    RuleProcessingStateCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline, QueryPostprocessingItem
from sigma.processing.transformations import (
    FieldMappingTransformation,
)

from .mappings import enum_mappings, get_field_mappings
from .postprocessing import PrependMetadataPostprocessingTransformation
from .transformations import (
    ConvertEnumValueTransformation,
    EnsureValidUDMFieldsTransformation,
    EventTypeFieldMappingTransformation,
    RemoveHashAlgoFromValueTransformation,
    SetPrependMetadataTransformation,
    SetRuleEventTypeFromEventIDTransformation,
    SetRuleEventTypeFromLogsourceTransformation,
)

# LOAD UDM SCHEMA
udm_schema = json.loads(resources.read_text("sigma.pipelines.secops", "udm_field_schema.json"))


# PROCESSING ITEM FACTORY FUNCTIONS
# In pySigma 1.0.0, ProcessingItems can only be bound to one pipeline.
# These factories create fresh instances for each pipeline instantiation.


def _set_prepend_metadata_proc_item(prepend_metadata: bool = True) -> ProcessingItem:
    return ProcessingItem(
        identifier="secops_set_prepend_metadata",
        transformation=SetPrependMetadataTransformation(prepend_metadata),
    )


def _set_event_type_proc_items() -> list:
    return [
        ProcessingItem(
            identifier="secops_set_event_type_from_logsource",
            transformation=SetRuleEventTypeFromLogsourceTransformation(),
        ),
        ProcessingItem(
            identifier="secops_set_event_type_from_event_id",
            transformation=SetRuleEventTypeFromEventIDTransformation(),
            field_name_conditions=[
                IncludeFieldCondition(["EventID"]),
            ],
            rule_conditions=[RuleProcessingItemAppliedCondition("secops_set_event_type_from_logsource")],
            rule_condition_negation=True,
        ),
    ]


def _event_type_field_mapping_proc_item() -> ProcessingItem:
    return ProcessingItem(
        identifier="secops_event_type_field_mappings",
        transformation=EventTypeFieldMappingTransformation(),
    )


def _common_field_mappings_proc_item() -> ProcessingItem:
    return ProcessingItem(
        identifier="secops_common_field_mappings",
        transformation=FieldMappingTransformation(get_field_mappings().get("common")),
        detection_item_conditions=[DetectionItemProcessingItemAppliedCondition("secops_event_type_field_mappings")],
        detection_item_condition_linking=any,
        detection_item_condition_negation=True,
    )


def _convert_enum_values_proc_item() -> ProcessingItem:
    return ProcessingItem(
        identifier="secops_convert_enum_values",
        transformation=ConvertEnumValueTransformation(),
        field_name_conditions=[
            IncludeFieldCondition(list(enum_mappings.keys())),
        ],
    )


def _udm_validation_proc_item() -> ProcessingItem:
    return ProcessingItem(
        identifier="secops_udm_validation",
        transformation=EnsureValidUDMFieldsTransformation(udm_schema),
    )


def _remove_hash_algo_from_hashes_proc_item() -> ProcessingItem:
    return ProcessingItem(
        identifier="secops_remove_hash_algo_from_hashes",
        transformation=RemoveHashAlgoFromValueTransformation(),
        field_name_conditions=[
            IncludeFieldCondition(["hash"]),
        ],
    )


def _prepend_metadata_postprocessing_item() -> QueryPostprocessingItem:
    return QueryPostprocessingItem(
        identifier="secops_prepend_metadata_postprocessing",
        transformation=PrependMetadataPostprocessingTransformation(),
        rule_conditions=[RuleProcessingStateCondition(key="prepend_metadata", val=True)],
    )


def secops_udm_pipeline(prepend_metadata: bool = True) -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Google SecOps UDM Pipeline",
        priority=20,
        items=[
            _set_prepend_metadata_proc_item(prepend_metadata),
            *_set_event_type_proc_items(),
            _event_type_field_mapping_proc_item(),
            _common_field_mappings_proc_item(),
            _udm_validation_proc_item(),
            _convert_enum_values_proc_item(),
            _remove_hash_algo_from_hashes_proc_item(),
        ],
        postprocessing_items=[_prepend_metadata_postprocessing_item()],
        allowed_backends=["secops"],
    )
