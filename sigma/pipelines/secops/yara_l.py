from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline, QueryPostprocessingItem

from .postprocessing import YaraLPostprocessingTransformation
from .transformations import PrependEventVariableTransformation


def _prepend_event_variable_item() -> ProcessingItem:
    return ProcessingItem(
        identifier="yara_l_prepend_event_variable",
        transformation=PrependEventVariableTransformation(mapping={}),
    )


def _output_format_postprocessing_item() -> QueryPostprocessingItem:
    return QueryPostprocessingItem(
        identifier="yara_l_output_format_postprocessing",
        transformation=YaraLPostprocessingTransformation(),
    )


def yara_l_pipeline() -> ProcessingPipeline:
    """Google SecOps backend format pipeline for YARA-L 2.0 output format
    Not for use as a general purpose pipeline, use the secops pipeline instead.
    """

    return ProcessingPipeline(
        name="Google SecOps YARA-L 2.0 Output Format Pipeline",
        priority=60,
        items=[_prepend_event_variable_item()],
        postprocessing_items=[_output_format_postprocessing_item()],
        allowed_backends=["secops"],
    )
