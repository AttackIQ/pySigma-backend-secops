from sigma.pipelines.secops.postprocessing import (
    PrependMetadataPostprocessingTransformation,
)
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule


def test_prepend_metadata_postprocessing():
    rule = SigmaRule.from_yaml(
        """
        title: Test Prepend Metadata
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                CommandLine: mimikatz.exe
            condition: selection
    """
    )

    # Add event types to rule
    rule.custom_attributes["event_types"] = {"PROCESS_LAUNCH", "PROCESS_TERMINATE"}

    pipeline = ProcessingPipeline()
    transform = PrependMetadataPostprocessingTransformation()
    transform._pipeline = pipeline

    # Test default format
    result = transform.apply(rule, "target.process.command_line = mimikatz.exe")
    assert "metadata.event_type =" in result
    assert "AND" in result

    # Test YARA-L format
    pipeline.state["output_format"] = "yara_l"
    result = transform.apply(rule, "target.process.command_line = mimikatz.exe")
    assert "$event1.metadata.event_type =" in result
    assert "OR" in result
