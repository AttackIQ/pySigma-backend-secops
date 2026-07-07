from sigma.pipelines.secops.postprocessing import (
    PrependMetadataPostprocessingTransformation,
    YaraLPostprocessingTransformation,
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

    rule.custom_attributes["event_types"] = {"PROCESS_LAUNCH", "PROCESS_TERMINATE"}

    pipeline = ProcessingPipeline()
    transform = PrependMetadataPostprocessingTransformation()
    transform._pipeline = pipeline

    result = transform.apply(rule, "target.process.command_line = mimikatz.exe")
    assert "metadata.event_type =" in result
    assert "AND" in result

    pipeline.state["output_format"] = "yara_l"
    result = transform.apply(rule, "target.process.command_line = mimikatz.exe")
    assert "$event1.metadata.event_type =" in result
    assert "OR" in result


def test_yara_l_meta_omits_unset_optional_fields():
    rule = SigmaRule.from_yaml(
        """
        title: Meta Omission Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: valueA
            condition: sel
        """
    )

    pipeline = ProcessingPipeline()
    pipeline.state["output_format"] = "yara_l"

    transform = YaraLPostprocessingTransformation()
    transform._pipeline = pipeline

    result = transform.apply(rule, '$event1.target.process.command_line = "valueA"')

    assert '    title = "Meta Omission Test"' in result
    assert '= "None"' not in result
    assert '    id =' not in result
    assert '    description =' not in result
    assert '    author =' not in result
    assert '    reference =' not in result
    assert '    date =' not in result
    assert '    tags =' not in result
    assert '    severity =' not in result
    assert '    falsepositives =' not in result


def test_yara_l_meta_preserves_set_optional_fields():
    rule = SigmaRule.from_yaml(
        """
        title: Meta Complete Test
        id: 11111111-1111-1111-1111-111111111111
        status: test
        description: Test description
        author: Anwesh Mahapatra
        references:
            - https://example.com/ref1
            - https://example.com/ref2
        date: 2026-07-07
        tags:
            - attack.execution
            - attack.t1059
        level: high
        falsepositives:
            - Admin activity
            - Testing
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: valueA
            condition: sel
        """
    )

    pipeline = ProcessingPipeline()
    pipeline.state["output_format"] = "yara_l"

    transform = YaraLPostprocessingTransformation()
    transform._pipeline = pipeline

    result = transform.apply(rule, '$event1.target.process.command_line = "valueA"')

    assert '    id = "11111111-1111-1111-1111-111111111111"' in result
    assert '    title = "Meta Complete Test"' in result
    assert '    description = "Test description"' in result
    assert '    author = "Anwesh Mahapatra"' in result
    assert '    reference = "https://example.com/ref1, https://example.com/ref2"' in result
    assert '    date = "2026-07-07"' in result
    assert '    tags = "attack.execution, attack.t1059"' in result
    assert '    severity = "high"' in result
    assert '    falsepositives = "Admin activity, Testing"' in result
