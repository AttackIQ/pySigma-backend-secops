from sigma.processing.postprocessing import QueryPostprocessingTransformation
from sigma.rule import SigmaRule


class PrependMetadataPostprocessingTransformation(QueryPostprocessingTransformation):
    def apply(self, rule: SigmaRule, query: str) -> str:  # type: ignore
        event_types = rule.custom_attributes.get("event_types", set())
        if self._pipeline.state.get("output_format", "default") == "yara_l":
            metadata_eventtype = " OR ".join(
                [f'$event1.metadata.event_type = "{event_type}"' for event_type in event_types]
            )
            return f"{metadata_eventtype}\n\n{query}"
        else:
            metadata_eventtype = " OR ".join([f'metadata.event_type = "{event_type}"' for event_type in event_types])
            return f"({metadata_eventtype}) AND ({query})"


class YaraLPostprocessingTransformation(QueryPostprocessingTransformation):
    def apply(self, rule: SigmaRule, query: str) -> str:  # type: ignore
        # Split the query into lines and remove any leading/trailing whitespace
        query_lines = [line.strip() for line in query.split("\n") if line.strip()]

        # Join the lines with proper indentation
        indented_query = "\n    ".join(query_lines)

        return f"""
rule {rule.title.lower().replace(" ", "_")} {{
  meta:
    id = "{rule.id}"
    title = "{rule.title}"
    description = "{rule.description}"
    author = "{rule.author}"
    reference = "{", ".join(rule.references)}"
    date = "{rule.date}"
    tags = "{", ".join(str(t) for t in rule.tags)}"
    severity = "{rule.level}"
    falsepositives = "{", ".join(rule.falsepositives) if rule.falsepositives else "Unknown"}"

  events:
    {indented_query}

  conditions:
    $event1
}}
    """
