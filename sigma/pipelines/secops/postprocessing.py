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

        meta_lines = [f'    title = "{rule.title}"']

        if rule.id:
            meta_lines.append(f'    id = "{rule.id}"')
        if rule.description:
            meta_lines.append(f'    description = "{rule.description}"')
        if rule.author:
            meta_lines.append(f'    author = "{rule.author}"')
        if rule.references:
            meta_lines.append(f'    reference = "{", ".join(rule.references)}"')
        if rule.date:
            meta_lines.append(f'    date = "{rule.date}"')
        if rule.tags:
            meta_lines.append(f'    tags = "{", ".join(str(tag) for tag in rule.tags)}"')
        if rule.level:
            meta_lines.append(f'    severity = "{rule.level}"')
        if rule.falsepositives:
            meta_lines.append(f'    falsepositives = "{", ".join(rule.falsepositives)}"')

        meta_block = "\n".join(meta_lines)

        return f"""
rule {rule.title.lower().replace(" ", "_")} {{
  meta:
{meta_block}

  events:
    {indented_query}

  conditions:
    $event1
}}
    """