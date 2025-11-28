from functools import lru_cache

from .utils import get_field_mapping_type

# TODO: EventType field in sysmon logs, ensure value is valid for metadata.event_type
# TODO: Add mappings/transformations for LogonType to Authentication.Mechanism enum conversion for logon events


@lru_cache(maxsize=128)
def get_field_mappings() -> dict[str, dict[str, str]]:
    return {
        "common": {
            "AccessMask": "target.process.access_mask",
            "User": "user",
            "Image": "file_path",
            "GrandparentImage": "file_path",
            "GrandparentProcessId": "process_id",
            "ParentImage": "file_path",
            "ProcessId": "process_id",
            "ParentProcessId": "process_id",
            "SourceHostname": "principal.hostname",
            "DestinationHostname": "target.hostname",
            "EventID": "metadata.product_event_type",
            "Provider_Name": "metadata.product_name",
            "ServiceName": "target.process.file.names",
            "ServiceFileName": "file_path",
            "AccountName": "user",
            "SubjectUserName": "principal.user.userid",
            "SubjectDomainName": "domain",
            "TargetUserName": "target.user.userid",
            "TargetDomainName": "domain",
            "IpAddress": "ip",
            "IpPort": "principal.port",
            "WorkstationName": "hostname",
            "Hostname": "hostname",
            "ComputerName": "hostname",
            "Hashes": "hash",
            "md5": "hash",
            "sha1": "hash",
            "sha256": "hash",
            "sha512": "hash",
            "imphash": "hash",
        },
        "process": {
            "CommandLine": "target.process.command_line",
            "CurrentDirectory": "target.process.file.full_path",
            "Image": "target.process.file.full_path",
            "GrandparentCommandLine": "principal.process.parent_process.command_line",
            "OriginalFileName": "target.process.file.names",
            "ParentImage": "principal.process.file.full_path",
            "ParentCommandLine": "principal.process.command_line",
            "ProcessGuid": "target.process.product_specific_process_id",
            "ProcessId": "target.process.pid",
            "ParentProcessImage": "principal.process.file.full_path",
            "ParentProcessCommandLine": "principal.process.command_line",
            "ParentProcessId": "principal.process.pid",
            "ParentProcessGuid": "principal.process.product_specific_process_id",
            "ParentUser": "principal.user.userid",
            "IntegrityLevel": "target.process.integrity_level_rid",
            "User": "target.user.userid",
        },
        "network": {
            "SourceIp": "principal.ip",
            "DestinationIp": "target.ip",
            "SourcePort": "principal.port",
            "DestinationPort": "target.port",
            "Protocol": "network.ip_protocol",
            "Image": "principal.process.file.full_path",
            "Initiated": "network.direction",
            "User": "principal.user.userid",
            "DestinationHostname": "target.hostname",
            "SourceHostname": "principal.hostname",
            "QueryName": "network.dns.questions.name",
            "QueryResults": "network.dns.answers.data",
            "QueryStatus": "network.dns.response_code",
        },
        "file": {
            "TargetFilename": "target.file.names",
            "Image": "target.process.file.full_path",
            "ObjectName": "target.file.full_path",
            "OldName": "target.file.names",
            "NewName": "target.file.names",
            "OriginalFileName": "target.file.names",
        },
        "authentication": {
            "TargetUserName": "target.user.userid",
            "SubjectUserName": "principal.user.user_display_name",
            "TargetOutboundUserName": "target.user.userid",
            "TargetUserSid": "target.user.windows_sid",
            "TargetServerName": "target.hostname",
            "WorkstationName": "principal.hostname",
            "IpAddress": "principal.ip",
            "IpPort": "principal.port",
            "LogonGuid": "principal.user.product_object_id",
        },
        "registry": {
            "TargetObject": "target.registry.registry_key",
            "Details": "target.registry.registry_value_data",
            "EventType": "metadata.event_type",
            "Image": "principal.process.file.full_path",
            "ProcessId": "principal.process.pid",
            "User": "principal.user.userid",
            "ObjectName": "target.registry.registry_key",
            "ObjectValueName": "target.registry.registry_value_name",
            "NewName": "target.registry.registry_key",
        },
        "dns": {
            "QueryName": "network.dns.questions.name",
            "QueryResults": "network.dns.answers.data",
            "QueryStatus": "network.dns.response_code",
            "record_type": "network.dns.questions.type",
            "answers": "network.dns.answers.name",
        },
    }


def get_field_mappings_by_event_type(metadata_event_type: str) -> dict[str, str]:
    """
    Get the field mappings for a given event type

    Args:
        metadata_event_type (str): The event type to get the field mappings for

    Returns:
        Dict[str, str]: The field mappings for the given event type
    """

    event_type = get_field_mapping_type(metadata_event_type)
    if not event_type:
        return {}

    all_mappings = get_field_mappings()
    return all_mappings.get(event_type, {})


enum_mappings = {
    "network.direction": {  # From Initiated sysmon field
        "Inbound": "INBOUND",
        "Outbound": "OUTBOUND",
        "Broadcast": "BROADCAST",
        "true": "OUTBOUND",
        "false": "INBOUND",
    }
}
