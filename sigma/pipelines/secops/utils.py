from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule


def get_rule_detection_fields(rule: SigmaRule) -> set[str]:
    fields = set()
    for detection_value in rule.detection.detections.values():
        fields.update(_get_fields_from_detection(detection_value))
    return fields


def _get_fields_from_detection(detection_value) -> set[str]:
    fields = set()
    if isinstance(detection_value, SigmaDetectionItem):
        if detection_value.field:
            fields.add(detection_value.field)
    elif isinstance(detection_value, SigmaDetection):
        for item in detection_value.detection_items:
            fields.update(_get_fields_from_detection(item))
    return fields


def determine_event_type_logsource(rule: SigmaRule) -> str | None:
    category = rule.logsource.category
    service = rule.logsource.service
    product = rule.logsource.product

    mappings = {**get_category_mapping(), **get_service_mapping(), **get_product_mapping()}

    return mappings.get(category) or mappings.get(service) or mappings.get(product)


def determine_event_type_event_id(event_id: str) -> str | None:
    return get_windows_event_id_mapping().get(event_id)


def get_category_mapping() -> dict[str, str]:
    return {
        "process_creation": "PROCESS_LAUNCH",
        "process_access": "PROCESS_OPEN",
        "process_termination": "PROCESS_TERMINATION",
        "image_load": "PROCESS_MODULE_LOAD",
        "file_event": "FILE_UNCATEGORIZED",
        "file_change": "FILE_MODIFICATION",
        "file_rename": "FILE_MOVE",
        "file_delete": "FILE_DELETION",
        "file_access": "FILE_READ",
        "registry_add": "REGISTRY_CREATION",
        "registry_delete": "REGISTRY_DELETION",
        "registry_set": "REGISTRY_MODIFICATION",
        "registry_event": "REGISTRY_UNCATEGORIZED",
        "network_connection": "NETWORK_CONNECTION",
        "dns_query": "NETWORK_DNS",
        "create_remote_thread": "PROCESS_INJECTION",
        "driver_load": "PROCESS_MODULE_LOAD",
        "create_stream_hash": "FILE_CREATION",
        "pipe_created": "FILE_CREATION",
    }


def get_service_mapping() -> dict[str, str]:
    return {
        "firewall": "NETWORK_CONNECTION",
        "dns": "NETWORK_DNS",
        "webserver": "NETWORK_HTTP",
        "proxy": "NETWORK_HTTP",
        "wmi": "PROCESS_LAUNCH",
        "powershell": "PROCESS_LAUNCH",
    }


def get_product_mapping() -> dict[str, str]:
    return {
        "apache": "NETWORK_HTTP",
        "nginx": "NETWORK_HTTP",
        "mysql": "RESOURCE_READ",
        "postgresql": "RESOURCE_READ",
    }


def get_windows_event_id_mapping() -> dict[str, str]:
    return {
        "1": "PROCESS_LAUNCH",
        "3": "NETWORK_CONNECTION",
        "4": "STATUS_UNCATEGORIZED",
        "5": "PROCESS_TERMINATION",
        "6": "PROCESS_MODULE_LOAD",
        "7": "PROCESS_MODULE_LOAD",
        "8": "PROCESS_INJECTION",
        "9": "FILE_READ",
        "10": "PROCESS_OPEN",
        "11": "FILE_CREATION",
        "12": "REGISTRY_UNCATEGORIZED",
        "13": "REGISTRY_UNCATEGORIZED",
        "14": "REGISTRY_UNCATEGORIZED",
        "15": "FILE_CREATION",
        "16": "STATUS_UPDATE",
        "17": "FILE_CREATION",
        "18": "FILE_OPEN",
        "19": "PROCESS_LAUNCH",
        "20": "PROCESS_LAUNCH",
        "21": "PROCESS_LAUNCH",
        "22": "NETWORK_DNS",
        "23": "FILE_DELETION",
        "24": "PROCESS_UNCATEGORIZED",
        "25": "PROCESS_TAMPERING",
        "26": "FILE_DELETION",
        "4624": "USER_LOGIN",
        "4625": "USER_LOGIN",
        "4688": "PROCESS_LAUNCH",
        "4663": "FILE_ACCESS",
        "5156": "NETWORK_CONNECTION",
        "4656": "FILE_ACCESS",
        "4660": "FILE_DELETE",
        "4657": "REGISTRY_CHANGE",
        "4697": "SERVICE_INSTALL",
        "4720": "USER_CREATION",
        "4728": "GROUP_MEMBER_ADD",
        "4732": "GROUP_MEMBER_ADD",
        "4756": "GROUP_MEMBER_ADD",
    }


def get_field_mapping_type(event_type: str) -> str:
    mapping = {
        "PROCESS_LAUNCH": "process",
        "PROCESS_TERMINATION": "process",
        "PROCESS_OPEN": "process",
        "PROCESS_MODULE_LOAD": "process",
        "PROCESS_INJECTION": "process",
        "PROCESS_TAMPERING": "process",
        "PROCESS_UNCATEGORIZED": "process",
        "FILE_CREATION": "file",
        "FILE_DELETION": "file",
        "FILE_MODIFICATION": "file",
        "FILE_READ": "file",
        "FILE_COPY": "file",
        "FILE_OPEN": "file",
        "FILE_MOVE": "file",
        "FILE_SYNC": "file",
        "FILE_UNCATEGORIZED": "file",
        "NETWORK_CONNECTION": "network",
        "NETWORK_FLOW": "network",
        "NETWORK_FTP": "network",
        "NETWORK_DHCP": "network",
        "NETWORK_DNS": "network",
        "NETWORK_HTTP": "network",
        "NETWORK_SMTP": "network",
        "NETWORK_UNCATEGORIZED": "network",
        "REGISTRY_CREATION": "registry",
        "REGISTRY_MODIFICATION": "registry",
        "REGISTRY_DELETION": "registry",
        "REGISTRY_UNCATEGORIZED": "registry",
        "USER_LOGIN": "authentication",
        "USER_LOGOUT": "authentication",
        "USER_CREATION": "authentication",
        "USER_CHANGE_PASSWORD": "authentication",
        "USER_CHANGE_PERMISSIONS": "authentication",
        "USER_UNCATEGORIZED": "authentication",
        "GENERIC_EVENT": "common",
        "STATUS_UNCATEGORIZED": "common",
        "STATUS_HEARTBEAT": "common",
        "STATUS_STARTUP": "common",
        "STATUS_SHUTDOWN": "common",
        "STATUS_UPDATE": "common",
    }
    return mapping.get(event_type)
