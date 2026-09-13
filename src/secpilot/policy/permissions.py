from __future__ import annotations

from secpilot.models import ExecutionMode, OperationCategory

# Categories that never execute, regardless of mode or approval.
DENIED_ALWAYS = {
    "exploit",
    "payload",
    "persistence",
    "credential_exfil",
    "data_destruction",
    "lateral_movement",
    "privilege_escalation_attack",
}

# Packet capture and deep file scans stay LAB-only.
LAB_ONLY = {
    OperationCategory.PACKET_CAPTURE,
    OperationCategory.YARA_SCAN,
}

# Observe never executes tools; these are the only categories audit may run.
AUDIT_ALLOWED = {
    OperationCategory.SERVICE_DISCOVERY,
    OperationCategory.SERVICE_VERSION,
    OperationCategory.DNS_LOOKUP,
    OperationCategory.WHOIS_LOOKUP,
    OperationCategory.HTTP_PROBE,
    OperationCategory.TLS_INSPECTION,
    OperationCategory.WEB_FINGERPRINT,
    OperationCategory.HOST_AUDIT,
    OperationCategory.SERVICE_STATUS,
    OperationCategory.LOG_REVIEW,
    OperationCategory.FILE_IDENTIFY,
    OperationCategory.STRINGS_EXTRACT,
    OperationCategory.METADATA_EXTRACT,
}


class PermissionMatrix:
    def allowed(self, mode: ExecutionMode, category: OperationCategory) -> tuple[bool, str]:
        if mode is ExecutionMode.OBSERVE:
            return False, "observe mode cannot execute tools"
        if category in LAB_ONLY and mode is not ExecutionMode.LAB:
            return False, f"{category.value} is only available in lab mode"
        if mode is ExecutionMode.AUDIT and category not in AUDIT_ALLOWED:
            return False, f"{category.value} is not permitted in audit mode"
        return True, "permitted"

    def execution_enabled(self, mode: ExecutionMode) -> bool:
        return mode is not ExecutionMode.OBSERVE
