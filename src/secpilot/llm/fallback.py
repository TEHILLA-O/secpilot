from __future__ import annotations

from secpilot.models import (
    Evidence,
    ExecutionMode,
    Finding,
    Intensity,
    OperationCategory,
    ProposedOperation,
    SecurityAssessment,
    SecurityContext,
    SecurityPlan,
    Severity,
)
from secpilot.policy.scope import extract_targets


class FallbackPlanner:
    """Deterministic planner used when no model is configured or a provider fails."""

    name = "fallback"
    model = "rules"

    async def plan(self, context: SecurityContext) -> SecurityPlan:
        targets = extract_targets(context.user_query)
        target = targets[0] if targets else "localhost"
        query = context.user_query.lower()
        operations: list[ProposedOperation] = []
        tools: list[str] = []

        def add(category: OperationCategory, tool: str, extra: dict | None = None) -> None:
            if tool not in context.available_tools and context.available_tools:
                return
            operations.append(
                ProposedOperation(
                    id=f"op-{len(operations) + 1}",
                    category=category,
                    target=target,
                    intensity=Intensity.NORMAL,
                    rationale="deterministic planner selected a defensive check",
                    extra=extra or {},
                )
            )
            if tool not in tools:
                tools.append(tool)

        wants_host = any(word in query for word in ("audit", "harden", "lynis", "local"))
        wants_web = any(word in query for word in ("http", "web", "tls", "ssl", "https"))
        add(OperationCategory.SERVICE_DISCOVERY, "nmap")
        add(OperationCategory.SERVICE_VERSION, "nmap")
        if wants_web or "exposed" in query or "unusual" in query:
            add(OperationCategory.TLS_INSPECTION, "openssl")
            add(OperationCategory.HTTP_PROBE, "curl", {"scheme": "http"})
            add(OperationCategory.WEB_FINGERPRINT, "whatweb", {"scheme": "http"})
        if wants_host and context.mode is not ExecutionMode.OBSERVE:
            add(OperationCategory.HOST_AUDIT, "lynis")
        if not operations:
            add(OperationCategory.SERVICE_DISCOVERY, "nmap")
        return SecurityPlan(
            target=target,
            authorization_notes="Deterministic plan; policy engine still decides executability.",
            operations=operations,
            tools=tools,
            risk="LOW",
            exploitation=False,
            summary="Defensive reconnaissance and configuration review only.",
            in_scope=True,
        )

    async def analyse(
        self, evidence: list[Evidence], context: SecurityContext
    ) -> SecurityAssessment:
        services: list[dict] = []
        findings: list[Finding] = []
        for item in evidence:
            for service in item.parsed_data.get("services") or []:
                if service not in services:
                    services.append(service)
            if item.severity.value in {"high", "medium", "critical", "low"}:
                findings.append(
                    Finding(
                        title=item.summary,
                        severity=item.severity,
                        summary=item.summary,
                        evidence_ids=[item.evidence_id],
                        recommendation=_recommendation(item),
                        target=item.target,
                    )
                )
        if not findings:
            findings.append(
                Finding(
                    title="Assessment complete",
                    severity=Severity.INFORMATIONAL,
                    summary="No high-severity conditions were derived from collected evidence.",
                    recommendation="Review raw evidence if the operator expected additional coverage.",
                    target=context.user_query,
                )
            )
        return SecurityAssessment(
            target=evidence[0].target if evidence else "unknown",
            executive_summary=(
                f"Reviewed {len(evidence)} evidence item(s) and identified {len(findings)} finding(s)."
            ),
            exposed_services=services,
            findings=findings,
            limitations=[
                "No exploitation was performed.",
                "Results reflect only authorized tools and the configured scope.",
            ],
            methodology=[item.command_category for item in evidence],
        )


def _recommendation(item: Evidence) -> str:
    if "5432" in item.summary or "3306" in item.summary:
        return (
            "Restrict the database listener to the application or private network "
            "unless remote access is intentionally required."
        )
    if item.finding_type.value == "weak_tls":
        return "Disable outdated protocol versions and weak cipher suites."
    if item.finding_type.value == "http":
        return "Keep HTTP-to-HTTPS redirection and review exposed headers."
    return "Review the finding against the intended security baseline."
