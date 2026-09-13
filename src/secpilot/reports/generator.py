from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Template

from secpilot.models import Evidence, SecurityAssessment
from secpilot.sessions.store import SessionRecord, SessionStore

_MD_TEMPLATE = Template(
    """# Security Assessment — {{ session.label }}

## Executive Summary

{{ assessment.executive_summary }}

## Scope

- Target: `{{ session.target }}`
- Mode: `{{ session.mode }}`
- Session: `{{ session.session_id }}`

## Methodology

{% for step in assessment.methodology %}- {{ step }}
{% endfor %}

## Asset Inventory

{% for service in assessment.exposed_services %}- {{ service.port }}/{{ service.proto }} {{ service.service }}
{% else %}- No services recorded
{% endfor %}

## Findings

{% for finding in assessment.findings %}
### {{ finding.severity.value | upper }} — {{ finding.title }}

{{ finding.summary }}

{% if finding.recommendation %}Recommendation: {{ finding.recommendation }}
{% endif %}
Evidence: {{ finding.evidence_ids | join(", ") }}
{% endfor %}

## Evidence

{% for item in evidence %}- `{{ item.evidence_id }}` {{ item.tool }} — {{ item.summary }}
{% endfor %}

## Remediation

{% for finding in assessment.findings %}{% if finding.recommendation %}- {{ finding.recommendation }}
{% endif %}{% endfor %}

## Commands / Tools Used

{% for item in evidence %}- `{{ item.argv | join(" ") }}`
{% endfor %}

## Timeline

{% for event in events %}- {{ event.timestamp.strftime("%H:%M") }} {{ event.message }}
{% endfor %}

## Limitations

{% for item in assessment.limitations %}- {{ item }}
{% endfor %}
"""
)

_HTML_TEMPLATE = Template(
    """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SecPilot {{ session.label }}</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; color: #111; }
    h1, h2 { border-bottom: 1px solid #ddd; padding-bottom: .3rem; }
    .sev-critical, .sev-high { color: #9b1c1c; }
    .sev-medium { color: #9a3412; }
    .sev-low, .sev-informational { color: #1e3a5f; }
    code { background: #f4f4f5; padding: .1rem .3rem; }
  </style>
</head>
<body>
  <h1>Security Assessment — {{ session.label }}</h1>
  <p>{{ assessment.executive_summary }}</p>
  <h2>Scope</h2>
  <ul>
    <li>Target: <code>{{ session.target }}</code></li>
    <li>Mode: <code>{{ session.mode }}</code></li>
  </ul>
  <h2>Findings</h2>
  {% for finding in assessment.findings %}
    <h3 class="sev-{{ finding.severity.value }}">{{ finding.severity.value | upper }} — {{ finding.title }}</h3>
    <p>{{ finding.summary }}</p>
    <p>{{ finding.recommendation }}</p>
  {% endfor %}
</body>
</html>
"""
)


class ReportGenerator:
    def __init__(self, store: SessionStore) -> None:
        self.store = store

    def render(
        self,
        session: SessionRecord,
        assessment: SecurityAssessment,
        evidence: list[Evidence],
        fmt: str,
    ) -> str:
        events = self.store.events(session.directory)
        context = {
            "session": session,
            "assessment": assessment,
            "evidence": evidence,
            "events": events,
        }
        if fmt == "json":
            return json.dumps(
                {
                    "session": session.model_dump(mode="json"),
                    "assessment": assessment.model_dump(mode="json"),
                    "evidence": [item.model_dump(mode="json") for item in evidence],
                },
                indent=2,
                default=str,
            )
        if fmt == "html":
            return _HTML_TEMPLATE.render(**context)
        return _MD_TEMPLATE.render(**context)

    def write(
        self,
        session: SessionRecord,
        assessment: SecurityAssessment,
        evidence: list[Evidence],
        fmt: str,
    ) -> Path:
        text = self.render(session, assessment, evidence, fmt)
        suffix = {"markdown": "md", "html": "html", "json": "json"}[fmt]
        path = Path(session.directory) / f"report.{suffix}"
        path.write_text(text, encoding="utf-8")
        return path
