"""Tests for ticketing integration adapters (Jira Cloud + ServiceNow).

Coverage:

 1. FindingTicket — valid construction
 2. FindingTicket — frozen (immutable)
 3. FindingTicket — rejects extra fields
 4. FindingTicket — entity_identifier min_length
 5. FindingTicket — score bounds (0-100)
 6. TicketResult — valid construction with defaults
 7. TicketResult — duplicate_of populated
 8. TicketingConfig — min_score default and bounds
 9. Jira — correct API URL for issue creation
10. Jira — Basic auth header format
11. Jira — field mapping (project, issuetype, summary, priority, labels)
12. Jira — CRITICAL finding maps to Bug issue type + Highest priority
13. Jira — ADF description body contains score and signals
14. Jira — duplicate detection via JQL returns existing key
15. Jira — duplicate found -> comment added instead of new issue
16. Jira — no duplicate -> new issue created
17. Jira — health check success
18. Jira — health check failure
19. Jira — API error returns failure result
20. ServiceNow — correct API URL for incident creation
21. ServiceNow — field mapping (assignment_group, urgency, category)
22. ServiceNow — urgency mapping per priority tier
23. ServiceNow — duplicate detection query
24. ServiceNow — duplicate found -> work note added
25. ServiceNow — health check success
26. ServiceNow — health check failure
27. ServiceNow — Bearer token auth when no colon in token
28. Both — disabled adapter config is detected
"""

from __future__ import annotations

import base64
import json
from uuid import UUID

import httpx
import pytest
import respx

from expose.integrations.jira import (
    JiraAdapter,
    _build_adf_description,
)
from expose.integrations.jira import (
    _build_auth_header as jira_build_auth,
)
from expose.integrations.servicenow import (
    ServiceNowAdapter,
    _build_description,
)
from expose.integrations.servicenow import (
    _build_auth_header as snow_build_auth,
)
from expose.integrations.ticketing import (
    FindingTicket,
    TicketingConfig,
    TicketResult,
)

# Deterministic test constants
TENANT_ID = UUID("018f1f00-0000-7000-8000-000000000001")
RUN_ID = UUID("018f1f00-0000-7000-8000-000000000099")
JIRA_ENDPOINT = "https://acme.atlassian.net"
SNOW_ENDPOINT = "https://acme.service-now.com"
AUTH_TOKEN = "user@example.com:xyztoken123456"  # noqa: S105
BEARER_TOKEN = "eyJhbGciOiJIUzI1NiJ9.bearer-test-token"  # noqa: S105
PROJECT_KEY = "SEC"


def _sample_finding(
    *,
    score: int = 75,
    priority_tier: str = "critical",
    entity: str = "staging.example.com",
) -> FindingTicket:
    return FindingTicket(
        entity_identifier=entity,
        entity_type="domain",
        score=score,
        priority_tier=priority_tier,
        justification="non-production endpoint and no WAF protection",
        contributing_signals=["non_production_exposed", "no_waf_protection"],
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
    )


def _jira_config(*, endpoint: str = JIRA_ENDPOINT) -> TicketingConfig:
    return TicketingConfig(
        adapter_type="jira",
        endpoint=endpoint,
        auth_token=AUTH_TOKEN,
        project_key=PROJECT_KEY,
    )


def _snow_config(*, endpoint: str = SNOW_ENDPOINT, auth_token: str = AUTH_TOKEN) -> TicketingConfig:
    return TicketingConfig(
        adapter_type="servicenow",
        endpoint=endpoint,
        auth_token=auth_token,
        project_key="Security Operations",
    )


# ======================================================================
# FindingTicket model tests
# ======================================================================


class TestFindingTicketModel:
    """FindingTicket Pydantic model validation."""

    def test_valid_construction(self) -> None:
        """A well-formed FindingTicket constructs without error."""
        ft = _sample_finding()
        assert ft.entity_identifier == "staging.example.com"
        assert ft.score == 75
        assert ft.priority_tier == "critical"
        assert ft.tenant_id == TENANT_ID
        assert ft.run_id == RUN_ID
        assert len(ft.contributing_signals) == 2

    def test_frozen(self) -> None:
        """FindingTicket is immutable (frozen=True)."""
        ft = _sample_finding()
        with pytest.raises(Exception):  # noqa: B017
            ft.score = 50  # type: ignore[misc]

    def test_extra_fields_rejected(self) -> None:
        """Extra fields are rejected (extra='forbid')."""
        with pytest.raises(Exception):  # noqa: B017
            FindingTicket(
                entity_identifier="test.com",
                entity_type="domain",
                score=50,
                priority_tier="high",
                justification="test",
                contributing_signals=[],
                tenant_id=TENANT_ID,
                bogus_field="not allowed",  # type: ignore[call-arg]
            )

    def test_entity_identifier_min_length(self) -> None:
        """entity_identifier must be at least 1 character."""
        with pytest.raises(Exception):  # noqa: B017
            FindingTicket(
                entity_identifier="",
                entity_type="domain",
                score=50,
                priority_tier="high",
                justification="test",
                contributing_signals=[],
                tenant_id=TENANT_ID,
            )

    def test_score_bounds(self) -> None:
        """Score must be 0-100."""
        with pytest.raises(Exception):  # noqa: B017
            _sample_finding(score=101)
        with pytest.raises(Exception):  # noqa: B017
            _sample_finding(score=-1)


# ======================================================================
# TicketResult model tests
# ======================================================================


class TestTicketResultModel:
    """TicketResult Pydantic model validation."""

    def test_success_with_defaults(self) -> None:
        """Success result has optional fields defaulted to None."""
        result = TicketResult(success=True, ticket_id="SEC-42")
        assert result.success is True
        assert result.ticket_id == "SEC-42"
        assert result.ticket_url is None
        assert result.duplicate_of is None
        assert result.error is None

    def test_duplicate_result(self) -> None:
        """Duplicate result carries the existing ticket ID."""
        result = TicketResult(
            success=True,
            ticket_id="SEC-10",
            ticket_url="https://acme.atlassian.net/browse/SEC-10",
            duplicate_of="SEC-10",
        )
        assert result.duplicate_of == "SEC-10"


# ======================================================================
# TicketingConfig model tests
# ======================================================================


class TestTicketingConfigModel:
    """TicketingConfig validation."""

    def test_min_score_default(self) -> None:
        """min_score defaults to 40."""
        config = _jira_config()
        assert config.min_score == 40

    def test_min_score_bounds(self) -> None:
        """min_score must be 0-100."""
        with pytest.raises(Exception):  # noqa: B017
            TicketingConfig(
                adapter_type="jira",
                endpoint=JIRA_ENDPOINT,
                auth_token=AUTH_TOKEN,
                project_key=PROJECT_KEY,
                min_score=101,
            )

    def test_disabled_adapter(self) -> None:
        """Disabled config is detected via enabled=False."""
        config = TicketingConfig(
            adapter_type="jira",
            endpoint=JIRA_ENDPOINT,
            auth_token=AUTH_TOKEN,
            project_key=PROJECT_KEY,
            enabled=False,
        )
        assert config.enabled is False


# ======================================================================
# Jira adapter tests
# ======================================================================


class TestJiraAdapter:
    """JiraAdapter — API interaction, field mapping, deduplication."""

    def test_auth_header_format(self) -> None:
        """Basic auth header is base64-encoded email:token."""
        header = jira_build_auth("user@example.com:api-token")
        expected = base64.b64encode(b"user@example.com:api-token").decode()
        assert header == f"Basic {expected}"

    def test_adf_description_contains_score(self) -> None:
        """ADF description body includes the score."""
        finding = _sample_finding(score=85)
        adf = _build_adf_description(finding)
        adf_text = json.dumps(adf)
        assert "85/100" in adf_text

    def test_adf_description_contains_signals(self) -> None:
        """ADF description body includes contributing signals."""
        finding = _sample_finding()
        adf = _build_adf_description(finding)
        adf_text = json.dumps(adf)
        assert "non_production_exposed" in adf_text
        assert "no_waf_protection" in adf_text

    @respx.mock
    async def test_correct_api_url(self) -> None:
        """Issue creation POSTs to /rest/api/3/issue."""
        # No duplicate found
        search_route = respx.get(f"{JIRA_ENDPOINT}/rest/api/3/search").mock(
            return_value=httpx.Response(200, json={"issues": []})
        )
        create_route = respx.post(f"{JIRA_ENDPOINT}/rest/api/3/issue").mock(
            return_value=httpx.Response(201, json={"key": "SEC-1", "id": "10001"})
        )

        adapter = JiraAdapter(_jira_config())
        await adapter.create_ticket(_sample_finding())

        assert search_route.called
        assert create_route.called

    @respx.mock
    async def test_field_mapping_critical(self) -> None:
        """CRITICAL finding maps to Bug type + Highest priority."""
        captured_body: dict = {}

        def _capture(request: httpx.Request) -> httpx.Response:
            captured_body.update(json.loads(request.content))
            return httpx.Response(201, json={"key": "SEC-1", "id": "10001"})

        respx.get(f"{JIRA_ENDPOINT}/rest/api/3/search").mock(
            return_value=httpx.Response(200, json={"issues": []})
        )
        respx.post(f"{JIRA_ENDPOINT}/rest/api/3/issue").mock(side_effect=_capture)

        adapter = JiraAdapter(_jira_config())
        await adapter.create_ticket(_sample_finding(score=75, priority_tier="critical"))

        fields = captured_body["fields"]
        assert fields["issuetype"]["name"] == "Bug"
        assert fields["priority"]["name"] == "Highest"
        assert fields["project"]["key"] == PROJECT_KEY
        assert "[EXPOSE]" in fields["summary"]
        assert "staging.example.com" in fields["summary"]
        assert "expose" in fields["labels"]
        assert "attack-surface" in fields["labels"]
        assert "critical" in fields["labels"]

    @respx.mock
    async def test_field_mapping_high(self) -> None:
        """HIGH finding maps to Task type + High priority."""
        captured_body: dict = {}

        def _capture(request: httpx.Request) -> httpx.Response:
            captured_body.update(json.loads(request.content))
            return httpx.Response(201, json={"key": "SEC-2", "id": "10002"})

        respx.get(f"{JIRA_ENDPOINT}/rest/api/3/search").mock(
            return_value=httpx.Response(200, json={"issues": []})
        )
        respx.post(f"{JIRA_ENDPOINT}/rest/api/3/issue").mock(side_effect=_capture)

        adapter = JiraAdapter(_jira_config())
        await adapter.create_ticket(_sample_finding(score=55, priority_tier="high"))

        fields = captured_body["fields"]
        assert fields["issuetype"]["name"] == "Task"
        assert fields["priority"]["name"] == "High"

    @respx.mock
    async def test_duplicate_detection_jql(self) -> None:
        """Duplicate check queries JQL with project and entity identifier."""
        captured_params: dict = {}

        def _capture(request: httpx.Request) -> httpx.Response:
            captured_params.update(dict(request.url.params))
            return httpx.Response(200, json={"issues": [{"key": "SEC-10"}]})

        respx.get(f"{JIRA_ENDPOINT}/rest/api/3/search").mock(side_effect=_capture)

        adapter = JiraAdapter(_jira_config())
        result = await adapter.check_duplicate("staging.example.com")

        assert result == "SEC-10"
        assert PROJECT_KEY in captured_params.get("jql", "")
        assert "staging.example.com" in captured_params.get("jql", "")
        assert "Done" in captured_params.get("jql", "")

    @respx.mock
    async def test_duplicate_found_adds_comment(self) -> None:
        """When duplicate exists, a comment is added instead of a new issue."""
        respx.get(f"{JIRA_ENDPOINT}/rest/api/3/search").mock(
            return_value=httpx.Response(200, json={"issues": [{"key": "SEC-10"}]})
        )
        comment_route = respx.post(f"{JIRA_ENDPOINT}/rest/api/3/issue/SEC-10/comment").mock(
            return_value=httpx.Response(201, json={"id": "20001"})
        )

        adapter = JiraAdapter(_jira_config())
        result = await adapter.create_ticket(_sample_finding())

        assert comment_route.called
        assert result.success is True
        assert result.duplicate_of == "SEC-10"
        assert result.ticket_id == "SEC-10"

    @respx.mock
    async def test_no_duplicate_creates_new(self) -> None:
        """When no duplicate exists, a new issue is created."""
        respx.get(f"{JIRA_ENDPOINT}/rest/api/3/search").mock(
            return_value=httpx.Response(200, json={"issues": []})
        )
        create_route = respx.post(f"{JIRA_ENDPOINT}/rest/api/3/issue").mock(
            return_value=httpx.Response(201, json={"key": "SEC-42", "id": "10042"})
        )

        adapter = JiraAdapter(_jira_config())
        result = await adapter.create_ticket(_sample_finding())

        assert create_route.called
        assert result.success is True
        assert result.ticket_id == "SEC-42"
        assert result.duplicate_of is None
        assert f"{JIRA_ENDPOINT}/browse/SEC-42" == result.ticket_url

    @respx.mock
    async def test_health_check_success(self) -> None:
        """Health check returns True when /rest/api/3/myself responds 200."""
        respx.get(f"{JIRA_ENDPOINT}/rest/api/3/myself").mock(
            return_value=httpx.Response(200, json={"accountId": "abc123"})
        )

        adapter = JiraAdapter(_jira_config())
        assert await adapter.health_check() is True

    @respx.mock
    async def test_health_check_failure(self) -> None:
        """Health check returns False on 401."""
        respx.get(f"{JIRA_ENDPOINT}/rest/api/3/myself").mock(return_value=httpx.Response(401))

        adapter = JiraAdapter(_jira_config())
        assert await adapter.health_check() is False

    @respx.mock
    async def test_api_error_returns_failure(self) -> None:
        """Non-201 from issue creation returns a failure result."""
        respx.get(f"{JIRA_ENDPOINT}/rest/api/3/search").mock(
            return_value=httpx.Response(200, json={"issues": []})
        )
        respx.post(f"{JIRA_ENDPOINT}/rest/api/3/issue").mock(
            return_value=httpx.Response(400, text="Bad Request: missing field")
        )

        adapter = JiraAdapter(_jira_config())
        result = await adapter.create_ticket(_sample_finding())

        assert result.success is False
        assert "400" in (result.error or "")

    @respx.mock
    async def test_network_error_returns_failure(self) -> None:
        """httpx.ConnectError during creation returns failure result."""
        respx.get(f"{JIRA_ENDPOINT}/rest/api/3/search").mock(
            return_value=httpx.Response(200, json={"issues": []})
        )
        respx.post(f"{JIRA_ENDPOINT}/rest/api/3/issue").mock(
            side_effect=httpx.ConnectError("connection refused")
        )

        adapter = JiraAdapter(_jira_config())
        result = await adapter.create_ticket(_sample_finding())

        assert result.success is False
        assert "connection" in (result.error or "").lower()


# ======================================================================
# ServiceNow adapter tests
# ======================================================================


class TestServiceNowAdapter:
    """ServiceNowAdapter — API interaction, field mapping, deduplication."""

    @respx.mock
    async def test_correct_api_url(self) -> None:
        """Incident creation POSTs to /api/now/table/incident."""
        # No duplicate
        respx.get(f"{SNOW_ENDPOINT}/api/now/table/incident").mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        create_route = respx.post(f"{SNOW_ENDPOINT}/api/now/table/incident").mock(
            return_value=httpx.Response(
                201,
                json={"result": {"sys_id": "abc123", "number": "INC0010001"}},
            )
        )

        adapter = ServiceNowAdapter(_snow_config())
        await adapter.create_ticket(_sample_finding())

        assert create_route.called

    @respx.mock
    async def test_field_mapping(self) -> None:
        """Incident fields are correctly mapped from the finding."""
        captured_body: dict = {}

        def _capture(request: httpx.Request) -> httpx.Response:
            captured_body.update(json.loads(request.content))
            return httpx.Response(
                201,
                json={"result": {"sys_id": "abc123", "number": "INC0010001"}},
            )

        respx.get(f"{SNOW_ENDPOINT}/api/now/table/incident").mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        respx.post(f"{SNOW_ENDPOINT}/api/now/table/incident").mock(side_effect=_capture)

        adapter = ServiceNowAdapter(_snow_config())
        await adapter.create_ticket(_sample_finding(score=75, priority_tier="critical"))

        assert captured_body["assignment_group"] == "Security Operations"
        assert captured_body["urgency"] == "1"  # CRITICAL
        assert captured_body["impact"] == "2"
        assert captured_body["category"] == "Security"
        assert captured_body["subcategory"] == "Attack Surface"
        assert "[EXPOSE]" in captured_body["short_description"]
        assert "staging.example.com" in captured_body["short_description"]

    @respx.mock
    async def test_urgency_mapping_high(self) -> None:
        """HIGH priority maps to urgency 2."""
        captured_body: dict = {}

        def _capture(request: httpx.Request) -> httpx.Response:
            captured_body.update(json.loads(request.content))
            return httpx.Response(
                201,
                json={"result": {"sys_id": "abc", "number": "INC0010002"}},
            )

        respx.get(f"{SNOW_ENDPOINT}/api/now/table/incident").mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        respx.post(f"{SNOW_ENDPOINT}/api/now/table/incident").mock(side_effect=_capture)

        adapter = ServiceNowAdapter(_snow_config())
        await adapter.create_ticket(_sample_finding(score=55, priority_tier="high"))

        assert captured_body["urgency"] == "2"

    @respx.mock
    async def test_urgency_mapping_low(self) -> None:
        """LOW priority maps to urgency 3."""
        captured_body: dict = {}

        def _capture(request: httpx.Request) -> httpx.Response:
            captured_body.update(json.loads(request.content))
            return httpx.Response(
                201,
                json={"result": {"sys_id": "abc", "number": "INC0010003"}},
            )

        respx.get(f"{SNOW_ENDPOINT}/api/now/table/incident").mock(
            return_value=httpx.Response(200, json={"result": []})
        )
        respx.post(f"{SNOW_ENDPOINT}/api/now/table/incident").mock(side_effect=_capture)

        adapter = ServiceNowAdapter(_snow_config())
        await adapter.create_ticket(_sample_finding(score=10, priority_tier="low"))

        assert captured_body["urgency"] == "3"

    @respx.mock
    async def test_duplicate_detection(self) -> None:
        """Duplicate check queries with entity identifier and state filter."""
        captured_params: dict = {}

        def _capture(request: httpx.Request) -> httpx.Response:
            captured_params.update(dict(request.url.params))
            return httpx.Response(
                200,
                json={"result": [{"sys_id": "dup123", "number": "INC0010099"}]},
            )

        respx.get(f"{SNOW_ENDPOINT}/api/now/table/incident").mock(side_effect=_capture)

        adapter = ServiceNowAdapter(_snow_config())
        result = await adapter.check_duplicate("staging.example.com")

        assert result == "dup123"
        query = captured_params.get("sysparm_query", "")
        assert "staging.example.com" in query
        assert "state!=7" in query

    @respx.mock
    async def test_duplicate_found_adds_work_note(self) -> None:
        """When duplicate exists, a PATCH work note is added."""
        respx.get(f"{SNOW_ENDPOINT}/api/now/table/incident").mock(
            return_value=httpx.Response(
                200, json={"result": [{"sys_id": "dup456", "number": "INC0010099"}]}
            )
        )
        patch_route = respx.patch(f"{SNOW_ENDPOINT}/api/now/table/incident/dup456").mock(
            return_value=httpx.Response(
                200,
                json={"result": {"sys_id": "dup456", "number": "INC0010099"}},
            )
        )

        adapter = ServiceNowAdapter(_snow_config())
        result = await adapter.create_ticket(_sample_finding())

        assert patch_route.called
        assert result.success is True
        assert result.duplicate_of == "dup456"

    @respx.mock
    async def test_health_check_success(self) -> None:
        """Health check returns True when incident table responds 200."""
        respx.get(f"{SNOW_ENDPOINT}/api/now/table/incident").mock(
            return_value=httpx.Response(200, json={"result": []})
        )

        adapter = ServiceNowAdapter(_snow_config())
        assert await adapter.health_check() is True

    @respx.mock
    async def test_health_check_failure(self) -> None:
        """Health check returns False on connection error."""
        respx.get(f"{SNOW_ENDPOINT}/api/now/table/incident").mock(
            side_effect=httpx.ConnectError("refused")
        )

        adapter = ServiceNowAdapter(_snow_config())
        assert await adapter.health_check() is False

    def test_bearer_token_auth(self) -> None:
        """Token without colon uses Bearer auth."""
        header = snow_build_auth(BEARER_TOKEN)
        assert header == f"Bearer {BEARER_TOKEN}"

    def test_basic_auth_with_colon(self) -> None:
        """Token with colon uses Basic auth."""
        header = snow_build_auth("admin:password123")
        expected = base64.b64encode(b"admin:password123").decode()
        assert header == f"Basic {expected}"

    def test_description_builder(self) -> None:
        """Plain-text description includes all finding fields."""
        finding = _sample_finding()
        desc = _build_description(finding)
        assert "staging.example.com" in desc
        assert "75/100" in desc
        assert "CRITICAL" in desc
        assert "non_production_exposed" in desc
        assert str(TENANT_ID) in desc
        assert str(RUN_ID) in desc
