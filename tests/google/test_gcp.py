import json
import pathlib

import httpx
import pytest

from howfuckedistheinternet import google


@pytest.mark.asyncio
async def test_get_gcp_incidents():
    result = await google.fetch_gcp_incidents()
    assert "affected_products" in result[0]


@pytest.mark.asyncio
async def test_get_gcp_incidents_non_json_input():
    with pytest.raises(json.JSONDecodeError):
        assert await google.fetch_gcp_incidents(url="https://example.com/") is None


@pytest.mark.asyncio
async def test_get_gcp_incidents_nonexistant_url():
    with pytest.raises((httpx.ConnectError, httpx.ConnectTimeout)):
        await google.fetch_gcp_incidents(url="https://asidnasdihnasdinasdadsada.com/")


@pytest.mark.asyncio
async def test_get_gcp_incidents_and_parse():
    """This really fetches from the Google GCP and so will fail if GCP is down.
    It doesn't really test anything, as we don't know what the results from GCP will be.
    It merely checks no exceptions are raised while fetching and parsing the current data.

    Some people will view this as a bad test, but GCP is a moving uncontrolled target.
    """
    results = await google.fetch_gcp_incidents()
    _ = google.parse_gcp_incidents(results)


@pytest.mark.asyncio
async def test_real_gcp_parse_defaults(gcp_test_data):
    parse = google.parse_gcp_incidents(gcp_test_data)
    parse == [
        google.GCPIncident(
            service="Google Compute Engine",
            severity="high",
            affected_locations=["asia-east1"],
            status_impact="SERVICE_DISRUPTION",
        )
    ]


@pytest.mark.asyncio
async def test_real_gcp_parse_severity_low(gcp_test_data):
    parse = google.parse_gcp_incidents(
        gcp_test_data, required_severity=google.GCPSeverity.LOW
    )
    assert parse == [
        google.GCPIncident(
            service="Google Compute Engine",
            severity="high",
            affected_locations=["asia-east1"],
            status_impact="SERVICE_DISRUPTION",
        ),
        google.GCPIncident(
            service="Google Cloud SQL",
            severity="low",
            affected_locations=["us-west4"],
            status_impact="SERVICE_DISRUPTION",
        ),
    ]


@pytest.fixture(scope="session")
def gcp_test_data(
    filename: pathlib.Path = pathlib.Path("tests/google/gcp_test_data.json"),
) -> str:
    with open(filename) as f:
        ret = json.load(f)
    return ret
