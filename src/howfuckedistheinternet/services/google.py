"""Handles Google"""

import dataclasses
import logging
import typing

import httpx
import ordered_enum

_DEFAULT_URL = "https://status.cloud.google.com/incidents.json"

GCPServiceName = str
GCPImpact = str
GCPLocation = str


class GCPSeverity(ordered_enum.OrderedEnum):  # type: ignore
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclasses.dataclass
class GCPIncident:
    service: str
    severity: GCPSeverity
    affected_locations: list[GCPLocation]
    status_impact: GCPImpact


async def fetch_gcp_incidents(
    url: str = _DEFAULT_URL,
) -> typing.Any:
    """Grabs the latest published incidents for GCP"""

    async with httpx.AsyncClient() as client:
        logging.debug("Fetching gcp incidents from: {}", url)
        response = await client.request(url=url, method="GET")
        logging.debug("Response from google was {}", response.text)
        return response.json()


def parse_gcp_incidents(
    incidents: dict[typing.Any, typing.Any],
    required_severity: GCPSeverity = GCPSeverity.HIGH,  # type: ignore
) -> list[GCPIncident]:
    """Filters for severity of service impacting incidents and for currently impacted regions
    If the regions list returns empty, then all listed incidents have been resolved so ignore it
    build a results dict keyed on service name containing a list of regions"""

    logging.debug("Parsing GCP incidents from json: {}", incidents)
    gcp_incidents = []

    for incident in incidents:
        if (
            incident.get("currently_affected_locations")
            and GCPSeverity(incident.get("severity")) >= required_severity
            and incident.get("status_impact")
            in ("SERVICE_DISRUPTION", "SERVICE_OUTAGE")
        ):
            relevant_incident = GCPIncident(
                service=incident.get("service_name"),
                severity=incident.get("severity"),
                status_impact=incident.get("status_impact"),
                affected_locations=[
                    x.get("id") for x in incident.get("currently_affected_locations")
                ],
            )
            logging.debug("Adding incident {}", relevant_incident)
            gcp_incidents.append(relevant_incident)

    return gcp_incidents
