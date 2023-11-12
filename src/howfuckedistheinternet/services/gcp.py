import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import config
import requests
import ujson


def fetch_gcp():
    """Grabs the latest published incidents for GCP
    Filters for high severity service impacting incidents and for currently impacted regions
    If the regions list returns empty, then all listed incidents have been resolved so ignore it
    build a results dict keyed on service name containing a list of regions"""

    url = "https://status.cloud.google.com/incidents.json"

    gcp_results = {}

    try:
        results = ujson.loads(requests.get(url, headers=config.headers, timeout=60).text)
    except:
        if config.debug:
            print(f"failed to fetch GCP Incidents from {url}")
        return gcp_results

    for inc in results:
        if (
            inc.get("currently_affected_locations")
            and inc.get("severity") == "high"
            and inc.get("status_impact") in ("SERVICE_DISRUPTION", "SERVICE_OUTAGE")
        ):
            for region in inc.get("currently_affected_locations"):
                try:
                    gcp_results[inc.get("service_name")].append(region.get("id"))
                except KeyError:
                    gcp_results[inc.get("service_name")] = [region.get("id")]

    return gcp_results


def check_gcp(gcp_results):
    fucked_reasons = []

    if len(gcp_results) > config.metrics["gcp"].get("threshold"):
        for service, regions in gcp_results.items():
            if service == "Multiple Products":
                modifier = "are"
                # Bump up the weight for all GCP incidents
                config.metrics["gcp"]["adjusted_weight"] = config.metrics["gcp"]["weight"] + 1
            else:
                modifier = "is"
            if "global" in regions:
                reason = f"[GCP] {service} {modifier} down globally"
                # Bump up the weight for all GCP incidents
                config.metrics["gcp"]["adjusted_weight"] = config.metrics["gcp"]["weight"] + 1
            else:
                reason = (
                    f"[GCP] {service} {modifier} down in regions: {', '.join(regions)}"
                )

            fucked_reasons.append(reason)
            if config.debug:
                print(reason)

    return fucked_reasons
