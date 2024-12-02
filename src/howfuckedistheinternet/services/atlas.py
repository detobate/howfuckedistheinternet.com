""" All RIPE Atlas based checks"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import config
import requests
import ujson
from certvalidator import CertificateValidator, errors

base_url = "https://atlas.ripe.net/api/v2/measurements/"


def fetch_atlas_results(url):
    """ Generic function to fetch results from RIPE Atlas API """
    try:
        results = ujson.loads(
            requests.get(url, headers=config.headers, timeout=60).text
        )

    except requests.exceptions.RequestException as e:
        if config.debug:
            print(e)
        return None
    except (AttributeError, ujson.JSONDecodeError):
        if config.debug:
            print(f"failed to parse RIPE Atlas results from {url}")
        return None

    return results


def fetch_tls_certs():
    """ Gets x509 cert chains from RIPE Atlas probe's perspective, and does local validation. """
    https_measurements = {
        "www.youtube.com": {"v6": 62517823, "v4": 62517825},
        "www.netflix.com": {"v6": 62517770, "v4": 62517771},
        "www.amazon.com": {"v6": 62517772, "v4": 62517773},
        "www.ebay.com": {"v6": None, "v4": 62517853},
        "www.paypal.com": {"v6": None, "v4": 62517854},
        "www.tiktok.com": {"v6": None, "v4": 62696644},
        "www.aliexpress.com": {"v6": None, "v4": 62696649}
    }

    v6_https = {}
    v4_https = {}

    for server in https_measurements:
        if v6 := https_measurements[server].get("v6"):
            url_v6 = base_url + str(v6) + "/latest/"
            results_v6 = fetch_atlas_results(url_v6)
        else:
            results_v6 = None

        if results_v6:
            v6_https[server] = {"failed": [], "passed": []}
            for probe in results_v6:
                certs = probe.get('cert')

                if certs:
                    # RIPE Atlas API escapes forward slashes, so they need to be stripped out of the cert string
                    # and then converted to ByteStrings for consumption

                    # end cert MUST always come first: rfc8446#section-4.4.2
                    end_cert = bytes(certs[0].replace('\\', ''), 'ascii')

                    # But sometimes we'll also have intermediate cert(s)
                    if len(certs) > 1:
                        intermediate_certs = [bytes(x.replace('\\', ''), 'ascii') for x in certs[1:]]
                        validator = CertificateValidator(end_cert, intermediate_certs)
                    else:
                        validator = CertificateValidator(end_cert)

                    try:
                        validator.validate_tls(server)
                        v6_https[server]['passed'].append(probe.get('prb_id'))
                    except (errors.InvalidCertificateError,
                            errors.PathValidationError,
                            errors.PathBuildingError):
                        v6_https[server]['failed'].append(probe.get('prb_id'))
                        if config.debug:
                            print(f"Probe {probe.get('prb_id')} received an invalid certificate for {server} over IPv6")
                    except:
                        print(f"Unknown TLS validation error: for {server} over IPv6. probe id: {probe.get('prb_id')}")
                else:
                    v6_https[server]['failed'].append(probe.get('prb_id'))
                    #if config.debug:
                    #    print(f"Probe {probe.get('prb_id')} received no certs from {server} over IPv6")

        if v4 := https_measurements[server].get("v4"):
            url_v4 = base_url + str(v4) + "/latest/"
            results_v4 = fetch_atlas_results(url_v4)
        else:
            results_v4 = None

        if results_v4:
            v4_https[server] = {"failed": [], "passed": []}
            for probe in results_v4:
                certs = probe.get('cert')

                if certs:
                    # end cert MUST always be first: rfc8446#section-4.4.2
                    end_cert = bytes(certs[0].replace('\\', ''), 'ascii')

                    # But sometimes we'll also have intermediate cert(s)
                    if len(certs) > 1:
                        intermediate_certs = [bytes(x.replace('\\', ''), 'ascii') for x in certs[1:]]
                        validator = CertificateValidator(end_cert, intermediate_certs)
                    else:
                        validator = CertificateValidator(end_cert)

                    try:
                        validator.validate_tls(server)
                        v4_https[server]['passed'].append(probe.get('prb_id'))
                    except (errors.InvalidCertificateError,
                            errors.PathValidationError,
                            errors.PathBuildingError):
                        v4_https[server]['failed'].append(probe.get('prb_id'))
                        if config.debug:
                            print(f"Probe {probe.get('prb_id')} received an invalid certificate for {server} over IPv4")
                    except:
                        print(f"Unknown TLS validation error: for {server} over IPv4. probe id: {probe.get('prb_id')}")
                else:
                    v4_https[server]['failed'].append(probe.get('prb_id'))
                    #if config.debug:
                    #    print(f"Probe {probe.get('prb_id')} received no certs from {server} over IPv4")

    return v6_https, v4_https


def fetch_public_dns_status():
    # RIPE Atlas Measurement IDs for Public DNS server measurements.
    dns_servers = {
        "8.8.8.8": 43869257,
        "8.8.4.4": None,
        "1.1.1.1": 12001626,
        "1.0.0.1": 62471673,
        "208.67.222.123": 56955213,
        "208.67.220.123": 56955214,
        "2001:4860:4860::8888": 62469965,
        "2001:4860:4860::8844": 62470008,
        "2606:4700:4700::1111": 62469962,
        "2606:4700:4700::1001": 62469963,
        "2620:119:35::35": 62469959,
        "2620:119:53::53": 62469961
    }

    dns_results = {}

    for server in dns_servers:
        if dns_servers[server] is not None:
            dns_results[server] = {}
            dns_results[server] = {"failed": [], "passed": []}
            url = base_url + str(dns_servers[server]) + "/latest"

            results = fetch_atlas_results(url)
            if not results:
                if config.debug:
                    print(f"failed to fetch DNS measurement results from {url}")
                return dns_results

            for probe in results:
                try:
                    if probe["result"].get("ANCOUNT") > 0:
                        dns_results[server]["passed"].append(probe.get("prb_id"))
                    else:
                        dns_results[server]["failed"].append(probe.get("prb_id"))
                except KeyError:
                    if probe.get("error"):
                        dns_results[server]["failed"].append(probe.get("prb_id"))
                except TypeError:
                    # print(ujson.dumps(probe, indent=2))    # ToDo: investigate this error
                    pass

    return dns_results


def fetch_ntp_pool_status():
    # RIPE Atlas Measurement IDs for NTP.
    # Apparently NTP Pool Project are still dragging their IPv6 heels
    ntp_pools = {
        "africa.pool.ntp.org": {"v4": 58750160},
        "asia.pool.ntp.org": {"v4": 58750162},
        "europe.pool.ntp.org": {"v4": 58750164},
        "north-america.pool.ntp.org": {"v4": 58750166},
        "oceania.pool.ntp.org": {"v4": 58750168},
        "south-america.pool.ntp.org": {"v4": 58750170},
        "2.africa.pool.ntp.org": {"v6": 58749906},
        "2.asia.pool.ntp.org": {"v6": 58749908},
        "2.europe.pool.ntp.org": {"v6": 58749909},
        "2.north-america.pool.ntp.org": {"v6": 58749919},
        "2.oceania.pool.ntp.org": {"v6": 58749922},
        "2.south-america.pool.ntp.org": {"v6": 58749923},
    }

    ntp_results = {}

    for pool in ntp_pools:
        ntp_results[pool] = {}
        for af in ntp_pools[pool]:
            ntp_results[pool][af] = {"failed": [], "passed": []}
            url = base_url + str(ntp_pools[pool].get(af)) + "/latest"

            results = fetch_atlas_results(url)
            if not results:
                if config.debug:
                    print(f"failed to fetch NTP over IP{af} measurement results from {url}")
                return ntp_results

            for probe in results:
                if len(probe.get("result")[0]) == 6:
                    ntp_results[pool][af]["passed"].append(probe.get("prb_id"))
                else:
                    ntp_results[pool][af]["failed"].append(probe.get("prb_id"))

    return ntp_results


def fetch_ripe_atlas_status():
    """Uses the RIPE Atlas built-in connection measurement id 7000 to get last seen status for probes"""

    probe_status = {"connected": [], "disconnected": []}

    url = base_url + "7000/latest"

    results = fetch_atlas_results(url)
    if not results:
        if config.debug:
            print(f"failed to fetch RIPE Atlas probe connected status measurements from {url}")
        return probe_status

    for probe in results:
        if probe.get("event") == "disconnect":
            probe_status["disconnected"].append(probe.get("prb_id"))
        if probe.get("event") == "connect":
            probe_status["connected"].append(probe.get("prb_id"))

    return probe_status


def fetch_root_dns():
    # RIPE Atlas measurement IDs for root server DNSoUDP checks. QueryType SOA
    dns_roots = {
        "a.root-servers.net": {"v6": 10509, "v4": 10009},
        "b.root-servers.net": {"v6": 10510, "v4": 10010},
        "c.root-servers.net": {"v6": 10511, "v4": 10011},
        "d.root-servers.net": {"v6": 10512, "v4": 10012},
        "e.root-servers.net": {"v6": 10513, "v4": 10013},
        "f.root-servers.net": {"v6": 10504, "v4": 10004},
        "g.root-servers.net": {"v6": 10514, "v4": 10014},
        "h.root-servers.net": {"v6": 10515, "v4": 10015},
        "i.root-servers.net": {"v6": 10505, "v4": 10005},
        "j.root-servers.net": {"v6": 10516, "v4": 10016},
        "k.root-servers.net": {"v6": 10501, "v4": 10001},
        "l.root-servers.net": {"v6": 10510, "v4": 10008},
        "m.root-servers.net": {"v6": 10506, "v4": 10009},
    }

    v6_roots_failed = {}
    v4_roots_failed = {}

    for server in dns_roots:
        url_v6 = base_url + str(dns_roots[server].get("v6")) + "/latest/"
        url_v4 = base_url + str(dns_roots[server].get("v4")) + "/latest/"

        results_v6 = fetch_atlas_results(url_v6)
        if results_v6:
            v6_roots_failed[server] = {"total": len(results_v6), "failed": []}
            for probe in results_v6:
                if probe.get("error"):
                    v6_roots_failed[server]["failed"].append(probe.get("prb_id"))
        elif config.debug:
            print(f"failed to fetch IPv6 DNS Root Server measurements from {url_v6}")

        results_v4 = fetch_atlas_results(url_v4)
        if results_v4:
            v4_roots_failed[server] = {"total": len(results_v4), "failed": []}
            for probe in results_v4:
                if probe.get("error"):
                    v4_roots_failed[server]["failed"].append(probe.get("prb_id"))
        elif config.debug:
            print(f"failed to fetch IPv4 DNS Root Server measurements from {url_v4}")

    return v6_roots_failed, v4_roots_failed


def check_dns_roots(v6_roots_failed, v4_roots_failed):
    fucked_reasons = []

    for dns_root in v6_roots_failed:
        total = v6_roots_failed[dns_root].get("total")
        failed = len(v6_roots_failed[dns_root].get("failed"))
        percent_failed = round((failed / total * 100), 1)
        if percent_failed > config.metrics["dns_root"].get("threshold"):
            reason = f"[DNS] {dns_root} failed to respond to {percent_failed}% of {total} RIPE Atlas probes over IPv6"
            fucked_reasons.append(reason)
            if config.debug:
                print(reason)

    for dns_root in v4_roots_failed:
        total = v4_roots_failed[dns_root].get("total")
        failed = len(v4_roots_failed[dns_root].get("failed"))
        percent_failed = round((failed / total * 100), 1)
        if percent_failed > config.metrics["dns_root"].get("threshold"):
            reason = f"[DNS] {dns_root} failed to respond to {percent_failed}% of {total} RIPE Atlas probes over IPv4"
            fucked_reasons.append(reason)
            if config.debug:
                print(reason)

    return fucked_reasons


def check_public_dns(dns_results):
    fucked_reasons = []

    for server in dns_results:
        total = len(dns_results[server].get("failed")) + len(
            dns_results[server].get("passed")
        )
        failed = len(dns_results[server].get("failed"))
        try:
            percent_failed = round((failed / total * 100), 1)
        except ZeroDivisionError:
            percent_failed = 0
        if percent_failed > config.metrics["public_dns"].get("threshold"):
            reason = f"[DNS] {server} failed to recurse an A query from {percent_failed}% of {total} RIPE Atlas probes"
            fucked_reasons.append(reason)
            if config.debug:
                print(reason)

    return fucked_reasons


def check_tls_certs(certs, af):
    fucked_reasons = []

    for server in certs:
        total = len(certs[server].get("failed")) + len(
            certs[server].get("passed")
        )
        failed = len(certs[server].get("failed"))
        try:
            percent_failed = round((failed / total * 100), 1)
        except ZeroDivisionError:
            percent_failed = 0
        if percent_failed > config.metrics["tls"].get("threshold"):
            reason = f"[TLS] {percent_failed}% of {total} RIPE Atlas probes received invalid certs for {server} over IPv{af}"
            fucked_reasons.append(reason)
            if config.debug:
                print(reason)

    return fucked_reasons


def check_ripe_atlas_status(probe_status):
    fucked_reasons = []

    disconnected = len(probe_status["disconnected"])
    total = len(probe_status["connected"]) + disconnected

    try:
        avg = round((disconnected / total) * 100, 2)
    except ZeroDivisionError:
        avg = 0
        if config.debug:
            print("No RIPE Atlas probes to check")
    if avg > config.metrics["atlas_connected"].get("threshold"):
        reason = (
            f"[RIPE Atlas] {avg}% of previously active RIPE Atlas probes are now disconnected"
        )
        fucked_reasons.append(reason)
        if config.debug:
            print(reason)

    return fucked_reasons


def check_ntp(ntp_pool_status):
    fucked_reasons = []

    for server in ntp_pool_status:
        for af in ntp_pool_status[server]:
            failed = len(ntp_pool_status[server][af].get("failed"))
            total = len(ntp_pool_status[server][af].get("passed")) + failed

            try:
                avg = round((failed / total) * 100, 2)
            except ZeroDivisionError:
                avg = 0
                if config.debug:
                    print(f"No RIPE Atlas results for {server} over IP{af}")

            if avg > config.metrics["ntp"].get("threshold"):
                reason = f"[NTP] {server} failed to respond to {avg}% of {total} RIPE Atlas probes over IP{af}"
                fucked_reasons.append(reason)
                if config.debug:
                    print(reason)

    return fucked_reasons
