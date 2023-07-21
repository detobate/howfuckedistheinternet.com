#!/usr/bin/env python3
import math
import requests
import time
import ujson
import sqlite3
from datetime import datetime, timezone

routinator_api_url = 'https://rpki-validator.ripe.net/api/v1/status'
bgp_table_url = 'https://bgp.tools/table.jsonl'
ripe_atlas_api_url = 'https://atlas.ripe.net/api/v2/measurements/'
root = '/var/www/howfuckedistheinternet.com/html/'
sqlitedb = 'howfucked.db'
aws_v4_file = 'aws_ec2_checkpoints.json'
aws_v6_file = 'aws_ec2_checkpointsv6.json'
gcp_incidents_url = 'https://status.cloud.google.com/incidents.json'
azure_incidents_url = 'https://azure.status.microsoft/en-gb/status/feed/'

max_history = 12                    # 6hrs at regular 30min updates
update_frequency = 1800             # 30 mins
write_sql_enabled = True
debug = True

# Adjust metric weighting based on importance
# threshold unit for literal measurements is %; measurements using historic averages have no thresholds
# Frequency to check each measurement type (seconds)
metrics = {'origins': {'enabled': True, 'weight': 0.1, 'threshold': None, 'freq': 1800,
                       'descr': 'Number of origin AS per prefix'},
           'prefixes': {'enabled': True, 'weight': 0.2, 'threshold': 85, 'freq': 1800,
                        'descr': 'Dramatic decrease in advertised prefixes by an AS'},
           'dns_root': {'enabled': True, 'weight': 10, 'threshold': 10, 'freq': 1800,
                        'descr': 'DNS root-server reachability using RIPE Atlas'},
           'atlas_connected': {'enabled': True, 'weight': 1, 'threshold': 20, 'freq': 1800,
                               'descr': 'RIPE Atlas probe connected status'},
           'invalid_roa': {'enabled': True, 'weight': 1, 'threshold': None, 'freq': 1800,
                           'descr': 'RPKI ROA validity'},
           'total_roa': {'enabled': True, 'weight': 5, 'threshold': 90, 'freq': 1800,
                         'descr': 'Dramatic decrease in published RPKI ROAs'},
           'dfz': {'enabled': True, 'weight': 3, 'threshold': 1, 'freq': 1800,
                   'descr': 'Dramatic increase or decrease of DFZ size'},
           'ntp': {'enabled': True, 'weight': 2, 'threshold': 30, 'freq': 1800,
                   'descr': 'NTP Pool Project checks using RIPE Atlas'},
           'public_dns': {'enabled': True, 'weight': 5, 'threshold': 25, 'freq': 1800,
                          'descr': 'Public DNS resolver checks using RIPE Atlas'},
           'aws': {'enabled': True, 'weight': 6, 'threshold': 10, 'freq': 1800,
                   'descr': 'AWS connectivity checks'},
           'gcp': {'enabled': True, 'weight': 1, 'threshold': 1, 'freq': 1800,  # gcp weight is scaled dynamically
                   'descr': 'GCP Incident Notifications'},
           'azure': {'enabled': False, 'weight': 1, 'threshold': 10, 'freq': 1800,
                     'descr': '[soon] Azure status checks'}
           }


def fetch_gcp(url, headers):
    """ Grabs the latest published incidents for GCP
        Filters for high severity service impacting incidents and for currently impacted regions
        If the regions list returns empty, then all listed incidents have been resolved so ignore it
        build a results dict keyed on service name containing a list of regions"""

    gcp_results = {}

    try:
        results = ujson.loads(requests.get(url, headers=headers, timeout=60).text)
    except:
        if debug:
            print(f"failed to fetch GCP Incidents from {url}")
        return gcp_results

    for inc in results:
        if inc.get('currently_affected_locations') and inc.get('severity') == 'high' and \
                inc.get('status_impact') in ('SERVICE_DISRUPTION', 'SERVICE_OUTAGE'):
            for region in inc.get('currently_affected_locations'):
                try:
                    gcp_results[inc.get('service_name')].append(region.get('id'))
                except KeyError:
                    gcp_results[inc.get('service_name')] = [region.get('id')]

    return gcp_results


def fetch_aws(aws_urls_file, headers):
    """ Attempts to fetch the green-icon.gif hosted in all regions for the specific purpose of connectivity checks
    see http://ec2-reachability.amazonaws.com
    Timeouts or HTTP errors are marked as failures """

    aws_results = {}
    with open(aws_urls_file, 'r') as f:
        aws_check_urls = ujson.loads(f.read())

    for region, urls in aws_check_urls.items():
        aws_results[region] = []
        for url in urls:
            try:
                r = requests.get(url, headers=headers, timeout=60)
                if r.ok:
                    aws_results[region].append(True)
                else:
                    aws_results[region].append(False)
            except:
                aws_results[region].append(False)

    return aws_results


def fetch_public_dns_status(base_url, headers):
    # RIPE Atlas Measurement IDs for Public DNS server measurements.
    dns_servers = {'8.8.8.8': 43869257, '8.8.4.4': None, '1.1.1.1': 12001626, '1.0.0.1': 56955212,
                   '208.67.222.123': 56955213, '208.67.220.123': 56955214}

    dns_results = {}

    for server in dns_servers:
        if dns_servers[server] is not None:
            dns_results[server] = {}
            dns_results[server] = {'failed': [], 'passed': []}
            url = base_url + str(dns_servers[server]) + '/latest'
            try:
                results = ujson.loads(requests.get(url, headers=headers, timeout=60).text)
            except:
                if debug:
                    print(f"failed to fetch RIPE Atlas results from {url}")
                return dns_results

            for probe in results:
                try:
                    if probe['result'].get('ANCOUNT') > 0:
                        dns_results[server]['passed'].append(probe.get('prb_id'))
                    else:
                        dns_results[server]['failed'].append(probe.get('prb_id'))
                except KeyError:
                    if probe.get('error'):
                        dns_results[server]['failed'].append(probe.get('prb_id'))
                except TypeError:
                    #print(ujson.dumps(probe, indent=2))    # ToDo: investigate this error
                    pass

    return dns_results


def fetch_ntp_pool_status(base_url, headers):
    # RIPE Atlas Measurement IDs for NTP.
    # Apparently NTP Pool Project are still dragging their IPv6 heels
    ntp_pools = {"africa.pool.ntp.org": {"v4": 56902185},
                 "asia.pool.ntp.org": {"v4": 56902186},
                 "europe.pool.ntp.org": {"v4": 56902187},
                 "north-america.pool.ntp.org": {"v4": 56902188},
                 "oceania.pool.ntp.org": {"v4": 56902189},
                 "south-america.pool.ntp.org": {"v4": 56902192},
                 "2.africa.pool.ntp.org": {"v6": 56913100},
                 "2.asia.pool.ntp.org": {"v6": 56913101},
                 "2.europe.pool.ntp.org": {"v6": 56913102},
                 "2.north-america.pool.ntp.org": {"v6": 56913103},
                 "2.oceania.pool.ntp.org": {"v6": 56913105},
                 "2.south-america.pool.ntp.org": {"v6": 56913106}
                 }

    ntp_results = {}

    for pool in ntp_pools:
        ntp_results[pool] = {}
        for af in ntp_pools[pool]:
            ntp_results[pool][af] = {'failed': [], 'passed': []}
            url = base_url + str(ntp_pools[pool].get(af))  + '/latest'
            try:
                results = ujson.loads(requests.get(url, headers=headers, timeout=60).text)
            except:
                if debug:
                    print(f"failed to fetch RIPE Atlas results from {url} over IP{af}")
                return ntp_results

            for probe in results:
                if len(probe.get('result')[0]) == 6:
                    ntp_results[pool][af]['passed'].append(probe.get('prb_id'))
                else:
                    ntp_results[pool][af]['failed'].append(probe.get('prb_id'))

    return ntp_results


def fetch_ripe_atlas_status(base_url, headers):
    """ Uses the RIPE Atlas built-in connection measurement id 7000 to get last seen status for probes """

    probe_status = {'connected': [], 'disconnected': []}

    url = base_url + '7000/latest'
    try:
        results = ujson.loads(requests.get(url, headers=headers, timeout=60).text)
    except:
        if debug:
            print(f"failed to fetch RIPE Atlas results from {url}")
        return probe_status

    for probe in results:
        if probe.get('event') == 'disconnect':
            probe_status['disconnected'].append(probe.get('prb_id'))
        if probe.get('event') == 'connect':
            probe_status['connected'].append(probe.get('prb_id'))

    return probe_status


def fetch_root_dns(base_url, headers):
    # RIPE Atlas measurement IDs for root server DNSoUDP checks. QueryType SOA
    dns_roots = {'a.root-servers.net': {'v6': 10509, 'v4': 10009},
                 'b.root-servers.net': {'v6': 10510, 'v4': 10010},
                 'c.root-servers.net': {'v6': 10511, 'v4': 10011},
                 'd.root-servers.net': {'v6': 10512, 'v4': 10012},
                 'e.root-servers.net': {'v6': 10513, 'v4': 10013},
                 'f.root-servers.net': {'v6': 10504, 'v4': 10004},
                 'g.root-servers.net': {'v6': 10514, 'v4': 10014},
                 'h.root-servers.net': {'v6': 10515, 'v4': 10015},
                 'i.root-servers.net': {'v6': 10505, 'v4': 10005},
                 'j.root-servers.net': {'v6': 10516, 'v4': 10016},
                 'k.root-servers.net': {'v6': 10501, 'v4': 10001},
                 'l.root-servers.net': {'v6': 10510, 'v4': 10008},
                 'm.root-servers.net': {'v6': 10506, 'v4': 10009},
                 }

    v6_roots_failed = {}
    v4_roots_failed = {}

    for server in dns_roots:
        url_v6 = base_url + str(dns_roots[server].get('v6')) + '/latest/'
        url_v4 = base_url + str(dns_roots[server].get('v4')) + '/latest/'

        try:
            results_v6 = ujson.loads(requests.get(url_v6, headers=headers, timeout=60).text)
            v6_roots_failed[server] = {'total': len(results_v6), 'failed': []}
            for probe in results_v6:
                if probe.get('error') is not None:
                    v6_roots_failed[server]['failed'].append(probe.get('prb_id'))
        except requests.exceptions.RequestException as e:
            if debug:
                print(f"failed to fetch DNSoUDP6 RIPE Atlas results from {url_v6}")
                print(e)
            else:
                pass
        except AttributeError:
            print(f"failed to fetch DNSoUDP6 RIPE Atlas results from {url_v6}")
            print(f"Check that the measurement ID {dns_roots[server].get('v6')} is correct")

        try:
            results_v4 = requests.get(url_v4).json()
            v4_roots_failed[server] = {'total': len(results_v4), 'failed': []}
            for probe in results_v4:
                if probe.get('error') is not None:
                    v4_roots_failed[server]['failed'].append(probe.get('prb_id'))
        except requests.exceptions.RequestException as e:
            if debug:
                print(f"failed to fetch DNSoUDP4 RIPE Atlas results from {url_v4}")
                print(e)
            else:
                pass
        except AttributeError:
            print(f"failed to fetch DNSoUDP4 RIPE Atlas results from {url_v4}")
            print(f"Check that the measurement ID {dns_roots[server].get('v4')} is correct")

    return v6_roots_failed, v4_roots_failed


def fetch_rpki_roa(url, headers):

    invalid_roa = {}
    total_roa = {}

    try:
        results = ujson.loads(requests.get(url, headers=headers, timeout=60).text)
    except:
        if debug:
            print(f"failed to fetch {url}")
        return invalid_roa, total_roa

    for repo in results.get('repositories'):
        invalid = results['repositories'][repo].get('invalidROAs')
        invalid_roa[repo] = invalid

        valid_roa = results['repositories'][repo].get('validROAs')
        total_roa[repo] = int(valid_roa + invalid)

    return invalid_roa, total_roa


def fetch_bgp_table(url, headers):
    """ Fetches BGP/DFZ info as json from bgp.tools
        Builds two dicts, keyed on ASN and Prefix"""

    table_asn_key = {}
    table_pfx_key = {}
    try:
        results = requests.get(url, headers=headers, timeout=60)
    except:
        if debug:
            print(f"failed to fetch {url}")
        return table_asn_key, table_pfx_key

    table_list = results.text.split('\n')

    for x in table_list:
        # Build a dict keyed on ASN
        try:
            x = ujson.loads(x)
        except ujson.JSONDecodeError:
            break
        try:
            asn = x.get('ASN')
            if asn in table_asn_key:
                table_asn_key[asn].append(x)
            else:
                table_asn_key[asn] = [x]
        except KeyError:
            break

        # Build a dict keyed on prefix
        try:
            pfx = x.get('CIDR')
            if pfx in table_pfx_key:
                table_pfx_key[pfx].append(x)
            else:
                table_pfx_key[pfx] = [x]
        except KeyError:
            break

    return table_asn_key, table_pfx_key


def check_aws(aws_results, af):
    fucked_reasons = []
    for region, results in aws_results.items():
        total = len(results)
        failed = results.count(False)
        try:
            pct_failed = round((failed / total) * 100, 1)
        except ZeroDivisionError:
            pct_failed = 0

        if pct_failed > metrics['aws'].get('threshold'):
            fucked_reasons.append(f"[AWS] {region} {pct_failed}% of connectivity checks over IPv{af} failed")

    return fucked_reasons


def check_bgp_origins(table_pfx_key, num_origins_history):
    """ Store the latest num of origin AS per prefix
        Check the history to see if any prefixes have an increased number of origin AS"""

    fucked_reasons = []

    for pfx in table_pfx_key:
        num_origins = len(table_pfx_key.get(pfx))
        if pfx in num_origins_history:
            num_origins_history[pfx].insert(0, num_origins)
            if len(num_origins_history.get(pfx)) > max_history:
                zz = num_origins_history[pfx].pop()
        else:
            num_origins_history[pfx] = [num_origins]

    # Check for an increase in origins, could signify hijacking
    for pfx, origins in num_origins_history.items():
        avg = sum(origins) / len(origins)

        # Exclude any multi-origin anycast prefixes
        if origins[0] > avg and avg < 2:
            reason = f"[Origins] {pfx} is being originated by {origins[0]} ASNs, above the " \
                     f"{((max_history * update_frequency) / 60 ) / 60}hrs average of {math.floor(avg)}"
            fucked_reasons.append(reason)
            if debug:
                print(reason)

        # Catch a sudden decrease in origins of anycast prefixes that usually have a lot
        if origins[0] < 2 and avg > 5:
            reason = f"[Origins] {pfx} is being originated by {origins[0]} ASNs, below the " \
                     f"{((max_history * update_frequency) / 60 ) / 60}hrs average of {math.floor(avg)}"
            fucked_reasons.append(reason)
            if debug:
                print(reason)

    return fucked_reasons, num_origins_history


def check_bgp_prefixes(table_asn_key, num_prefixes_history):
    """ Store the latest number of prefixes advertised per ASN
        Check the history to see if any ASNs have a drastically reduced number of prefixes"""

    fucked_reasons = []

    # Add latest result to the history
    for asn in table_asn_key:
        num_prefixes = len(table_asn_key.get(asn))
        if asn in num_prefixes_history:
            num_prefixes_history[asn].insert(0, num_prefixes)
            if len(num_prefixes_history.get(asn)) > max_history:
                zz = num_prefixes_history[asn].pop()
        else:
            num_prefixes_history[asn] = [num_prefixes]

    # Check for a drastic decrease in prefixes being advertised by an ASN
    for asn, prefixes in num_prefixes_history.items():
        avg = sum(prefixes) / len(prefixes)
        percentage = 100 - int(round((prefixes[0] / avg) * 100, 0))
        if percentage > metrics['prefixes'].get('threshold'):
            reason = f"[Prefixes] AS{asn} is originating only {prefixes[0]} prefixes, {percentage}% " \
                     f"fewer than the {((max_history * update_frequency) / 60 ) / 60}hrs average of {math.ceil(avg)}"
            fucked_reasons.append(reason)
            if debug:
                print(reason)

    return fucked_reasons, num_prefixes_history


def check_rpki_totals(total_roa, rpki_total_roa_history):
    """ Store the latest num of total ROAs
        Check the history to see if any repos have an increased number of Invalids and add to the fucked_reasons list """

    fucked_reasons = []

    for repo in total_roa:
        if repo in rpki_total_roa_history:
            rpki_total_roa_history[repo].insert(0, total_roa.get(repo))
            if len(rpki_total_roa_history) > max_history:
                zz = rpki_total_roa_history[repo].pop()
        else:
            rpki_total_roa_history[repo] = [total_roa.get(repo)]

    for repo, totals in rpki_total_roa_history.items():
        avg = int(sum(totals) / len(totals))
        try:
            percentage = (totals[0] / avg) * 100
        except ZeroDivisionError:
            percentage = 100
        if (100 - percentage) > metrics['total_roa'].get('threshold'):
            reason = f"[RPKI] {repo} has decreased published ROAs by {percentage}, from an average of {avg} to {totals[0]}"
            fucked_reasons.append(reason)
            if debug:
                print(reason)

    return fucked_reasons, rpki_total_roa_history


def check_rpki_invalids(invalid_roa, rpki_invalids_history):
    """ Store the latest num of invalid ROAs
        Check the history to see if any repos have an increased number of Invalids and add to the fucked_reasons list """

    fucked_reasons = []

    for repo in invalid_roa:
        if repo in rpki_invalids_history:
            rpki_invalids_history[repo].insert(0, invalid_roa.get(repo))
            if len(rpki_invalids_history) > max_history:
                zz = rpki_invalids_history[repo].pop()
        else:
            rpki_invalids_history[repo] = [invalid_roa.get(repo)]

    for repo, invalids in rpki_invalids_history.items():
        avg = sum(invalids) / len(invalids)
        if invalids[0] > avg:
            reason = f"[RPKI] {invalids[0]} ROAs from {repo} have invalid routes being advertised to the DFZ, " \
                            f"more than the {((max_history * update_frequency) / 60 ) / 60}hrs average of {math.floor(avg)}"
            fucked_reasons.append(reason)
            if debug:
                print(reason)

    return fucked_reasons, rpki_invalids_history


def check_dfz(table_pfx_key, num_dfz_routes_history):
    """ Keep track of the number of routes present in both the IPv4 and IPv6 DFZ
        Alert when DFZ size increases by dfz_threshold %
        Iterating this dict to parse v4 or v6 seems silly, but oh well.
    """

    fucked_reasons = []

    v6_dfz_count = 0
    v4_dfz_count = 0

    for pfx in table_pfx_key:
        if pfx.find('::/') > 0:
            v6_dfz_count += 1
        else:
            v4_dfz_count += 1

    num_dfz_routes_history['v6'].insert(0, v6_dfz_count)
    if len(num_dfz_routes_history['v6']) > max_history:
        num_dfz_routes_history['v6'].pop()

    num_dfz_routes_history['v4'].insert(0, v4_dfz_count)
    if len(num_dfz_routes_history['v4']) > max_history:
        num_dfz_routes_history['v4'].pop()

    avg_v6 = sum(num_dfz_routes_history['v6']) / len(num_dfz_routes_history['v6'])
    try:
        v6_pc = round(((num_dfz_routes_history['v6'][0] / avg_v6) * 100), 1)
    except ZeroDivisionError:
        v6_pc = 100

    if v6_pc - 100 > metrics['dfz'].get('threshold'):
        reason = f"[DFZ] IPv6 DFZ has increased by {round(v6_pc, 2)}% from the {((max_history * update_frequency) / 60 ) / 60}hrs " \
                 f"average {int(avg_v6)} to {num_dfz_routes_history['v6'][0]} routes"
    elif 100 - v6_pc > metrics['dfz'].get('threshold'):
        reason = f"[DFZ] IPv6 DFZ has decreased by {round(100 - v6_pc, 2)}% from the {((max_history * update_frequency) / 60) / 60}hrs " \
                 f"average {int(avg_v6)} to {num_dfz_routes_history['v6'][0]} routes"
    else:
        reason = None

    if reason:
        fucked_reasons.append(reason)
        if debug:
            print(reason)
        del reason

    avg_v4 = sum(num_dfz_routes_history['v4']) / len(num_dfz_routes_history['v4'])
    try:
        v4_pc = round(((num_dfz_routes_history['v4'][0] / avg_v4) * 100), 1)
    except ZeroDivisionError:
        v4_pc = 100

    if v4_pc - 100 > metrics['dfz'].get('threshold'):
        reason = f"[DFZ] IPv4 DFZ has increased by {round(v4_pc - 100, 2)}% from the {((max_history * update_frequency) / 60 ) / 60}hrs " \
                 f"average {int(avg_v4)} to {num_dfz_routes_history['v4'][0]} routes"
    elif 100 - v4_pc > metrics['dfz'].get('threshold'):
        reason = f"[DFZ] IPv4 DFZ has decreased by {round(v4_pc, 2)}% from the {((max_history * update_frequency) / 60) / 60}hrs " \
                 f"average {int(avg_v4)} to {num_dfz_routes_history['v4'][0]} routes"
    else:
        reason = None

    if reason:
        fucked_reasons.append(reason)
        if debug:
            print(reason)

    return fucked_reasons, num_dfz_routes_history


def check_dns_roots(v6_roots_failed, v4_roots_failed):
    fucked_reasons = []

    for dns_root in v6_roots_failed:
        total = v6_roots_failed[dns_root].get('total')
        failed = len(v6_roots_failed[dns_root].get('failed'))
        percent_failed = round((failed / total * 100), 1)
        if percent_failed > metrics['dns_root'].get('threshold'):
            reason = f"[DNS] {dns_root} failed to respond to {percent_failed}% of {total} RIPE Atlas probes over IPv6"
            fucked_reasons.append(reason)
            if debug:
                print(reason)

    for dns_root in v4_roots_failed:
        total = v4_roots_failed[dns_root].get('total')
        failed = len(v4_roots_failed[dns_root].get('failed'))
        percent_failed = round((failed / total * 100), 1)
        if percent_failed > metrics['dns_root'].get('threshold'):
            reason = f"[DNS] {dns_root} failed to respond to {percent_failed}% of {total} RIPE Atlas probes over IPv4"
            fucked_reasons.append(reason)
            if debug:
                print(reason)

    return fucked_reasons


def check_public_dns(dns_results):
    fucked_reasons = []

    for server in dns_results:
        total = len(dns_results[server].get('failed')) + len(dns_results[server].get('passed'))
        failed = len(dns_results[server].get('failed'))
        try:
            percent_failed = round((failed / total * 100), 1)
        except ZeroDivisionError:
            percent_failed = 0
        if percent_failed > metrics['public_dns'].get('threshold'):
            reason = f"[DNS] {server} failed to recurse an A query from {percent_failed}% of {total} RIPE Atlas probes"
            fucked_reasons.append(reason)
            if debug:
                print(reason)

    return fucked_reasons


def check_ripe_atlas_status(probe_status):
    fucked_reasons = []

    disconnected = len(probe_status['disconnected'])
    total = len(probe_status['connected']) + disconnected

    try:
        avg = (disconnected / total) * 100
    except ZeroDivisionError:
        avg = 0
        if debug:
            print("No RIPE Atlas probes to check")
    if avg > metrics['atlas_connected'].get('threshold'):
        reason = f"[RIPE Atlas] {avg}% of recently active RIPE Atlas probes are disconnected"
        fucked_reasons.append(reason)
        if debug:
            print(reason)

    return fucked_reasons


def check_ntp(ntp_pool_status):
    fucked_reasons = []

    for server in ntp_pool_status:
        for af in ntp_pool_status[server]:
            failed = len(ntp_pool_status[server][af].get('failed'))
            total = len(ntp_pool_status[server][af].get('passed')) + failed

            try:
                avg = round((failed / total) * 100, 2)
            except ZeroDivisionError:
                avg = 0
                if debug:
                    print(f"No RIPE Atlas results for {server} over IP{af}")

            if avg > metrics['ntp'].get('threshold'):
                reason = f"[NTP] {server} failed to respond to {avg}% of {total} RIPE Atlas probes over IP{af}"
                fucked_reasons.append(reason)
                if debug:
                    print(reason)

    return fucked_reasons


def check_gcp(gcp_results):
    fucked_reasons = []

    if len(gcp_results) > metrics['gcp'].get('threshold'):
        for service, regions in gcp_results.items():
            if service == "Multiple Products":
                modifier = 'are'
                metrics['gcp']['weight'] += 1   # Bump up the weight for all GCP incidents
            else:
                modifier = 'is'
            if 'global' in regions:
                reason = f"[GCP] {service} {modifier} down globally"
                metrics['gcp']['weight'] += 1   # Bump up the weight for all GCP incidents
            else:
                reason = f"[GCP] {service} {modifier} down in regions: {', '.join(regions)}"

            fucked_reasons.append(reason)
            if debug:
                print(reason)

    return fucked_reasons


def main():

    headers = {'User-Agent': 'howfuckedistheinternet.com'}

    num_dfz_routes_history = {'v6': [], 'v4': []}
    num_origins_history = {}
    num_prefixes_history = {}
    rpki_invalid_roa_history = {}
    rpki_total_roa_history = {}

    if write_sql_enabled:
        try:
            connection = sqlite3.connect(root + sqlitedb)
            cursor = connection.cursor()
        except sqlite3.OperationalError:
            print(f"Error: Can't open sqlite db file")
            exit(1)

        # Create and populate the metrics table
        try:
            cursor.execute("""CREATE TABLE metrics (metric TEXT PRIMARY KEY, description TEXT,
                              weight REAL, frequency INTEGER, last TEXT)""")
        except sqlite3.OperationalError:
            cursor.execute("DELETE FROM metrics")
            connection.commit()

        metrics_list = []
        for metric, attrs in metrics.items():
            metrics_list.append((metric, attrs.get('descr'), attrs.get('weight'), attrs.get('freq'), None))
        try:
            cursor.executemany("INSERT INTO metrics VALUES (?, ?, ?, ?, ?)", metrics_list)
            connection.commit()
        except sqlite3.InterfaceError:
            print(f"Failed to insert into status table: {metrics_list}")

        try:
            cursor.execute("CREATE TABLE status (status TEXT, timestamp TEXT, duration TEXT)")
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute("""CREATE TABLE reasons (reason TEXT, metric TEXT, weight REAL,
                              FOREIGN KEY(metric) REFERENCES metrics(metric))""")
        except sqlite3.OperationalError:
            pass


    while True:
        # Reset reasons and duration timer
        fucked_reasons = {}
        for metric in metrics:
            fucked_reasons[metric] = []

        before = datetime.now()

        if metrics['origins'].get('enabled') or metrics['prefixes'].get('enabled') or metrics['dfz'].get('enabled'):
            table_asn_key, table_pfx_key = fetch_bgp_table(bgp_table_url, headers)
            if metrics['origins'].get('enabled'):
                fucked_reasons['origins'], num_origins_history = check_bgp_origins(table_pfx_key, num_origins_history)
            if metrics['prefixes'].get('enabled'):
                fucked_reasons['prefixes'], num_prefixes_history = check_bgp_prefixes(table_asn_key, num_prefixes_history)
            if metrics['dfz'].get('enabled'):
                fucked_reasons['dfz'], num_dfz_routes_history = check_dfz(table_pfx_key, num_dfz_routes_history)
            del table_asn_key, table_pfx_key

        if metrics['invalid_roa'].get('enabled') or metrics['total_roa'].get('enabled'):
            invalid_roa, total_roa = fetch_rpki_roa(routinator_api_url, headers)
            if metrics['invalid_roa'].get('enabled'):
                fucked_reasons['invalid_roa'], rpki_invalid_roa_history = check_rpki_invalids(invalid_roa, rpki_invalid_roa_history)
            if metrics['total_roa'].get('enabled'):
                fucked_reasons['total_roa'], rpki_total_roa_history = check_rpki_totals(total_roa, rpki_total_roa_history)
            del invalid_roa, total_roa

        if metrics['ntp'].get('enabled'):
            ntp_pool_status = fetch_ntp_pool_status(ripe_atlas_api_url, headers)
            fucked_reasons['ntp'] = check_ntp(ntp_pool_status)

        if metrics['dns_root'].get('enabled'):
            v6_roots_failed, v4_roots_failed = fetch_root_dns(ripe_atlas_api_url, headers)
            fucked_reasons['dns_root'] = check_dns_roots(v6_roots_failed, v4_roots_failed)
            del v6_roots_failed, v4_roots_failed
        if metrics['atlas_connected'].get('enabled'):
            probe_status = fetch_ripe_atlas_status(ripe_atlas_api_url, headers)
            fucked_reasons['atlas_connected'] = check_ripe_atlas_status(probe_status)
            del probe_status
        if metrics['public_dns'].get('enabled'):
            public_dns_status = fetch_public_dns_status(ripe_atlas_api_url, headers)
            fucked_reasons['public_dns'] = check_public_dns(public_dns_status)

        if metrics['aws'].get('enabled'):
            aws_v6_results = fetch_aws(aws_v6_file, headers)
            fucked_reasons['aws'] = check_aws(aws_v6_results, 6)
            aws_v4_results = fetch_aws(aws_v4_file, headers)
            fucked_reasons['aws'] = check_aws(aws_v4_results, 4)

        if metrics['gcp'].get('enabled'):
            gcp_results = fetch_gcp(gcp_incidents_url, headers)
            fucked_reasons['gcp'] = check_gcp(gcp_results)

        weighted_reasons = 0
        for metric, reasons in fucked_reasons.items():
            weighted_reasons = weighted_reasons + (len(reasons) * metrics[metric].get('weight'))
        unweighted_reasons = sum(map(lambda x: len(x), fucked_reasons.values()))

        if weighted_reasons > 200:
            status = "The Internet is totally, utterly, and completely fucked"
        elif weighted_reasons > 100:
            status = "The Internet is completely fucked"
        elif weighted_reasons > 60:
            status = "The Internet is utterly fucked"
        elif weighted_reasons > 50:
            status = "The Internet is totally fucked"
        elif weighted_reasons > 40:
            status = "The Internet is really fucked"
        elif weighted_reasons > 30:
            status = "The Internet is rather fucked"
        elif weighted_reasons > 20:
            status = "The Internet is quite fucked"
        elif weighted_reasons > 15:
            status = "The Internet is pretty fucked"
        elif weighted_reasons > 10:
            status = "The Internet is somewhat fucked"
        elif weighted_reasons > 5:
            status = "The Internet is only partially fucked"
        elif weighted_reasons > 0:
            status = "The Internet is just a little bit fucked"
        else:
            status = "The Internet is fucked no more than usual"

        after = datetime.now()
        duration = after - before
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds", sep=" ").replace("+00:00", "Z")

        if debug:
            print(status)
            print(f"It took {duration.seconds} seconds to check for fuckedness")
            print(f"Weighted: {weighted_reasons} - Unweighted: {unweighted_reasons}")

        if write_sql_enabled:

            status_tuple = (status,  timestamp, str(duration.seconds))
            try:
                cursor.execute("DELETE FROM status")
                connection.commit()
                cursor.execute("INSERT INTO status VALUES (?, ?, ?)", status_tuple)
                connection.commit()
            except sqlite3.InterfaceError:
                print(f"Failed to insert into status table: {status_tuple}")

            reasons_list = []

            for metric, reasons in fucked_reasons.items():
                if reasons:
                    for reason in sorted(reasons):
                        reasons_list.append((reason, metric, metrics[metric].get('weight')))

            try:
                cursor.execute("DELETE FROM reasons")
                connection.commit()
                if reasons_list:
                    cursor.executemany("INSERT INTO reasons VALUES (?, ?, ?)", reasons_list)
                    connection.commit()
            except sqlite3.InterfaceError:
                print(f"Failed to insert into reasons table: {reasons_list}")

        if duration.seconds < update_frequency:
            time.sleep(update_frequency - duration.seconds)
        else:
            pass  # We've taken long enough


if __name__ == '__main__':
    main()
