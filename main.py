#!/usr/bin/env python3
import math
import requests
import time
import ujson
from datetime import datetime, timezone

routinator_api_url = 'https://rpki-validator.ripe.net/api/v1/status'
bgp_table_url = 'https://bgp.tools/table.jsonl'
ripe_atlas_api_url = 'https://atlas.ripe.net/api/v2/measurements/'
root = '/var/www/howfuckedistheinternet.com/html/'
status_file = 'status.txt'
why_file = 'why.txt'
timestamp_file = 'timestamp.txt'

max_history = 24                    # 12hrs at regular 30min updates
update_frequency = 1800             # 30 mins
dfz_threshold = 1                   # Threshold of routes in the DFZ (% increase or decrease)
bgp_prefix_threshold = 85           # Threshold of prefix decrease before alerting (%)
dns_root_fail_threshold = 10        # Threshold of RIPE Atlas Probes failing to reach root-servers (%) [Baseline is ~3%]
atlas_probe_threshold = 10          # Threshold of RIPE Atlas Probes disconnected (%)
total_roa_threshold = 90            # Threshold of published RPKI ROA decrease (%)
ntp_pool_failure_threshold = 20     # Threshold of NTP pool failures before alerting (%)

bgp_enabled = True
rpki_enabled = True
atlas_enabled = True
write_enabled = True
debug = True

# Adjust weighting based on importance
weighting = {'origins': 0.1, 'prefixes': 0.2, 'dns_root': 10, 'atlas_connected': 1,
             'invalid_roa': 1, 'total_roa': 5, 'dfz': 1, 'ntp': 2}


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
                results = requests.get(url, headers=headers).json()
            except:
                if debug:
                    print(f"failed to fetch RIPE Atlas results from {url}")
                results = None

            if results:
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
        results = requests.get(url, headers=headers).json()
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
            results_v6 = requests.get(url_v6, headers=headers).json()
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
    results = requests.get(url, headers=headers).json()

    invalid_roa = {}
    total_roa = {}

    for repo in results.get('repositories'):
        invalid = results['repositories'][repo].get('invalidROAs')
        invalid_roa[repo] = invalid

        valid_roa = results['repositories'][repo].get('validROAs')
        total_roa[repo] = int(valid_roa + invalid)

    return invalid_roa, total_roa


def fetch_bgp_table(url, headers):
    """ Fetches BGP/DFZ info as json from bgp.tools
        Builds two dicts, keyed on ASN and Prefix"""

    results = requests.get(url, headers=headers)

    table_list = results.text.split('\n')
    table_asn_key = {}
    table_pfx_key = {}

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
            reason = f"{pfx} is being originated by {origins[0]} ASNs, this is above the " \
                     f"{((max_history * update_frequency) / 60 ) / 60}hrs average of {math.floor(avg)}"
            fucked_reasons.append(reason)
            if debug:
                print(reason)

        # Catch a sudden decrease in origins of anycast prefixes that usually have a lot
        if origins[0] < 2 and avg > 5:
            reason = f"{pfx} is being originated by {origins[0]} ASNs, this is below the " \
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
        if percentage > bgp_prefix_threshold:
            reason = f"AS{asn} is originating only {prefixes[0]} prefixes, {percentage}% " \
                     f"fewer than their {((max_history * update_frequency) / 60 ) / 60}hrs average of {math.ceil(avg)}"
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
        if (100 - percentage) > total_roa_threshold:
            reason = f"{repo} has decreased published ROAs by {percentage}, from an average of {avg} to {totals[0]}"
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
            reason = f"{invalids[0]} RPKI ROAs from {repo} have invalid routes being advertised to the DFZ, " \
                            f"which is more than the {((max_history * update_frequency) / 60 ) / 60}hrs average of {math.floor(avg)}"
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

    if v6_pc - 100 > dfz_threshold:
        reason = f"The IPv6 DFZ has increased by {v6_pc}% from the {((max_history * update_frequency) / 60 ) / 60}hrs " \
                 f"average {int(avg_v6)} to {num_dfz_routes_history['v6'][0]} routes"
    elif 100 - v6_pc > dfz_threshold:
        reason = f"The IPv6 DFZ has decreased by {v6_pc}% from the {((max_history * update_frequency) / 60) / 60}hrs " \
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

    if v4_pc - 100 > dfz_threshold:
        reason = f"The IPv4 DFZ has increased by {v4_pc - 100}% from the {((max_history * update_frequency) / 60 ) / 60}hrs " \
                 f"average {int(avg_v4)} to {num_dfz_routes_history['v4'][0]} routes"
    elif 100 - v4_pc > dfz_threshold:
        reason = f"The IPv4 DFZ has decreased by {v4_pc}% from the {((max_history * update_frequency) / 60) / 60}hrs " \
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
        if percent_failed > dns_root_fail_threshold:
            reason = f"{percent_failed}% of RIPE Atlas Probes failed to get a response from {dns_root} over IPv6"
            fucked_reasons.append(reason)
            if debug:
                print(reason)

    for dns_root in v4_roots_failed:
        total = v4_roots_failed[dns_root].get('total')
        failed = len(v4_roots_failed[dns_root].get('failed'))
        percent_failed = round((failed / total * 100), 1)
        if percent_failed > dns_root_fail_threshold:
            reason = f"{percent_failed}% of RIPE Atlas Probes failed to get a response from {dns_root} over IPv4"
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
    if avg > atlas_probe_threshold:
        reason = f"{avg}% of recently active RIPE Atlas probes are disconnected"
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

            if avg > ntp_pool_failure_threshold:
                reason = f"{avg}% of {total} RIPE Atlas probes measured, failed to get a response from {server} over IP{af}"
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

    while True:
        # Reset reasons and duration timer
        fucked_reasons = {'origins': [], 'prefixes': [], 'dns_root': [], 'atlas_connected': [],
                          'invalid_roa': [], 'total_roa': [], 'dfz': [], 'ntp': []}

        before = datetime.now()

        if bgp_enabled:
            table_asn_key, table_pfx_key = fetch_bgp_table(bgp_table_url, headers)
            fucked_reasons['origins'], num_origins_history = check_bgp_origins(table_pfx_key, num_origins_history)
            fucked_reasons['prefixes'], num_prefixes_history = check_bgp_prefixes(table_asn_key, num_prefixes_history)
            fucked_reasons['dfz'], num_dfz_routes_history = check_dfz(table_pfx_key, num_dfz_routes_history)
            del table_asn_key, table_pfx_key

        if rpki_enabled:
            invalid_roa, total_roa = fetch_rpki_roa(routinator_api_url, headers)
            fucked_reasons['invalid_roa'], rpki_invalid_roa_history = check_rpki_invalids(invalid_roa, rpki_invalid_roa_history)
            fucked_reasons['total_roa'], rpki_total_roa_history = check_rpki_totals(total_roa, rpki_total_roa_history)
            del invalid_roa, total_roa

        if atlas_enabled:
            ntp_pool_status = fetch_ntp_pool_status(ripe_atlas_api_url, headers)
            fucked_reasons['ntp'] = check_ntp(ntp_pool_status)

            v6_roots_failed, v4_roots_failed = fetch_root_dns(ripe_atlas_api_url, headers)
            fucked_reasons['dns_root'] = check_dns_roots(v6_roots_failed, v4_roots_failed)

            probe_status = fetch_ripe_atlas_status(ripe_atlas_api_url, headers)
            fucked_reasons['atlas_connected'] = check_ripe_atlas_status(probe_status)

            del v6_roots_failed, v4_roots_failed, probe_status

        weighted_reasons = 0
        for metric, reasons in fucked_reasons.items():
            weighted_reasons = weighted_reasons + (len(reasons) * weighting.get(metric))
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
            status = "The Internet is partially fucked"
        elif weighted_reasons > 0:
            status = "The Internet is just a bit fucked"
        else:
            status = "The Internet is fucked no more than usual"

        if write_enabled:
            with open(root + status_file, 'w') as sf:
                sf.write(status + '\n')

        if write_enabled:
            with open(root + why_file, 'w') as wf:
                for metric in sorted(weighting, key=weighting.get, reverse=True):
                    reasons = fucked_reasons[metric]
                    if reasons:
                        wf.writelines(f"<h4>{metric}:</h4>\n")
                        print('<ul class="why-list">')
                        for reason in sorted(reasons):
                            wf.writelines(f"<li><var>{reason}</var>\n")
                        wf.writelines("</ul>")
                    else:
                        wf.write('')

        after = datetime.now()
        duration = after - before
        if debug:
            print(status)
            print(f"It took {duration.seconds} seconds to check for fuckedness")
            print(f"Weighted: {weighted_reasons} - Unweighted: {unweighted_reasons}")

        if write_enabled:
            with open(root + timestamp_file, 'w') as tf:
                tf.write(datetime.now(timezone.utc).isoformat(timespec="seconds", sep=" ").replace("+00:00", "Z") + '\n')
                tf.write(str(duration.seconds) + '\n')

        if duration.seconds < update_frequency:
            time.sleep(update_frequency - duration.seconds)
        else:
            pass    # We've taken long enough


if __name__ == '__main__':
    main()
