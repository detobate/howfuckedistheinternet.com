"""All bgp.tools based checks"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import config
import requests
import ujson
import math


def fetch_bgp_table():
    """Fetches BGP/DFZ info as json from bgp.tools
    Builds two dicts, keyed on ASN and Prefix"""

    url = "https://bgp.tools/table.jsonl"

    table_asn_key = {}
    table_pfx_key = {}
    try:
        results = requests.get(url, headers=config.headers, timeout=60)
    except:
        if config.debug:
            print(f"failed to fetch {url}")
        return table_asn_key, table_pfx_key

    table_list = results.text.split("\n")

    for x in table_list:
        # Build a dict keyed on ASN
        try:
            x = ujson.loads(x)
        except ujson.JSONDecodeError:
            break
        try:
            asn = x.get("ASN")
            if asn in table_asn_key:
                table_asn_key[asn].append(x)
            else:
                table_asn_key[asn] = [x]
        except KeyError:
            break

        # Build a dict keyed on prefix
        try:
            pfx = x.get("CIDR")
            if pfx in table_pfx_key:
                table_pfx_key[pfx].append(x)
            else:
                table_pfx_key[pfx] = [x]
        except KeyError:
            break

    return table_asn_key, table_pfx_key


def check_bogon_asns(table_pfx_key):
    """ Check origin ASN(s) for every prefix and complain about bad ones """

    fucked_reasons = []

    bogon_asns = (
        range(0, 0 + 1),                    # RFC 7607
        range(23456, 23456 + 1),            # RFC 4893 AS_TRANS
        range(64496, 64511 + 1),            # RFC 5398 and documentation/example ASNs
        range(64512, 65534 + 1),            # RFC 6996 Private ASNs
        range(65535, 65535 + 1),            # RFC 7300 Last 16 bit ASN
        range(65536, 65551 + 1),            # RFC 5398 and documentation/example ASNs
        range(65552, 131071 + 1),           # IANA reserved ASNs
        range(4200000000, 4294967294 + 1),  # RFC 6996 Private ASNs
        range(4294967295, 4294967295 + 1)   # RFC 7300 Last 32 bit ASN
    )

    for pfx in table_pfx_key:
        for path in table_pfx_key.get(pfx):
            asn = path.get("ASN")

            # It feels uglier but it's much quicker to iterate over a tuple of ranges
            # than checking a fully expanded tuple with 95M entries.
            for bogon in bogon_asns:
                if asn in bogon and path.get("Hits") >= config.metrics["bogonASNs"].get("threshold"):
                    reason = (
                        f"[BogonASN] <a href='https://bgp.tools/prefix/{pfx}#connectivity'>{pfx}</a> "
                        f"is originated by a private or invalid ASN AS{asn}, "
                        f"visible by {path.get('Hits')} BGP.tools contributors"
                    )
                    fucked_reasons.append(reason)
                    if config.debug:
                        print(f"[BogonASN] {pfx} is originated by a private or invalid ASN AS{asn}, visible by {path.get('Hits')}")
                        # print(path)
    return fucked_reasons


def check_bgp_origins(table_pfx_key, num_origins_history):
    """Store the latest num of origin AS per prefix
    Check the history to see if any prefixes have an increased number of origin AS"""

    fucked_reasons = []

    for pfx in table_pfx_key:
        num_origins = len(table_pfx_key.get(pfx))
        if pfx in num_origins_history:
            num_origins_history[pfx].insert(0, num_origins)
            if len(num_origins_history.get(pfx)) > config.max_history:
                zz = num_origins_history[pfx].pop()
        else:
            num_origins_history[pfx] = [num_origins]

    # Check for an increase in origins, could signify hijacking
    for pfx, origins in num_origins_history.items():
        avg = sum(origins) / len(origins)

        # Exclude any multi-origin anycast prefixes
        if origins[0] > avg and avg < 2:
            reason = (
                f"[Origins] {pfx} is being originated by <a href='https://bgp.tools/prefix/{pfx}#connectivity'>{origins[0]} ASNs</a>, above the "
                f"{((config.max_history * config.update_frequency) / 60 ) / 60}hrs average of {math.floor(avg)}"
            )
            fucked_reasons.append(reason)
            if config.debug:
                print(f"[Origins] {pfx} is being originated by {origins[0]} ASNs, above the "
                      f"{((config.max_history * config.update_frequency) / 60 ) / 60}hrs average of {math.floor(avg)}")

        # Catch a sudden decrease in origins of anycast prefixes that usually have a lot
        if origins[0] < 2 and avg > 5:
            reason = (
                f"[Origins] {pfx} is being originated by <a href='https://bgp.tools/prefix/{pfx}#connectivity'>{origins[0]} ASNs</a>, below the "
                f"{((config.max_history * config.update_frequency) / 60 ) / 60}hrs average of {math.floor(avg)}"
            )
            fucked_reasons.append(reason)
            if config.debug:
                print(f"[Origins] {pfx} is being originated by {origins[0]} ASNs, below the "
                      f"{((config.max_history * config.update_frequency) / 60 ) / 60}hrs average of {math.floor(avg)}")

    return fucked_reasons, num_origins_history


def check_bgp_prefixes(table_asn_key, num_prefixes_history):
    """Store the latest number of prefixes advertised per ASN
    Check the history to see if any ASNs have a drastically reduced number of prefixes
    """

    fucked_reasons = []

    # Add latest result to the history
    for asn in table_asn_key:
        num_prefixes = len(table_asn_key.get(asn))
        if asn in num_prefixes_history:
            num_prefixes_history[asn].insert(0, num_prefixes)
            if len(num_prefixes_history.get(asn)) > config.max_history:
                zz = num_prefixes_history[asn].pop()
        else:
            num_prefixes_history[asn] = [num_prefixes]

    # Check for a drastic decrease in prefixes being advertised by an ASN
    for asn, prefixes in num_prefixes_history.items():
        avg = sum(prefixes) / len(prefixes)
        percentage = 100 - int(round((prefixes[0] / avg) * 100, 0))
        if percentage > config.metrics["prefixes"].get("threshold"):
            reason = (
                f"[Prefixes] <a href='https://bgp.tools/as/{asn}#prefixes'>AS{asn}</a> "
                f"is originating only {prefixes[0]} prefixes, {percentage}% "
                f"fewer than the {((config.max_history * config.update_frequency) / 60 ) / 60}hrs "
                f"average of {math.ceil(avg)}"
            )
            fucked_reasons.append(reason)
            if config.debug:
                print(f"[Prefixes] AS{asn} is originating only {prefixes[0]} prefixes, {percentage}% "
                      f"fewer than the {((config.max_history * config.update_frequency) / 60 ) / 60}hrs "
                      f"average of {math.ceil(avg)}")

    return fucked_reasons, num_prefixes_history


def check_dfz(table_pfx_key, num_dfz_routes_history):
    """Keep track of the number of routes present in both the IPv4 and IPv6 DFZ
    Alert when DFZ size increases by dfz_threshold %
    Iterating this dict to parse v4 or v6 seems silly, but oh well.
    """

    fucked_reasons = []

    v6_dfz_count = 0
    v4_dfz_count = 0

    for pfx in table_pfx_key:
        if pfx.find("::/") > 0:
            v6_dfz_count += 1
        else:
            v4_dfz_count += 1

    num_dfz_routes_history["v6"].insert(0, v6_dfz_count)
    if len(num_dfz_routes_history["v6"]) > config.max_history:
        num_dfz_routes_history["v6"].pop()

    num_dfz_routes_history["v4"].insert(0, v4_dfz_count)
    if len(num_dfz_routes_history["v4"]) > config.max_history:
        num_dfz_routes_history["v4"].pop()

    avg_v6 = sum(num_dfz_routes_history["v6"]) / len(num_dfz_routes_history["v6"])
    try:
        v6_pc = round(((num_dfz_routes_history["v6"][0] / avg_v6) * 100), 1)
    except ZeroDivisionError:
        v6_pc = 100

    if v6_pc - 100 > config.metrics["dfz"].get("threshold"):
        reason = (
            f"[DFZ] IPv6 DFZ has increased by {round(v6_pc - 100, 2)}% from the "
            f"{((config.max_history * config.update_frequency) / 60 ) / 60}hrs average {int(avg_v6)} "
            f"to {num_dfz_routes_history['v6'][0]} routes"
        )
    elif 100 - v6_pc > config.metrics["dfz"].get("threshold"):
        reason = (
            f"[DFZ] IPv6 DFZ has decreased by {round(100 v6_pc, 2)}% from the "
            f"{((config.max_history * config.update_frequency) / 60) / 60}hrs average {int(avg_v6)} "
            f"to {num_dfz_routes_history['v6'][0]} routes"
        )
    else:
        reason = None

    if reason:
        fucked_reasons.append(reason)
        if config.debug:
            print(reason)
        del reason

    avg_v4 = sum(num_dfz_routes_history["v4"]) / len(num_dfz_routes_history["v4"])
    try:
        v4_pc = 100 - round(((num_dfz_routes_history["v4"][0] / avg_v4) * 100), 1)
    except ZeroDivisionError:
        v4_pc = 100

    if v4_pc - 100 > config.metrics["dfz"].get("threshold"):
        reason = (
            f"[DFZ] IPv4 DFZ has increased by {round(v4_pc - 100, 2)}% from the "
            f"{((config.max_history * config.update_frequency) / 60 ) / 60}hrs average {int(avg_v4)} "
            f"to {num_dfz_routes_history['v4'][0]} routes"
        )
    elif 100 - v4_pc > config.metrics["dfz"].get("threshold"):
        reason = (
            f"[DFZ] IPv4 DFZ has decreased by {round(100 - v4_pc, 2)}% from the "
            f"{((config.max_history * config.update_frequency) / 60) / 60}hrs average {int(avg_v4)} "
            f"to {num_dfz_routes_history['v4'][0]} routes"
        )
    else:
        reason = None

    if reason:
        fucked_reasons.append(reason)
        if config.debug:
            print(reason)

    return fucked_reasons, num_dfz_routes_history
