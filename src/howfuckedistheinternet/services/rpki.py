import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import config
import requests
import ujson
import math


def fetch_rpki_roa():

    url = "https://rpki-validator.ripe.net/api/v1/status"

    invalid_roa = {}
    total_roa = {}

    try:
        results = ujson.loads(requests.get(url, headers=config.headers, timeout=60).text)
    except:
        if config.debug:
            print(f"failed to fetch {url}")
        return invalid_roa, total_roa

    for repo in results.get("repositories"):
        invalid = results["repositories"][repo].get("invalidROAs")
        invalid_roa[repo] = invalid

        valid_roa = results["repositories"][repo].get("validROAs")
        total_roa[repo] = int(valid_roa + invalid)

    return invalid_roa, total_roa


def check_rpki_totals(total_roa, rpki_total_roa_history):
    """Store the latest num of total ROAs
    Check the history to see if any repos have an increased number of Invalids and add to the fucked_reasons list
    """

    fucked_reasons = []

    for repo in total_roa:
        if repo in rpki_total_roa_history:
            rpki_total_roa_history[repo].insert(0, total_roa.get(repo))
            if len(rpki_total_roa_history) > config.max_history:
                zz = rpki_total_roa_history[repo].pop()
        else:
            rpki_total_roa_history[repo] = [total_roa.get(repo)]

    for repo, totals in rpki_total_roa_history.items():
        avg = int(sum(totals) / len(totals))
        try:
            percentage = (totals[0] / avg) * 100
        except ZeroDivisionError:
            percentage = 100
        if (100 - percentage) > config.metrics["total_roa"].get("threshold"):
            reason = f"[RPKI] {repo} has decreased published ROAs by {percentage}, " \
                     f"from an average of {avg} to {totals[0]}"
            fucked_reasons.append(reason)
            if config.debug:
                print(reason)

    return fucked_reasons, rpki_total_roa_history


def check_rpki_invalids(invalid_roa, rpki_invalids_history):
    """Store the latest num of invalid ROAs
    Check the history to see if any repos have an increased number of Invalids and add to the fucked_reasons list
    """

    fucked_reasons = []

    for repo in invalid_roa:
        if repo in rpki_invalids_history:
            rpki_invalids_history[repo].insert(0, invalid_roa.get(repo))
            if len(rpki_invalids_history) > config.max_history:
                zz = rpki_invalids_history[repo].pop()
        else:
            rpki_invalids_history[repo] = [invalid_roa.get(repo)]

    for repo, invalids in rpki_invalids_history.items():
        avg = sum(invalids) / len(invalids)
        if invalids[0] > avg:
            reason = (
                f"[RPKI] {invalids[0]} ROAs from {repo} have invalid routes being advertised to the DFZ, more than "
                f"the {((config.max_history * config.update_frequency) / 60 ) / 60}hrs average of {math.floor(avg)}"
            )
            fucked_reasons.append(reason)
            if config.debug:
                print(reason)

    return fucked_reasons, rpki_invalids_history
