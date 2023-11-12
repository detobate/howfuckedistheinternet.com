import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import config
import requests
import ujson


def fetch_discord():
    url = 'https://discordstatus.com/api/v2/incidents/unresolved.json'

    try:
        response = ujson.loads(
            requests.get(url, headers=config.headers,timeout=60).text
        )
    except requests.exceptions.RequestException as e:
        if config.debug:
            print(e)
        return None
    except (AttributeError, ujson.JSONDecodeError):
        if config.debug:
            print(f"failed to parse Discord Status")
        return None

    incs = []

    if incidents := response.get('incidents'):
        for inc in incidents:
            status = inc.get('status')
            name = inc.get('name')
            impact = inc.get('impact')
            inc_url = inc.get('shortlink')

            if status in ('investigating', 'identified'):
                incs.append({'name': name, 'url': inc_url, 'status': status, 'impact': impact})

    if incs and config.debug:
        print(f"Discord has open incs: {incs}")

    return incs


def check_discord(incidents):

    fucked_reasons = []

    for inc in incidents:
        if inc.get('status') == 'investigating':
            fucked_reasons.append(f"[Discord] are investigating: <a href=\"{inc.get('url')}\">{inc.get('name')}</a>")
        elif inc.get('status') == 'identified':
            fucked_reasons.append(f"[Discord] has an open incident: <a href=\"{inc.get('url')}\">{inc.get('name')}</a>")

        # Bump up the weight for all Discord incidents a click for every critical inc
        if inc.get('impact') == 'critical':
            config.metrics["discord"]["adjusted_weight"] = config.metrics["discord"]["weight"] + 1

    return fucked_reasons
