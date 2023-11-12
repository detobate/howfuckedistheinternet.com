import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import config
import requests
import ujson


def fetch_slack():
    url = 'https://status.slack.com/api/v2.0.0/current'

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
            print(f"failed to parse Slack Status")
        return None

    incs = []

    if response.get('active_incidents') != 'ok':
        incidents = response.get('active_incidents')
        for inc in incidents:
            status = inc.get('status')
            name = inc.get('title')
            type = inc.get('type')
            inc_url = inc.get('url')
            services = inc.get('services')

            if type != 'notice' and status == 'active':
                incs.append({'name': name, 'url': inc_url, 'services': services})

    if incs and config.debug:
        print(f"Slack has open incs: {incs}")

    return incs


def check_slack(incidents):

    fucked_reasons = []

    for inc in incidents:
        fucked_reasons.append(f"[Slack] <a href=\"{inc.get('url')}\">{inc.get('name')}</a> - "
                              f"Services Impacted: {inc.get('services')}")

    return fucked_reasons
