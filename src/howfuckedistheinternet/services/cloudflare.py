import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import config
import requests
import ujson


def fetch_cloudflare():

    url = 'https://www.cloudflarestatus.com/api/v2/incidents/unresolved.json'

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
            print(f"failed to parse Cloudflare Status")
        return None

    cloudflare_incs = {}

    if incidents := response.get('incidents'):
        for inc in incidents:
            status = inc.get('status')
            name = inc.get('name')
            impact = inc.get('impact')
            if status in ('identified', 'investigating'):
                try:
                    cloudflare_incs[impact].append(name)
                except KeyError:
                    cloudflare_incs[impact] = [name]

    if cloudflare_incs and config.debug:
        print(f"Cloudflare has open incs: {cloudflare_incs}")

    return cloudflare_incs


def check_cloudflare(incidents):
    fucked_reasons = []

    if crits := incidents.get('critical'):
        fucked_reasons.append(f'[Cloudflare] has {len(crits)} open critical incidents: {crits}')
        # Bump up the weight for all Cloudflare incidents based on number of crits
        config.metrics["cloudflare"]["adjusted_weight"] = config.metrics["cloudflare"]["weight"] + len(crits)
    if major := incidents.get('major'):
        fucked_reasons.append(f'[Cloudflare] has {len(major)} open major incidents: {major}')
        # Bump up the weight for all Cloudflare incidents just one click
        config.metrics["cloudflare"]["adjusted_weight"] = config.metrics["cloudflare"]["weight"] + 1
    if minor := incidents.get('minor'):
        fucked_reasons.append(f'[Cloudflare] has {len(minor)} open minor incidents: {minor}')

    return fucked_reasons
