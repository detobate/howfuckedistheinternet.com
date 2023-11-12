import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import config
import requests
import ujson


def fetch_aws(aws_urls_file):
    """Attempts to fetch the green-icon.gif hosted in all regions for the specific purpose of connectivity checks
    see http://ec2-reachability.amazonaws.com
    Timeouts or HTTP errors are marked as failures"""

    aws_results = {}
    with open(aws_urls_file, "r") as f:
        aws_check_urls = ujson.loads(f.read())

    for region, urls in aws_check_urls.items():
        aws_results[region] = []
        for url in urls:
            try:
                r = requests.get(url, headers=config.headers, timeout=60)
                if r.ok:
                    aws_results[region].append(True)
                else:
                    aws_results[region].append(False)
            except:
                aws_results[region].append(False)

    return aws_results

def check_aws(aws_results, af):
    fucked_reasons = []
    for region, results in aws_results.items():
        total = len(results)
        failed = results.count(False)
        try:
            pct_failed = round((failed / total) * 100, 1)
        except ZeroDivisionError:
            pct_failed = 0

        if pct_failed > config.metrics["aws"].get("threshold"):
            fucked_reasons.append(
                f"[AWS] {region} {pct_failed}% of connectivity checks over IPv{af} failed"
            )

    return fucked_reasons