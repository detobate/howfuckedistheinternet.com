#!/usr/bin/env python3
import services
import config
import sqlite3
import time
from datetime import datetime, timezone


def main():

    # Initialise dicts for the metrics we want to keep history of
    num_dfz_routes_history = {"v6": [], "v4": []}
    num_origins_history = {}
    num_prefixes_history = {}
    rpki_invalid_roa_history = {}
    rpki_total_roa_history = {}

    if config.write_sql_enabled:
        try:
            connection = sqlite3.connect(config.html_root + config.sqlitedb)
            cursor = connection.cursor()
        except sqlite3.OperationalError:
            print(f"Error: Can't open sqlite db file")
            exit(1)

        # Create and populate the metrics table
        try:
            cursor.execute(
                """CREATE TABLE metrics (metric TEXT PRIMARY KEY, description TEXT,
                              weight REAL, frequency INTEGER, last TEXT)"""
            )
        except sqlite3.OperationalError:
            cursor.execute("DELETE FROM metrics")
            connection.commit()

        metrics_list = []
        for metric, attrs in config.metrics.items():
            metrics_list.append(
                (
                    metric,
                    attrs.get("descr"),
                    attrs.get("weight"),
                    attrs.get("freq"),
                    None,
                )
            )
        try:
            cursor.executemany(
                "INSERT INTO metrics VALUES (?, ?, ?, ?, ?)", metrics_list
            )
            connection.commit()
        except sqlite3.InterfaceError:
            print(f"Failed to insert into status table: {metrics_list}")

        try:
            cursor.execute(
                "CREATE TABLE status (status TEXT, timestamp TEXT, duration TEXT)"
            )
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute(
                """CREATE TABLE reasons (reason TEXT, metric TEXT, weight REAL,
                              FOREIGN KEY(metric) REFERENCES metrics(metric))"""
            )
        except sqlite3.OperationalError:
            pass

    while True:
        # Reset reasons and duration timer
        fucked_reasons = {}
        for metric in config.metrics:
            fucked_reasons[metric] = []

        before = datetime.now()

        if (
            config.metrics["origins"].get("enabled")
            or config.metrics["bogonASNs"].get("enabled")
            or config.metrics["prefixes"].get("enabled")
            or config.metrics["dfz"].get("enabled")
        ):
            table_asn_key, table_pfx_key = services.fetch_bgp_table()
            if config.metrics["origins"].get("enabled"):
                fucked_reasons["origins"], num_origins_history = services.check_bgp_origins(
                    table_pfx_key, num_origins_history
                )
            if config.metrics["bogonASNs"].get("enabled"):
                fucked_reasons["bogonASNs"] = services.check_bogon_asns(table_pfx_key)
            if config.metrics["prefixes"].get("enabled"):
                fucked_reasons["prefixes"], num_prefixes_history = services.check_bgp_prefixes(
                    table_asn_key, num_prefixes_history
                )
            if config.metrics["dfz"].get("enabled"):
                fucked_reasons["dfz"], num_dfz_routes_history = services.check_dfz(
                    table_pfx_key, num_dfz_routes_history
                )
            del table_asn_key, table_pfx_key

        if config.metrics["invalid_roa"].get("enabled") or config.metrics["total_roa"].get("enabled"):
            invalid_roa, total_roa = services.fetch_rpki_roa()
            if config.metrics["invalid_roa"].get("enabled"):
                (
                    fucked_reasons["invalid_roa"],
                    rpki_invalid_roa_history,
                ) = services.check_rpki_invalids(invalid_roa, rpki_invalid_roa_history)
            if config.metrics["total_roa"].get("enabled"):
                fucked_reasons["total_roa"], rpki_total_roa_history = services.check_rpki_totals(
                    total_roa, rpki_total_roa_history
                )
            del invalid_roa, total_roa

        if config.metrics["ntp"].get("enabled"):
            ntp_pool_status = services.fetch_ntp_pool_status()
            if ntp_pool_status:
                fucked_reasons["ntp"] = services.check_ntp(ntp_pool_status)

        if config.metrics["dns_root"].get("enabled"):
            v6_roots_failed, v4_roots_failed = services.fetch_root_dns()
            if v6_roots_failed or v4_roots_failed:
                fucked_reasons["dns_root"] = services.check_dns_roots(
                    v6_roots_failed, v4_roots_failed
                )
            del v6_roots_failed, v4_roots_failed

        if config.metrics["atlas_connected"].get("enabled"):
            probe_status = services.fetch_ripe_atlas_status()
            if probe_status:
                fucked_reasons["atlas_connected"] = services.check_ripe_atlas_status(probe_status)
            del probe_status

        if config.metrics["public_dns"].get("enabled"):
            public_dns_status = services.fetch_public_dns_status()
            if public_dns_status:
                fucked_reasons["public_dns"] = services.check_public_dns(public_dns_status)

        if config.metrics["aws"].get("enabled"):
            aws_v6_results = services.fetch_aws(config.aws_v6_file)
            if aws_v6_results:
                fucked_reasons["aws"] = services.check_aws(aws_v6_results, 6)
            aws_v4_results = services.fetch_aws(config.aws_v4_file)
            if aws_v4_results:
                fucked_reasons["aws"] = services.check_aws(aws_v4_results, 4)

        if config.metrics["gcp"].get("enabled"):
            gcp_results = services.fetch_gcp()
            if gcp_results:
                fucked_reasons["gcp"] = services.check_gcp(gcp_results)

        if config.metrics["tls"].get("enabled"):
            v6_https, v4_https = services.fetch_tls_certs()
            if v6_https:
                fucked_reasons["tls"] = services.check_tls_certs(v6_https, 6)
            if v4_https:
                fucked_reasons["tls"] = services.check_tls_certs(v4_https, 4)

        if config.metrics["cloudflare"].get("enabled"):
            cloudflare_incs = services.fetch_cloudflare()
            if cloudflare_incs:
                fucked_reasons["cloudflare"] = services.check_cloudflare(cloudflare_incs)

        if config.metrics["slack"].get("enabled"):
            slack_incs = services.fetch_slack()
            if slack_incs:
                fucked_reasons["slack"] = services.check_slack(slack_incs)

        if config.metrics["discord"].get("enabled"):
            discord_incs = services.fetch_discord()
            if discord_incs:
                fucked_reasons["discord"] = services.check_discord(discord_incs)

        weighted_reasons = 0
        for metric, reasons in fucked_reasons.items():
            try:
                weighted_reasons = weighted_reasons + (
                    len(reasons) * config.metrics[metric]["adjusted_weight"]
                )
            except KeyError:
                weighted_reasons = weighted_reasons + (
                    len(reasons) * config.metrics[metric].get("weight")
                )
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
            status = "The Internet is just a little bit fucked"
        else:
            status = "The Internet is fucked no more than usual"

        after = datetime.now()
        duration = after - before
        timestamp = (
            datetime.now(timezone.utc)
            .isoformat(timespec="seconds", sep=" ")
            .replace("+00:00", "Z")
        )

        if config.debug:
            print(status)
            print(f"It took {duration.seconds} seconds to check for fuckedness")
            print(f"Weighted: {weighted_reasons} - Unweighted: {unweighted_reasons}")

        if config.write_sql_enabled:
            status_tuple = (status, timestamp, str(duration.seconds))
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
                        try:
                            adjusted_weight = config.metrics[metric]["adjusted_weight"]
                        except KeyError:
                            adjusted_weight = config.metrics[metric].get("weight")

                        reasons_list.append(
                            (reason, metric, adjusted_weight)
                        )

                # Reset any previously adjusted weightings
                try:
                    del config.metrics[metric]["adjusted_weight"]
                except KeyError:
                    pass

            try:
                cursor.execute("DELETE FROM reasons")
                connection.commit()
                if reasons_list:
                    cursor.executemany(
                        "INSERT INTO reasons VALUES (?, ?, ?)", reasons_list
                    )
                    connection.commit()
            except sqlite3.InterfaceError:
                print(f"Failed to insert into reasons table: {reasons_list}")

        if duration.seconds < config.update_frequency:
            time.sleep(config.update_frequency - duration.seconds)
        else:
            pass  # We've taken long enough


if __name__ == "__main__":
    main()
