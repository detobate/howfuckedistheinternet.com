#!/usr/bin/env python3
import cgitb
import sqlite3

from jinja2 import Environment, FileSystemLoader

sqlitedb = "howfucked.db"
index_template = "index.j2"
root = "/var/www/howfuckedistheinternet.com/html/"

cgitb.enable()
print("Content-Type: text/html;charset=utf-8\r\n\r\n")


def main():
    environment = Environment(loader=FileSystemLoader(root))
    template = environment.get_template(index_template)

    try:
        connection = sqlite3.connect(root + sqlitedb)
        cursor = connection.cursor()
    except:
        print(f"Failed to open sqlite3 db {root + sqlitedb}")
        exit(1)

    try:
        status, timestamp, duration = cursor.execute("SELECT * FROM status").fetchone()
    except:
        status, timestamp, duration = None, None, None

    try:
        reasons = cursor.execute(
            "SELECT * FROM reasons ORDER BY weight DESC"
        ).fetchall()
    except:
        reasons = None

    try:
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        c = cursor.execute("SELECT * FROM metrics ORDER BY weight DESC")
        metrics = [dict(row) for row in c.fetchall()]
    except:
        metrics = None

    html = template.render(
        timestamp=timestamp,
        duration=duration,
        status=status,
        reasons=reasons,
        metrics=metrics,
    )
    print(html)


if __name__ == "__main__":
    main()
