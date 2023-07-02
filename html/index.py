#!/usr/bin/env python3
import cgitb
import random

header = 'header.html'
footer = 'footer.html'
status_file = 'status.txt'
why_file = 'why.txt'
timestamp_file = 'timestamp.txt'
title = '''Metrics are:
* size of the DFZ and dramatic increase or decrease of prefixes
* number of origin AS per prefix
* RPKI ROA validity
* Dramatic decrease in published RPKI ROAs
* DNS root-server reachability
* RIPE Atlas probe connected status'''

cgitb.enable()
print("Content-Type: text/html;charset=utf-8\r\n\r\n")

def main():

    with open(header, 'r') as head:
        print(head.read())

    print('<div class = "main"><div class = "wrapper">')
    with open(timestamp_file, encoding="utf-8") as timestamp:
        print(f'<p class="timestamp" title="{title}">Fuckedness last checked {timestamp.readline()}</br>')
        print(f'It took {timestamp.readline()} seconds to checked fuckedness</p>')
    with open(status_file, encoding="utf-8") as status:
        print(f'<h1>{status.read()}</h1>')
    print('</div>')
    print('</div>')

    why = []
    with open(why_file, encoding="utf-8") as y:
        why = y.readlines()
    if why:
        print('<div class = "why">')
        print('<h2>But why though?</h2>')
        for y in why:
            print(f"<br>{y}</br>")
        print('</div>')

    with open(footer, 'r') as foot:
        print(foot.read())


if __name__ == "__main__":
    main()
