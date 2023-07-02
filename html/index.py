#!/usr/bin/env python3
import cgitb
import random

header = 'header.html'
footer = 'footer.html'
status_file = 'status.txt'
why_file = 'why.txt'
timestamp_file = 'timestamp.txt'

cgitb.enable()
print("Content-Type: text/html;charset=utf-8\r\n\r\n")


def main():
    with open(header, 'r') as head:
        print(head.read())

    print('<header>')
    print('<p class="metadata">')
    with open(timestamp_file, encoding="utf-8") as timestamp:
        print(f'Fuckedness last checked {timestamp.readline()}</br>')
        print(f'It took {timestamp.readline()} seconds to check for fuckedness')
    print('</p>')
    print('</header>')
    print('<main class="wrapper">')
    print('<section class="fuckometer">')

    with open(status_file, encoding="utf-8") as status:
        print(f'<h1>{status.read()}</h1>')
    print('</section>')

    why = []
    with open(why_file, encoding="utf-8") as y:
        why = y.readlines()
    if why:
        print('<section class="why">')
        print('<h2>But why though?</h2>')
        print('<h3>Calculation Metrics</h3>')
        print('''<ul class="how">
                <li>size of the DFZ and dramatic increase or decrease of prefixes
                <li>number of origin AS per prefix
                <li>RPKI ROA validity
                <li>Dramatic decrease in published RPKI ROAs
                <li>DNS root-server reachability
                <li>RIPE Atlas probe connected status
            </ul>''')
        print('<h3>Specifically</h3>')
        for y in why:
            print(y)
        print('</p>')
        print('</section>')
        print('</main>')

    with open(footer, 'r') as foot:
        print(foot.read())


if __name__ == "__main__":
    main()
