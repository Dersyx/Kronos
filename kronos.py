# -*- coding: utf-8 -*-

# Imports
import argparse
import time
import subprocess
import vulners


def main():
    """
    Takes in arguments, along with checks that there is an actual host to scan.
    After that, everything else is initiated.
    """
    vulners_api = vulners.Vulners(
        api_key="ADD KEY HERE")

    parser = argparse.ArgumentParser(
        description="Kronos V1, a modern, python based vulnerability scanner by Dersyx. https://github.com/Dersyx/Kronos")

    parser.add_argument('--target', action="store", dest="target", required=True, help="Target that you want to scan.")

    given_args = parser.parse_args()
    target = given_args.target

    if target is None:
        print(parser.usage)
        exit(0)

    print(" ")
    print("Scanning: " + target)
    nmap_scan(target)


def nmap_scan(target):
    """
    First, it tries to establish the PortScanner.
    After, nmap scans for everything from the host, and parses the info as csv.
    Then, it takes that info, and outputs it to a .txt files, with info such
    as the name of the host, the state of the host, and if it detected an OS.
    Finally, it calls upon the next function in the chain: 'csvParser'
    """
    # Initiating the Port Scanner

    csv = nm_scanner.csv()  # Putting the results in a csv variable

# Printing out the basic info gathered in the scan
    for host in nm_scanner.all_hosts():  # References host to minimize errors.
        time_of_file = time.strftime("%m-%d-%Y_%H.%M.%S")
        # Opens a file with the time and host of the scan.
        output = open("{}_{}.txt".format(
            time_of_file, nm_scanner[host].hostname()), "w+", encoding="UTF-8")
        output.write('-------BASIC INFO-------\r\n')
        output.write("\r\n")
        output.write('Host: {} ({})\r\n'.format(host, nm_scanner[host].hostname()))
        output.write('State: {}\r\n'.format(nm_scanner[host].state()))
        output.write("Found OS: " + str(nm_scanner[host].get('os')) + "\r\n")
        output.write("\r\n")
        csv_parser(csv, output)  # Calls csvParser function


def csv_parser(csv, output):
    """
    First, csvParser splits the data into a more sortable format.
    Then, it outputs to the file.
    Finally, it calls 'vulnersSearcher'.
    """
    csv = csv.splitlines()  # Splits data
    output.write('-------SERVICES-------\r\n')  # Spacer
    output.write("\r\n")
    port = [i.split(";")[4] for i in csv]  # Sorts port number
    name = [i.split(';')[5] for i in csv]  # Sorts name of the port
    state = [i.split(';')[6] for i in csv]  # Sorts out the state of the port
    product = [i.split(';')[7] for i in csv]  # Sorts product (if available)
    extrainfo = [i.split(';')[8] for i in csv]  # Sorts extrainfo (if there)
    version = [i.split(';')[10] for i in csv]  # Sorts version (if there)

    i = 0

    while i < len(name):
        if i == 0:  # Capitalizes the titles of the outputs
            output.write("Port Name State Extra Info Version \r\n")
        elif port[i] != port[i-1]:  # Outputs everything else as-is
            output.write("{} {} {} {} {} {}\r\n".format(
                port[i], name[i], state[i], product[i],
                extrainfo[i], version[i]))

        i = i + 1

    vulners_search(product, extrainfo, version, output)  # Calls next function


def vulners_search(product, extrainfo, version, output):
    """
    The function gets rid of dead space, and searches through the
    Vulners database.
    """

    i = 1

    while i < len(product):  # Searches Vulners database n times
        if not product[i]:  # Gets rid of blank space searches
            # Searches for exploits in the vulners database
            search = vulners_api.searchExploit(
                "{} {} {} order:cvss.score".format(
                    product[i], extrainfo[i], version[i]))

            if not search:  # If a search is blank, it doesn't output to file.
                return
            try:
                output.write("\r\n")
                output.write("-------VULNERABILITIES-------\r\n")  # Spacer
                output.write("\r\n")
                output.write("---" + product[i] + "---\r\n")
                search = str(search).split('"')  # Splits the data into blocks.
                search = str(search).split("', '")  # Splits the data further.
                search_output(search, output)
            except ValueError:
                pass

        i = i + 1

def search_output(search, output):
    """
    Takes output from vulners_search.
    After that, it splits and outputs that data to the file in a readable format.
    """
    title = [t for t in search if "title" in t]  # Searches title.
    href = [h for h in search if "href" in h]  # Searches for href.

    for i in range(len(title)):  # Prints data length of title.
        if len(title[i]) < 100:  # Limits data.
            try:
                output.write(
                    "Vulnerability: {}".format(
                        title[i].replace("'", "")
                        .replace("title", "").replace(": ", "")))
                output.write("\r\n")
                # Writes the title information to a file.
                output.write(
                    "Link: {}".format(
                        href[i].replace("'", "")
                        .replace("href", "").replace(": ", "")))
                output.write("\r\n")
                # Writes the href information to a file.
                output.write("~~~~~~~\r\n")
            except IndexError:
                pass

    output.close()

main()

print("Done.")
