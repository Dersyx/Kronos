# -*- coding: utf-8 -*-
# Imports
import argparse
import time
import subprocess
import os
import vulners
from bs4 import BeautifulSoup

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

def main():
    """
    The main function initiates any variables that are needed, and sets
    everything else up to be used by the functions.
    After the functions are done with their process, it deletes some left over
    files, and closes the output file, thereby ending the script.
    """

    vulners_api = vulners.Vulners(
        api_key="56IOL4ZVC71E74Z5GC3CCM0MK43NZNZLAZJHWV6XPQTQ37CRKQT06XAXSPV3NTVG")  # Vulners API key needed to search the vulners database. Replace ADD KEY HERE with your personal API key.

    parser = argparse.ArgumentParser(
        description="Kronos V1, a modern, python based vulnerability scanner by Dersyx. https://github.com/Dersyx/Kronos") # Provides a description for the argument parser, which is called with the -h option.
    parser.add_argument('target', action="store", help="Target that you want to scan.")  # Adds --target argument needed to use nmap.
    parser.add_argument('--keep-xml', action='store_true', dest='keep_xml', help="Allows you to store the resulting xml file from the nmap scan.")
    parser.add_argument('--keep-vulners', action='store_true', dest='keep_vulners', help="Allows you to save the vulners search data to an external file, for deeper parsing of the data.")

    given_args = parser.parse_args()  # Parses the arguments given.
    target = given_args.target  # Assigns the --target argument to a variable.
    keep_xml = given_args.keep_xml

    print("\r\nScanning: {}".format(target))  # Prints a console output to let the user know that the script is working.
    time_file = time.strftime("%m-%d-%Y_%H.%M.%S")  # Grabs the current time when the variable is initiated. Used for file names.
    products, extrainfo, versions, output = nmap_scan(target, time_file)  # Calls upon nmap_scan, and assigns the returned output to variables for vulners_search.

    if not keep_xml:
        os.remove('nmap-output.xml')  # Removes the output file created by nmap. File is needed to parse variables silently.

#    if keep_vulners:
    vulners_search(products, extrainfo, versions, output, vulners_api)  # Calls upon vulners_search with variables supplied by nmap_scan and by the main() function.
#    else:
#        vulners_search(products, extrainfo, versions, output, vulners_api)
    output.close()  # Closes the output .txt file.

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

def nmap_scan(target, time_file):
    """
    Function starts the output .txt file, and scans the host.
    Uses BeautifulSoup library to parse the .xml file.
    After, assigns the parsed xml to variables, and writes out to the output file.
    Returns variables necessary for vulners_search()
    """
    output_null = open(os.devnull, 'w')  # Sets up variable output to dump output to, in order to make nmap silent in the terminal.
    subprocess.run(['nmap', target, '-oX', 'nmap-output.xml', '-sV'], stdout=output_null)  # Executes nmap program installed on system, and outputs to nmap_output.xml.
    xml_file = open("nmap-output.xml", "r")  # Opens the output file of nmap, to be used for parsing.
    soup = BeautifulSoup(xml_file, 'xml')  # Creates a variable to interface with the output file variable xml_file.

    # Opens a file with the time and host of the scan.
    output = open("{}_{}.txt".format(target, time_file), "w+", encoding="UTF-8")  # Opens output file with current system time and UTF-8 encoding.

    output.write('-------BASIC INFO-------\r\n\r\n')  # Spaces
    for address in soup.find_all('address'):  # Finds all the addresses found in the scan.
        output.write('Host: {} ({})\r\n'.format(target, address.get('addr')))  # Outputs the IP address to the file.
    for status in soup.find_all('status'):  # Finds the state of the machine scanned.
        output.write('State: {}\r\n'.format(status.get('state')))  # Outputs the state of the machine scanned.

    output.write('\r\n-------SERVICES-------\r\n\r\n')  # Spacer

    # Sets empty lists for the variables in the .xml file to be assigned to.
    ports = []  # Ports list.
    port_names = []  # Name of the ports list.
    states = []  # The states of the ports list.
    products = []  # The products on each port, if found.
    versions = []  # The versions of the products on each port, if found.
    extrainfo = []  # Any extra info found about the products on each port, if found.


    for i in soup.find_all('port'):  # Finds all instances of 'port' in the .xml.
        ports.append(i.get('portid'))  # Appends each port number found.
    for i in soup.find_all('state'):  # Finds all instances of 'state' in the .xml.
        states.append(i.get('state'))  # Appends each port state found.
    for i in soup.find_all('service'):  # Finds all instances of 'service' in the .xml.
        port_names.append(i.get('name'))  # Appends each port name found.
        products.append(i.get('product'))  # Appends each product found, if any.
        versions.append(i.get('version'))  # Appends each version of the product found, if any.
        extrainfo.append(i.get('extrainfo'))  # Appends any extra info found about the products, if any.

    i = 0  # Sets while loop iteration variable.
    while i != len(ports):  # Loops through each of the lists, and makes sure that it doesn't catch an IndexError.
        output.write('{:<12} {:<12} {:<12}'.format(ports[i], states[i], port_names[i]))  # Prints the port numbers, their states, and the names of each port.
        if products[i] is not None:  # Catches any instance of None in the products list, which occurs if there is no product found in the .xml document.
            output.write('{:<12}'.format(products[i]))  # Writes product name, if it passes the if statement above.
        if versions[i] is not None:  # Catches any instance of None in the versions list; explained in if products[i].
            output.write('{:<12}'.format(versions[i]))  # Writes version info, if it passes the if statement above.
        if extrainfo[i] is not None:  # Catches any instance of None in the extrainfo list; explained in if products[i].
            output.write('{:<12}'.format(extrainfo[i]))  # Writes extra info, if it passes the if statement above.
        output.write('\r\n')  # Outputs to a new line for the next iteration through the while loop.
        i = i + 1  # Increments i variable for while loop.

    return (products, extrainfo, versions, output)  # Returns necessary info back to main() for use in vulners_search().

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

def vulners_search(products, extrainfo, versions, output, vulners_api):
    """
    This function takes in the data from nmap_scan, searches the vulners database for any info relating to it, and outputs it to a file.
    """
    i = 1

    while i < len(products):  # Searches Vulners database i times
        if products[i] == "None":  # Checks if current list placement value is equal to "None"
            products[i].remove("None")  # If it is equal to "None", it is removed from the list.
        elif extrainfo[i] == "None":  # Checks if current list placement value is equal to "None"
            extrainfo[i].remove("None")  # If it is equal to "None", it is removed from the list.
        elif versions[i] == "None":  # Checks if current list placement value is equal to "None"
            versions[i].remove("None")  # If it is equal to "None", it is removed from the list.

        # Searches for exploits in the vulners database with anything products, extrainfo, and versions of products found by nmap_scan.
        search = vulners_api.searchExploit("{} {} {} order:cvss.score".format(products[i], extrainfo[i], versions[i]))

        if not search:  # If a search is blank, it doesn't output to the file.
            return

        output.write("\r\n-------VULNERABILITIES-------\r\n\r\n")  # Spacer
        output.write("---{}---\r\n".format(products[i]))
        search = str(search).split('"')  # Splits the data into blocks.
        search = str(search).split("', '")  # Splits the data further.

        title = [t for t in search if "title" in t]  # Searches for titles of exploits found in the vulners database search.
        href = [h for h in search if "href" in h]  # Searches for href links from exploit enteries found in the vulners database search.
        for i in range(len(title)):  # Prints data length of title.
            try:
                if len(title[i]) < 100:
                    output.write("Vulnerability: {}\r\n".format(title[i].replace("'", "").replace("title", "").replace(": ", "")))  # Writes the title information to a file, and replaces dead space with nothing.
                    href_temp = href[i].replace("'", "").replace("href", "").replace(": ", "").replace("\r", "").replace("\n", "")
                    if href_temp and len(href_temp) < 200:
                        output.write("Link: {}\r\n".format(href_temp))  # Writes the href information to a file.
                    output.write("~~~~~~~\r\n")
            # Sometimes, the splitting above splits along big chunks of data that are irrelavent. If that does occur, this makes sure that does not get outputted to the .txt file.
            except IndexError:
                pass


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

main()

print("\r\nDone.")
