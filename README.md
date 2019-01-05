Kronos is a personal project of mine that I started to learn more about python. It will continue to be the main place where I test my python programming skills. However, I feel that its uniqueness could be used for more than just by myself, and is why I have chose to release it on GitHub.
The end goal of this project is to create a flexible scanner that will easily search vulnerability databases.

## Current state

Uses nmap to scan a target, takes the received information to search the Vulners database, and outputs it to a file. Unfinished.

## Overall Goals

> Allow for fluid incorporation of Nmap arguments from the command line (Most likely with something like `--arguments "-A -T4 -p-" `
> Allow for easy addition of search criteria from the command line
> Make a 99% polished tool for actual real-world use.
> Make it usable on all platforms (I do not personally own an apple product of any kind. If you have a desktop apple product, and would like to help with testing, I would really appreciate it. Message me with more details.

## Current Tasks

> Make more efficient than it currently is (takes a couple of minutes to run a scan).
> Add more options. Make every option less hard-coded.

## Installation

To install the dependencies that the script requires, simply run the command below while inside of the Kronos directory:

`pip install -r dependencies.txt`

That's it.

## Usage

To run Kronos, simply type: `python kronos.py --host x`, where x is the host you want to scan, while in the Kronos directory.

**IF**, when you run the script, you get an AttributeError, that is due to you missing the vulners api key.
In order to get an api key, register at the [vulners website](https://vulners.com). 
Once you have registered, go to the menu by clicking on your name in the top right-hand corner. 
Click on the **API KEYS** tab. Generate an api key with the scope "api".
From there, copy your api key into the code in place of ADD KEY HERE in the VULNERSAPI variable (Line 24).

**I hope that you enjoy this project as much as I do. Thanks for downloading!**
