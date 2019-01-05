## Description

Kronos is a personal project of mine that I started to learn more about python. It will continue to be the main place where I test my python programming skills. However, I feel that its uniqueness could be used for more than just by myself, and is why I have chose to release it on GitHub.
The end goal of this project is to create a flexible scanner that will easily search vulnerability databases.

## Current state

Uses nmap to scan a target, takes the received information to search the Vulners database, and outputs it to a file. Unfinished.

## Overall Goals

> Fluid incorporation of Nmap arguments from the command line (Example: `--arguments "-A -T4 -p-" `

> Easy addition of vulners search terms.

> 99% polished tool for professional use.

> Cross-platform compatability (mac users, would love to have your help with testing).


## Current Tasks

> Improve efficiency (currently takes 3-4 minutes/scan).

> More command-line arguments for flexability.

## Installation

To install the dependencies that the script requires, simply run the command below while inside of the Kronos directory:

`pip install -r dependencies.txt`

That's it.

## Usage

To run Kronos, simply type: `python kronos.py --host x`, where x is the host you want to scan, while in the Kronos directory.

**IF**, when you run the script, you get an AttributeError, that is due to the script missing the vulners api key.
In order to get an api key, register an account at [vulners website](https://vulners.com). 
Once you have registered, go to the menu by clicking on your name in the top right-hand corner. 
Click on the **API KEYS** tab. Generate an api key with the scope "api".
From there, copy your api key into the code in place of ADD KEY HERE in the VULNERSAPI variable (Line 12).

**I hope that you enjoy this project as much as I do. Thanks for downloading!**
