## Description

Kronos is a personal project of mine that I started to learn more about python. It will continue to be the main place where I test my python programming skills. However, I feel that its uniqueness could be used for more than just by myself, and is why I have chose to release it on GitHub.
The end goal of this project is to create a flexible scanner that will easily search vulnerability databases.

**CURRENTLY ONLY TESTED IN WINDOWS**

## Current state

Uses nmap to scan a target, takes the received information to search the Vulners database, and outputs it to a file. Unfinished.

## Overall Goals

> Easy addition of vulners search terms.

> 99% polished tool for professional use.

> Cross-platform compatability (mac users, would love to have your help with testing).


## Current Tasks

> Better search result parsing to gather more data.

## Installation

This script uses nmap to get information about the host.
You **MUST** have nmap installed on your host machine in order for the script to work.
To install the dependencies that the script uses, simply use while in the Kronos directory:

`pip install -U -r dependencies.txt`

In order to use the script, you must get a Vulners API key. In order to get an API key, regist an account at the [Vulners website](https://vulners.com).
Once you have registered, go to the menu by click on your name in the top, right-hand corner.
Click on **API KEYS**. Generate an API key with scope "API".
From there, copy your API key into the code in place of ADD KEY HERE (Line 12).

That's it.

## Usage

To run Kronos, simply type: `python kronos.py x`, where x is the target host you want to scan, while in the Kronos directory.

**I hope that you enjoy this project as much as I do. Thanks for using!**
