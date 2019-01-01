Kronos is a personal project of mine that I started to learn more about python, and will continue to be my way of learning python, but I feel that it could be used for more than that.
The end goal of this project is to create an all-in-one security scanner that anyone can use.

## Current state

Uses nmap to scan a target, takes the received information to search the Vulners database, and outputs it to a file in an easy-to-read format. Unfinished.

## Goals

> Incorporate a plethora of tools to make a versatile python scanning script that anyone can add on to.

## Installation

Currently, only two modules are required to run Kronos: vulners and python-nmap. 
Use the command below to install them:

```pip install vulners python-nmap```

That's it.

## Usage

To run Kronos, simply type: `python kronos.py --host x`, where x is the host you want to scan, while in the Kronos directory.

**IF**, when you run the script, you get an AttributeError, that is due to you missing the vulners api key.
In order to get an api key, register at the [vulners website](https://vulners.com). 
Once you have registered, go to the menu by clicking on your name in the top right-hand corner. 
Click on the **API KEYS** tab. Generate an api key with the scope "api".
From there, copy your api key into the code in place of ADD KEY HERE in the VULNERSAPI variable (Line 24).

**I hope that you enjoy this project as much as I do. Thanks for downloading!**
