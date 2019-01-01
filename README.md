Kronos is a personal project of mine that I started to learn more about python, and will continue to be my way of learning python, but I feel that it could be used for more than that. The end goal of this project is to create an all-in-one security scanner that anyone can use.

## Current state

Uses nmap to scan a target, takes the received information to search the Vulners database, and outputs it to a file in an easy-to-read format.

## Goals

> Incorporate a plethora of tools to make a versatile python script that anyone can add on to.

## Installation

Currently, only three modules are required to run Kronos: vulners, python-nmap, and validators. Use the command below to install them:

```pip install vulners python-nmap validators```

That's all there is to it.

## Usage

To run Kronos, simply type: `python kronos.py --host x`, where x is the host you want to scan, while in the Kronos directory.


**I hope that you enjoy this project as much as I do. Thanks for downloading!**
