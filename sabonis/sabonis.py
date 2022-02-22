#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###############################################################################
'''SABONIS
   ------
   Tool for pivoting investigations
   Great investigations need great pivots
   '''
###############################################################################

import os
import sys
import argparse
#from proxyplayer import *
#from pcapplayer import *
from evtxplayer import *


__author__       = "Antonio Diaz"
__copyright__   = "jupyterj1s"
__version__      = "1.0"

def parse_arguments():
    parser = argparse.ArgumentParser(description="parse forensics artifacts to CSV and load them into neo4j database")
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    parser.add_argument("action", help="choose the action to perform",choices=["parse","load2neo"])
    parser.add_argument("type", help="type of artifact",choices=["pcap","proxy","evtx","freestyle"])
    parser.add_argument('--source_artifact',help="forensic artifact file")
    parser.add_argument('--csv_output',help="Resulting CSV ready to be loaded")
    parser.add_argument('--csv_input',help="Processed CSV to be loaded into Neo4j instance")
    parser.add_argument('--ne04j_url',help="Ne04j database URL in bolt format")
    parser.add_argument('--ne04j_user',help="Ne04j database user. Pass will be prompted")
    parser.add_argument('--only_first',help="Just parse first connections of the group source_IP, user, dest_IP",action='store_true')
    parser.add_argument('--ignore_local',help="Just include remote logins",action='store_true')
    parser.add_argument('--stats',help="Display stats of processed evidence",action='store_true')
    parser.add_argument('--directory',help="Parses a whole winevt/Logs directory and merges results",action='store_true')
    parser.add_argument('--exclusionlist',help="Excludes all the evidence logs or packets that contain strings included in this wordlist")
    parser.add_argument('--focuslist',help="Parser will ONLY process the evidence logs or packets that contain strings included in this wordlist")
    parser.add_argument('--timezone',help="All dates with be converted to specified timezone. Ex: Europe/Leon")


    
    args= parser.parse_args()

    if args.action=="parse" and (args.csv_output is None):
        parser.error("parse option requires --csv_output")

    if args.action=="parse" and (args.source_artifact is None):
        parser.error("parse option requires --source_artifact")

    if args.action=="parse" and not args.directory and not os.path.isfile(args.source_artifact):
        parser.error(f"File {args.source_artifact} does not exist")

    if args.action=="load2neo" and (args.csv_input is None ):
        parser.error("load option requires --csv_input")

    if args.action=="load2neo" and not os.path.isfile(args.csv_input):
        parser.error(f"File {args.csv_input} does not exist")

    if args.action=="load2neo" and (args.ne04j_url is None):
        parser.error("load option requires --ne04j_url")

    if args.action=="load2neo" and (args.ne04j_user is None ):
        parser.error("load option requires --ne04j_user")

    if args.focuslist and not os.path.isfile(args.focuslist):
        parser.error(f"File {args.focuslist} does not exist")

    if args.exclusionlist and not os.path.isfile(args.exclusionlist):
        parser.error(f"File {args.exclusionlist} does not exist")

    if args.directory and not os.path.isdir(args.source_artifact):
        parser.error(f"Directory {args.source_artifact} does not exist.")

    if args.directory:
        if (("\\") in args.source_artifact) and (not args.source_artifact.endswith("\\")):
            args.source_artifact=args.source_artifact+"\\"
        elif (("/") in args.source_artifact) and (not args.source_artifact.endswith("/")):
            args.source_artifact=args.source_artifact+"/"   
    return args


def parse_pcap(arguments):
    pcapparser=PcapParser(arguments.source_artifact,arguments.only_first,arguments.stats,arguments.exclusionlist,arguments.focuslist)
    pcapparser.read()
    pcapparser.write(arguments.csv_output)

def parse_proxy(arguments):
    proxyparser=ProxyParser(arguments.source_artifact,arguments.only_first,arguments.stats,arguments.exclusionlist,arguments.focuslist)
    proxyparser.read()
    proxyparser.write(arguments.csv_output)
    
def parse_evtx(arguments):
    evtxparser=EvtxParser(arguments.source_artifact,arguments.only_first,arguments.stats,arguments.exclusionlist,arguments.focuslist,arguments.ignore_local,arguments.directory,arguments.timezone,arguments.csv_output)
    evtxparser.read()
    evtxparser.write(arguments.csv_output)

def parse_freestyle(arguments):
    print (arguments.action)
    print (arguments.type)

def load2neo_pcap(arguments):
    pcaploader=PcapLoader(arguments.csv_input,arguments.ne04j_url,arguments.ne04j_user)
    pcaploader.load()

def load2neo_proxy(arguments):
    proxyloader=ProxyLoader(arguments.csv_input,arguments.ne04j_url,arguments.ne04j_user)
    proxyloader.load()

def load2neo_evtx(arguments):
    evtxloader=EvtxLoader(arguments.csv_input,arguments.ne04j_url,arguments.ne04j_user)
    evtxloader.load()

def load2neo_freestyle(arguments):
    print (arguments.action)
    print (arguments.type)

#----------#
def main(arguments):
#----------#
    options = {
    'parse':
        {
        'pcap': parse_pcap,
        'proxy': parse_proxy,
        'evtx': parse_evtx,
        'freestyle': parse_freestyle
        },
    'load2neo' : 
        {
        'pcap': load2neo_pcap,
        'proxy': load2neo_proxy,
        'evtx': load2neo_evtx,
        'freestyle': load2neo_freestyle
        }
    }
    options[arguments.action][arguments.type](arguments)
    
##################
if __name__ == '__main__':
    arguments = parse_arguments()
    main(arguments)