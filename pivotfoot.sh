#!/bin/bash
#/bin/bash
# ------------------------------------------------------------------
# [Author] Toño Diaz - jupyterj1s
#          Title: Sabonis - Pivot foot
#          Description:
#
#          This script uses evtx_dump to parse all remote connection
#          related evtx logs in a folder and fixes some XML formatting 
#          for further processing with Sabonis
#          
#
# Dependency: https://github.com/omerbenamram/evtx
#     
# ------------------------------------------------------------------
VERSION=0.9
SUBJECT="Sabonis Pivot Tool - Toño Díaz"
USAGE="Usage: pivotfoot source_folder_with_evtx destination_folder"

# --- Option processing -------------------------------------------
if [ $# -ne 2 ] || [ $1 == "-h" ] || [ $1 == "-help" ] || [ $1 == "--h" ] || [ $1 == "--help" ]; then
    echo $USAGE
    exit 1;
fi

# --- Locks -------------------------------------------------------
LOCK_FILE=/tmp/${SUBJECT}.lock

if [ -f "$LOCK_FILE" ]; then
echo "Script is already running"
exit
fi

trap "rm -f $LOCK_FILE" EXIT
touch $LOCK_FILE

# -- Body ---------------------------------------------------------

source_folder=$1
dest_folder=$2

echo "  + EXECUTING SABONIS. LET'S FORENSICATE!..."
rm ${dest_folder}/*.xml
[ -f "${source_folder}/Security.evtx" ] && evtx_dump "${source_folder}/Security.evtx" -f "${dest_folder}/Security.evtx.xml" --dont-show-record-number --no-indent
[ -f "${source_folder}/Microsoft-Windows-SMBServer%4Security.evtx" ] && evtx_dump "${source_folder}/Microsoft-Windows-SMBServer%4Security.evtx" -f "${dest_folder}/Microsoft-Windows-SMBServer%4Security.evtx.xml" --dont-show-record-number --no-indent
[ -f "${source_folder}/Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx" ] && evtx_dump "${source_folder}/Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx" -f "${dest_folder}/Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx.xml" --dont-show-record-number --no-indent
[ -f "${source_folder}/Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx" ] && evtx_dump "${source_folder}/Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx" -f "${dest_folder}/Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx.xml" --dont-show-record-number --no-indent
[ -f "${source_folder}/Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx" ] && evtx_dump "${source_folder}/Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx" -f "${dest_folder}/Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx.xml" --dont-show-record-number --no-indent
[ -f "${source_folder}/Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx" ] && evtx_dump "${source_folder}/Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx" -f "${dest_folder}/Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx.xml" --dont-show-record-number --no-indent
[ -f "${source_folder}/Microsoft-Windows-SmbClient%4Security.evtx" ] && evtx_dump "${source_folder}/Microsoft-Windows-SmbClient%4Security.evtx" -f "${dest_folder}/Microsoft-Windows-SmbClient%4Security.evtx.xml" --dont-show-record-number --no-indent
sed -i 's+<?xml version="1.0" encoding="utf-8"?>++' ${dest_folder}/*.xml
sed -i '1s;^;<?xml version="1.0" encoding="utf-8"?><Events>;' ${dest_folder}/*.xml
echo -e "</Events>"  | tee -a ${dest_folder}/*.xml

# -----------------------------------------------------------------