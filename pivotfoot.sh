#!/bin/bash
echo "  + EXECUTING SABONIS. LET'S FORENSICATE!..."
evtx_dump "${thisevtxf}/Security.evtx" -f "${modod}/Security.evtx.xml" --dont-show-record-number --no-indent
[ -f "${thisevtxf}/Microsoft-Windows-SMBServer%4Security.evtx" ] && evtx_dump "${thisevtxf}/Microsoft-Windows-SMBServer%4Security.evtx" --dont-show-record-number --no-indent
[ -f "${thisevtxf}/Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx" ] && evtx_dump "${thisevtxf}/Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx" --dont-show-record-number --no-indent
[ -f "${thisevtxf}/Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx" ] && evtx_dump "${thisevtxf}/Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx" --dont-show-record-number --no-indent
[ -f "${thisevtxf}/Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx" ] && evtx_dump "${thisevtxf}/Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx" --dont-show-record-number --no-indent
[ -f "${thisevtxf}/Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx" ] && evtx_dump "${thisevtxf}/Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx" --dont-show-record-number --no-indent
[ -f "${thisevtxf}/Microsoft-Windows-SmbClient%4Security.evtx" ] && evtx_dump "${thisevtxf}/Microsoft-Windows-SmbClient%4Security.evtx" --dont-show-record-number --no-indent
sed -i 's+<?xml version="1.0" encoding="utf-8"?>++' ${modod}/*.xml
sed -i '1s;^;<?xml version="1.0" encoding="utf-8"?><Events>;' ${modod}/*.xml
echo -e "</Events>"  | tee -a ${modod}/*.xml
sabonis.py parse evtx --source_artifact $modod --directory --csv_output $thisprocessof --ignore_local
