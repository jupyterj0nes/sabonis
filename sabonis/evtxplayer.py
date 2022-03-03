#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pandas
import getpass
import numpy as np
import os
from py2neo import Graph, Node, Relationship
import webbrowser
import Evtx.Evtx as evtx
import lxml
from tqdm import tqdm
import xml.etree.ElementTree as ET

class EvtxParser:
    def __init__(self,source_artifact,only_first="False",stats="False",exclusionlist=None,focuslist=None,ignore_local=None,directory=None,timezone=None,outputfile=None):
        self.source_artifact=source_artifact
        self.only_first=only_first
        self.stats=stats
        self.exclusionlist=exclusionlist
        self.focuslist=focuslist
        self.ignore_local=ignore_local
        self.directory=directory
        self.timezone=timezone
        self.outputfile=outputfile

    def read(self):
        df = self.parseSecurity()
        if self.directory:
            df = self.parseTSLocalSession(df)
            df = self.parseTSRemoteConnetion(df)
            df = self.parseRDPClient(df)
            df = self.parseSMBServer(df)        
            df = self.parseRDPCoreTS(df)
            df = self.parseSMBClient(df)
        if self.timezone:
            df["time"]=df["time"].astype("datetime64[s]")
            df["time"] = df["time"].dt.tz_localize('UTC')
            df["time"] = df["time"].dt.tz_convert(self.timezone)

        if self.ignore_local:
            exclude_hosts=['','127.0.0.1','nan','-','::1','LOCAL','local']
            for host in exclude_hosts:
                df['source_ip'].replace(host, np.nan, inplace=True)
            df.dropna(subset=['source_ip'], inplace=True)

        df["source_ip"] = [ele.split(":")[0] if ":" in ele else ele for ele in df["source_ip"]]
        df['source_ip'] = df['source_ip'].map(lambda x: x.lstrip('[]\\').rstrip('[]'))
        df['remote_user'] = df['remote_user'].fillna("NoUser")
        df["source_ip"].fillna(df["hostname"], inplace=True)

        if self.focuslist:
            with open(self.focuslist) as f:
                focus_words= f.read().splitlines()
            df1=df.append(df[df["source_ip"].str.contains('|'.join(focus_words))], ignore_index=True)
            df1=df1.append(df[df["remote_user"].str.contains('|'.join(focus_words))], ignore_index=True)
            df1=df1.append(df[df["source_hostname"].str.contains('|'.join(focus_words))], ignore_index=True)
            df=df1
        if self.exclusionlist:
            with open(self.exclusionlist) as f:
                exclude_words= f.read().splitlines()
            df=df[~df["source_ip"].str.contains('|'.join(exclude_words))]
            df=df[~df["remote_user"].str.contains('|'.join(exclude_words))]
            df=df[~df["source_hostname"].str.contains('|'.join(exclude_words))]

        if self.only_first:

            df=df.sort_values('time').groupby(["source_ip","remote_user"],as_index=False).nth(0)
        
        if self.stats:
            print(f"SABONIS: Global statistics of {self.source_artifact}:")
            print()
            print(df.describe(include='all',datetime_is_numeric=True))
            print()
            print("Top 50 source IPs:")
            top50domains=df['source_ip'].value_counts().nlargest(50)
            with open(self.outputfile+"evtxtop50sourceIPs.csv",'a') as file1:
                for domain in top50domains.index:
                    file1.write(domain+ '\n')
            print(top50domains)
            print()
            print("Top 50 remote users:")
            top50destips=df['remote_user'].value_counts().nlargest(50)
            with open(self.outputfile+"evtxtop50remoteusers.csv",'a') as file1:
                for ip in top50destips.index:
                    file1.write(ip+ '\n')
            print(top50destips)
            print()
        self.df=df

    def parseSecurity(self):
        print("  - EVTX SABONIS: Started Security.evtx XML to dataframe conversion")
        if not self.directory:
            security_log=self.source_artifact
        else:
            security_log=self.source_artifact+"Security.evtx.xml"

        event_list = []
        capture=False
        try:
            for event, elem in tqdm(ET.iterparse(security_log, events=("start","end"))):
                if elem.tag.endswith("}Event") and event=="end":
                    if capture:
                        if source_ip in ("","-") and source_hostname not in ("","-"):
                            source_ip=str(source_hostname)
                        event_list.append((f"{timecreated},{event_id},{computername},{user},{source_ip},{source_hostname},{logon_type},{remote_user},{remote_domain},Security.evtx"))
                        capture=False
                    elem.clear()

                interesting_eventids = ["4624","4625","4648","4778","4647","4634","4779","4776"]

                if elem.tag.endswith("EventID") and event=="start" and elem.text in interesting_eventids:
                    capture=True
                    source_ip=""
                    source_hostname=""
                    logon_type=""
                    remote_user=""
                    remote_domain=""
                    user=""
                    timecreated=""
                    computername=""
                    event_id=elem.text

                if elem.tag.endswith("TimeCreated") and capture:
                    timecreated=elem.attrib["SystemTime"]

                if elem.tag.endswith("Computer") and capture:
                    computername=elem.text

                if elem.tag.endswith("Security") and "UserID" in elem.attrib and capture:
                    user=elem.attrib["UserID"]

                if elem.tag.endswith("}Data") and "Name" in elem.attrib and elem.attrib["Name"]=="IpAddress" and capture:
                    source_ip=elem.text

                if elem.tag.endswith("}Data") and "Name" in elem.attrib and elem.attrib["Name"]=="WorkstationName" and capture:
                    source_hostname=elem.text

                if elem.tag.endswith("}Data") and "Name" in elem.attrib and elem.attrib["Name"]=="Workstation" and capture:
                    source_hostname=elem.text

                if elem.tag.endswith("}Data") and "Name" in elem.attrib and elem.attrib["Name"]=="LogonType" and capture:
                    logon_type=elem.text

                if elem.tag.endswith("}Data") and "Name" in elem.attrib and elem.attrib["Name"]=="TargetUserName" and capture:
                    remote_user=elem.text

                if elem.tag.endswith("}Data") and "Name" in elem.attrib and elem.attrib["Name"]=="TargetDomainName" and capture:
                    remote_domain=elem.text
        except Exception:
            pass

        df = pandas.DataFrame([sub.split(",") for sub in event_list],columns =['time', 'event_id','hostname','user','source_ip','source_hostname','logon_type','remote_user','remote_domain','source_artifact'])
        df = df.sort_values('time')
        df = df.apply(lambda x: x.astype(str).str.lower())
        print("  - EVTX PROCESSHUNTER: Finished Security.evtx XML to dataframe parsing")
        return df

    def parseSMBServer(self, df):
        print("  - EVTX SABONIS: Started Microsoft-Windows-SMBServer%4Security.evtx XML to dataframe conversion")
        logfilename=self.source_artifact+"Microsoft-Windows-SMBServer%4Security.evtx.xml"
        if os.path.isfile(logfilename):

            event_list = []
            capture=False
            try:
                for event, elem in tqdm(ET.iterparse(logfilename, events=("start","end"))):
                    if elem.tag.endswith("}Event") and event=="end":
                        if capture and source_ip:
                            event_list.append((f"{timecreated},{event_id},{computername},{user},{source_ip},{source_hostname},{logon_type},{remote_user},{remote_domain},Microsoft-Windows-SMBServer%4Security.evtx"))
                            capture=False
                        elem.clear()

                    interesting_eventids = ["1009"]

                    if elem.tag.endswith("EventID") and event=="start" and elem.text in interesting_eventids:
                        capture=True
                        source_ip=""
                        source_hostname=""
                        logon_type="3"
                        remote_user=""
                        remote_domain=""
                        user=""
                        timecreated=""
                        computername=""
                        event_id=elem.text

                    if elem.tag.endswith("TimeCreated") and capture:
                        timecreated=elem.attrib["SystemTime"]

                    if elem.tag.endswith("Computer") and capture:
                        computername=elem.text

                    if elem.tag.endswith("Security") and "UserID" in elem.attrib and capture:
                        user=elem.attrib["UserID"]

                    if elem.tag.endswith("ClientName") and capture:
                        source_ip=elem.text

                    if elem.tag.endswith("}Data") and "Name" in elem.attrib and elem.attrib["Name"]=="UserName" and capture:
                        remote_user=elem.text
                        
            except Exception:
                pass

            df=df.append(pandas.DataFrame([sub.split(",") for sub in event_list], columns=['time', 'event_id','hostname','user','source_ip','source_hostname','logon_type','remote_user','remote_domain','source_artifact']),ignore_index=True)
            df = df.sort_values('time')
            df = df.apply(lambda x: x.astype(str).str.lower())
            print("  - EVTX SABONIS: Finished Microsoft-Windows-SMBServer%4Security.evtx XML to dataframe conversion")    
        return df

    def parseSMBClient(self, df):
        print("  - EVTX SABONIS: Started Microsoft-Windows-SmbClient%4Security.evtx XML to dataframe conversion")
        logfilename=self.source_artifact+"Microsoft-Windows-SmbClient%4Security.evtx.xml"
        if os.path.isfile(logfilename):

            event_list = []
            capture=False
            try:
                for event, elem in tqdm(ET.iterparse(logfilename, events=("start","end"))):
                    if elem.tag.endswith("}Event") and event=="end":
                        if capture and source_ip:
                            event_list.append((f"{timecreated},{event_id},{computername},{user},{source_ip},{source_hostname},{logon_type},{remote_user},{remote_domain},Microsoft-Windows-SmbClient%4Security.evtx"))
                            capture=False
                        elem.clear()

                    interesting_eventids = ["31001"]

                    if elem.tag.endswith("EventID") and event=="start" and elem.text in interesting_eventids:
                        capture=True
                        source_ip=""
                        source_hostname=""
                        logon_type="3"
                        remote_user=""
                        remote_domain=""
                        user=""
                        timecreated=""
                        computername=""
                        event_id=elem.text

                    if elem.tag.endswith("TimeCreated") and capture:
                        timecreated=elem.attrib["SystemTime"]

                    if elem.tag.endswith("Computer") and capture:
                        source_hostname=elem.text
                        source_ip=elem.text

                    if elem.tag.endswith("}Data") and "Name" in elem.attrib and elem.attrib["Name"]=="ServerName" and capture:
                        computername=elem.text

                    if elem.tag.endswith("}Data") and "Name" in elem.attrib and elem.attrib["Name"]=="UserName" and capture:
                        remote_user=elem.text
            except Exception:
                pass

            df=df.append(pandas.DataFrame([sub.split(",") for sub in event_list], columns=['time', 'event_id','hostname','user','source_ip','source_hostname','logon_type','remote_user','remote_domain','source_artifact']),ignore_index=True)
            df = df.sort_values('time')
            df = df.apply(lambda x: x.astype(str).str.lower())
            print("  - EVTX SABONIS: Finished Microsoft-Windows-SmbClient%4Security.evtx XML to dataframe conversion")
        return df

    def parseRDPClient(self, df):
        print("  - EVTX SABONIS: Started Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx XML to dataframe conversion")
        logfilename=self.source_artifact+"Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx.xml"
        if os.path.isfile(logfilename):

            event_list = []
            capture=False
            try:
                for event, elem in tqdm(ET.iterparse(logfilename, events=("start","end"))):
                    if elem.tag.endswith("}Event") and event=="end":
                        if capture and source_ip:
                            event_list.append((f"{timecreated},{event_id},{computername},{user},{source_ip},{source_hostname},{logon_type},{remote_user},{remote_domain},Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx"))
                            capture=False
                        elem.clear()

                    interesting_eventids = ["1024","1102"]

                    if elem.tag.endswith("EventID") and event=="start" and elem.text in interesting_eventids:
                        capture=True
                        source_ip=""
                        source_hostname=""
                        logon_type="10"
                        remote_user=""
                        remote_domain=""
                        user=""
                        timecreated=""
                        computername=""
                        event_id=elem.text

                    if elem.tag.endswith("TimeCreated") and capture:
                        timecreated=elem.attrib["SystemTime"]

                    if elem.tag.endswith("Computer") and capture:
                        source_hostname=elem.text
                        source_ip=elem.text

                    if elem.tag.endswith("Security") and "UserID" in elem.attrib and capture:
                        remote_user=elem.attrib["UserID"]

                    if elem.tag.endswith("}Data") and "Name" in elem.attrib and elem.attrib["Name"]=="Value" and capture:
                        computername=elem.text

                    if elem.tag.endswith("}Data") and "Name" in elem.attrib and elem.attrib["Name"]=="UserName" and capture:
                        remote_user=elem.text
            except Exception:
                pass

            df=df.append(pandas.DataFrame([sub.split(",") for sub in event_list], columns=['time', 'event_id','hostname','user','source_ip','source_hostname','logon_type','remote_user','remote_domain','source_artifact']),ignore_index=True)
            df = df.sort_values('time')
            df = df.apply(lambda x: x.astype(str).str.lower())
            print("  - EVTX SABONIS: Finished Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx XML to dataframe conversion")
        return df

    def parseTSRemoteConnetion(self, df):
        print("  - EVTX SABONIS: Started Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx XML to dataframe conversion")
        logfilename=self.source_artifact+"Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx.xml"
        if os.path.isfile(logfilename):

            event_list = []
            capture=False
            try:
                for event, elem in tqdm(ET.iterparse(logfilename, events=("start","end"))):
                    if elem.tag.endswith("}Event") and event=="end":
                        if capture and source_ip:
                            event_list.append((f"{timecreated},{event_id},{computername},{user},{source_ip},{source_hostname},{logon_type},{remote_user},{remote_domain},Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx"))
                            capture=False
                        elem.clear()

                    interesting_eventids = ["1149"]

                    if elem.tag.endswith("EventID") and event=="start" and elem.text in interesting_eventids:
                        capture=True
                        source_ip=""
                        source_hostname=""
                        logon_type="10"
                        remote_user=""
                        remote_domain=""
                        user=""
                        timecreated=""
                        computername=""
                        event_id=elem.text

                    if elem.tag.endswith("TimeCreated") and capture:
                        timecreated=elem.attrib["SystemTime"]

                    if elem.tag.endswith("Computer") and capture:
                        computername=elem.text

                    if elem.tag.endswith("Security") and "UserID" in elem.attrib and capture:
                        user=elem.attrib["UserID"]

                    if elem.tag.endswith("Param3") and capture:
                        source_ip=elem.text

                    if elem.tag.endswith("Param2") and capture:
                        remote_domain=elem.text

                    if elem.tag.endswith("Param1") and capture:
                        remote_user=elem.text
                        
            except Exception:
                pass

            df=df.append(pandas.DataFrame([sub.split(",") for sub in event_list], columns=['time', 'event_id','hostname','user','source_ip','source_hostname','logon_type','remote_user','remote_domain','source_artifact']),ignore_index=True)
            df = df.sort_values('time')
            df = df.apply(lambda x: x.astype(str).str.lower())
            print("  - EVTX SABONIS: Finished Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx XML to dataframe conversion")
        return df

    def parseTSLocalSession(self, df):
        print("  - EVTX SABONIS: Started Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx XML to dataframe conversion")
        logfilename=self.source_artifact+"Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx.xml"
        if os.path.isfile(logfilename):

            event_list = []
            capture=False
            try:
                for event, elem in tqdm(ET.iterparse(logfilename, events=("start","end"))):
                    if elem.tag.endswith("}Event") and event=="end":
                        if capture and source_ip:
                            event_list.append((f"{timecreated},{event_id},{computername},{user},{source_ip},{source_hostname},{logon_type},{remote_user},{remote_domain},Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"))
                            capture=False
                        elem.clear()

                    interesting_eventids = ["21","22","24","25"]

                    if elem.tag.endswith("EventID") and event=="start" and elem.text in interesting_eventids:
                        capture=True
                        source_ip=""
                        source_hostname=""
                        logon_type="10"
                        remote_user=""
                        remote_domain=""
                        user=""
                        timecreated=""
                        computername=""
                        event_id=elem.text

                    if elem.tag.endswith("TimeCreated") and capture:
                        timecreated=elem.attrib["SystemTime"]

                    if elem.tag.endswith("Computer") and capture:
                        computername=elem.text

                    if elem.tag.endswith("Security") and "UserID" in elem.attrib and capture:
                        user=elem.attrib["UserID"]

                    if elem.tag.endswith("Address") and capture:
                        source_ip=elem.text

                    if elem.tag.endswith("User") and capture:
                        remote_user=elem.text
                        if ("\\") in remote_user:
                            remote_domain=remote_user.split("\\")[0]
                            remote_user=remote_user.split("\\")[1]   
            except Exception:
                pass

            df=df.append(pandas.DataFrame([sub.split(",") for sub in event_list], columns=['time', 'event_id','hostname','user','source_ip','source_hostname','logon_type','remote_user','remote_domain','source_artifact']),ignore_index=True)
            df = df.sort_values('time')
            df = df.apply(lambda x: x.astype(str).str.lower())
            print("  - EVTX SABONIS: Finished Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx XML to dataframe conversion")
        return df

    def parseRDPCoreTS(self, df):
        print("  - EVTX SABONIS: Started Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx XML to dataframe conversion")
        logfilename=self.source_artifact+"Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx.xml"
        if os.path.isfile(logfilename):

            event_list = []
            capture=False
            try:
                for event, elem in tqdm(ET.iterparse(logfilename, events=("start","end"))):
                    if elem.tag.endswith("}Event") and event=="end":
                        if capture and source_ip:
                            event_list.append((f"{timecreated},{event_id},{computername},{user},{source_ip},{source_hostname},{logon_type},{remote_user},{remote_domain},Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx"))
                            capture=False
                        elem.clear()

                    interesting_eventids = ["131"]

                    if elem.tag.endswith("EventID") and event=="start" and elem.text in interesting_eventids:
                        capture=True
                        source_ip=""
                        source_hostname=""
                        logon_type="10"
                        remote_user=""
                        remote_domain=""
                        user=""
                        timecreated=""
                        computername=""
                        event_id=elem.text

                    if elem.tag.endswith("TimeCreated") and capture:
                        timecreated=elem.attrib["SystemTime"]

                    if elem.tag.endswith("Computer") and capture:
                        computername=elem.text

                    if elem.tag.endswith("Security") and "UserID" in elem.attrib and capture:
                        user=elem.attrib["UserID"]

                    if elem.tag.endswith("}Data") and "Name" in elem.attrib and elem.attrib["Name"]=="ClientIP" and capture:
                        source_ip=elem.text

            except Exception:
                pass

            df=df.append(pandas.DataFrame([sub.split(",") for sub in event_list], columns=['time', 'event_id','hostname','user','source_ip','source_hostname','logon_type','remote_user','remote_domain','source_artifact']),ignore_index=True)
            df = df.sort_values('time')
            df = df.apply(lambda x: x.astype(str).str.lower())
            print("  - EVTX SABONIS: Finished Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx XML to dataframe conversion")
        return df

    def write(self,filepath):
        self.df.to_csv(filepath, index = False, header=True)
        print(f"SABONIS: EVTX evidence has been processed succesfully and writen to {filepath}")

class EvtxLoader:
    def __init__(self,csv_input,ne04j_url,ne04j_user):
        self.csv_input=csv_input
        self.ne04j_url=ne04j_url
        self.ne04j_user=ne04j_user
        self.graph = Graph(ne04j_url, user=ne04j_user, password=getpass.getpass("Enter ne04j database password: "))

    def load(self):
        transaction = self.graph.begin()
        df = pandas.read_csv(self.csv_input)
        for index, row in df.iterrows():
            if row['source_ip']:
                transaction.evaluate(f'''
                MERGE (origin:host{{name:'{row['source_ip']}'}})
                MERGE (destination:host{{name:'{row['hostname']}'}})
                MERGE (origin)-[r:{row['remote_user'].replace('.','_').replace('-','_').replace(' ','_').split("@")[0]}{{time:datetime("{row['time'].replace(' utc','').replace(' ','T')}"), user:'{row['remote_user'].replace('.','_').replace('-','_').replace(' ','_').split("@")[0]}', logon_type:'{row['logon_type']}', source_hostname:'{row['source_hostname']}', remote_domain:'{row['remote_domain']}'}}]->(destination)
                ''')

        transaction.commit()
        answer=input (f"SABONIS: Data from {self.csv_input} has been correctly loaded. Press Y if you want to open it:")
        if answer=='Y':
            webbrowser.open(self.ne04j_url.replace("bolt", "http").replace("7687", "7474"), new=2)