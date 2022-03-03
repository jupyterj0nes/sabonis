<div align="center">
 <p>
  <h1>
   Sabonis, a Digital Forensics and Incident Response pivoting tool
  </h1>
 </p>
<img style="padding:0;vertical-align:bottom;" height="76" width="300" src="sabonis.jpg"/>
</div>

---
Sabonis proves a way of quicly parse EVTX, proxy and PCAP files and extracting just the information related to lateral movements.
It also has the ability of loading all this information into a Neo4J database. This not only provides a graphic and easy-going way of investigating an incident, but also allows incidents handles to make use of the powerful graph database language "Cypher"

## Features
---

 - :mag: Extracts and merge lateral movements from more than 7 different EVTX files
 - :mag: Parses Squid proxy events
 - :mag: Extracts all lateral movements from PCAP files
 - :zap: Quick and low memory compuption
 - :bookmark_tabs: Loads different sources into a Neo4J database 
 - :mag: Includes a Cypher Playbook to make investigations easy


## Getting Started
---
Make sure that you have evtx_dump binary in src folder

## Help

```
usage: sabonis.py [-h] [--version] [--source_artifact SOURCE_ARTIFACT] [--csv_output CSV_OUTPUT] [--csv_input CSV_INPUT] [--ne04j_url NE04J_URL]
                  [--ne04j_user NE04J_USER] [--only_first] [--ignore_local] [--stats] [--directory] [--exclusionlist EXCLUSIONLIST] [--focuslist FOCUSLIST]
                  [--timezone TIMEZONE]
                  {parse,load2neo} {pcap,proxy,evtx,freestyle}

parse forensics artifacts to CSV and load them into neo4j database

positional arguments:
  {parse,load2neo}      choose the action to perform
  {pcap,proxy,evtx,freestyle}
                        type of artifact

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --source_artifact SOURCE_ARTIFACT
                        forensic artifact file
  --csv_output CSV_OUTPUT
                        Resulting CSV ready to be loaded
  --csv_input CSV_INPUT
                        Processed CSV to be loaded into Neo4j instance
  --ne04j_url NE04J_URL
                        Ne04j database URL in bolt format
  --ne04j_user NE04J_USER
                        Ne04j database user. Pass will be prompted
  --only_first          Just parse first connections of the group source_IP, user, dest_IP
  --ignore_local        Just include remote logins
  --stats               Display stats of processed evidence
  --directory           Parses a whole winevt/Logs directory and merges results
  --exclusionlist EXCLUSIONLIST
                        Excludes all the evidence logs or packets that contain strings included in this wordlist
  --focuslist FOCUSLIST
                        Parser will ONLY process the evidence logs or packets that contain strings included in this wordlist
  --timezone TIMEZONE   All dates with be converted to specified timezone. Ex: Europe/Leon

```

## Examples
---
### Parsing

   * Parse all EVTX files before processing with Sabonis*

    ./pivotfoot.sh source_folder_with_evtx destination_folder



#### Command Examples

   * Process all evtx files in a directory*

    ./sabonis.py parse evtx --source artifact folder_with_evtx_files --directory --csv_output sabonis_output.csv --ignore_local



### Acknowledgements
 - [EVTX parser](https://github.com/omerbenamram/evtx) library by [@OBenamram](https://twitter.com/obenamram?lang=en)

