<div align="center">
 <p>
  <h1>
   Sabonis, a Digital Forensics and Incident Response pivoting tool
  </h1>
 </p>
<img style="padding:0;vertical-align:bottom;" height="76" width="300" src="sabonis.png"/>
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
You can find pre-compiled versions of chainsaw in the releases section of this Github repo, or you can clone the repo (and the submodules) by running:
 `git clone --recurse-submodules https://github.com/countercept/chainsaw.git`

You can then compile the code yourself by running:  `cargo build --release`. Once the build has finished, you will find a copy of the compiled binary in the target/release folder.

**Make sure to build with the `--release` flag as this will ensure significantly faster execution time.**

If you want to quickly see what Chainsaw looks like when it runs, you can use the command:
```
./chainsaw hunt evtx_attack_samples/ --rules sigma_rules/ --mapping mapping_files/sigma-mapping.yml
```

## Supporting Additional Event IDs (via Mapping Files)
When using Sigma rule detection logic, Chainsaw requires a 'mapping file' to tell it which event IDs to check, what fields are important, and which fields to output in the table view. The included sigma mapping in the "mapping_files" directory already supports most of the key Event IDs, but if you want to add support for additional event IDs you can use this mapping file as a template.

## Examples
---
### Searching

#### Command Examples

   *Search all .evtx files in the evtx_files dir for event id 4624*

    ./chainsaw search ~/Downloads/evtx_files/ -e 4624

   *Search a specific evtx log for logon events containing the string "bob" (case insensitive)*

    ./chainsaw search ~/Downloads/evtx_files/security.evtx -e 4624 -s "bob" -i

   *Search a specific evtx log for logon events, with a matching regex pattern, output in JSON format*

     ./chainsaw search ~/Downloads/evtx_files/security.evtx -e 4624 -r "bob[a-zA-Z]" --json



### Acknowledgements
 - [EVTX parser](https://github.com/omerbenamram/evtx) library by [@OBenamram](https://twitter.com/obenamram?lang=en)

