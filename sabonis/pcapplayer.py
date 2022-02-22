import pandas
import getpass
from py2neo import Graph, Node, Relationship
import webbrowser
from scapy.all import *
import numpy as np

class PcapParser:
    def __init__(self,source_artifact,only_first="False",stats="False",exclusionlist=None,focuslist=None):
        self.source_artifact=source_artifact
        self.only_first=only_first
        self.stats=stats
        self.exclusionlist=exclusionlist
        self.focuslist=focuslist


    def read(self):
        
        column_names=["time","proto","source_ip","dest_ip","dest_port"]
        protocols={
            0:'HOPOPT',
            1:'ICMP',
            2:'IGMP',
            3:'GGP',
            4:'IPv4',
            5:'ST',
            6:'TCP',
            7:'CBT',
            8:'EGP',
            9:'IGP',
            10:'BBN-RCC-MON',
            11:'NVP-II',
            12:'PUP',
            13:'ARGUS (deprecated)',
            14:'EMCON',
            15:'XNET',
            16:'CHAOS',
            17:'UDP',
            18:'MUX',
            19:'DCN-MEAS',
            20:'HMP',
            21:'PRM',
            22:'XNS-IDP',
            23:'TRUNK-1',
            24:'TRUNK-2',
            25:'LEAF-1',
            26:'LEAF-2',
            27:'RDP',
            28:'IRTP',
            29:'ISO-TP4',
            30:'NETBLT',
            31:'MFE-NSP',
            32:'MERIT-INP',
            33:'DCCP',
            34:'3PC',
            35:'IDPR',
            36:'XTP',
            37:'DDP',
            38:'IDPR-CMTP',
            39:'TP++',
            40:'IL',
            41:'IPv6',
            42:'SDRP',
            43:'IPv6-Route',
            44:'IPv6-Frag',
            45:'IDRP',
            46:'RSVP',
            47:'GRE',
            48:'DSR',
            49:'BNA',
            50:'ESP',
            51:'AH',
            52:'I-NLSP',
            53:'SWIPE (deprecated)',
            54:'NARP',
            55:'MOBILE',
            56:'TLSP',
            57:'SKIP',
            58:'IPv6-ICMP',
            59:'IPv6-NoNxt',
            60:'IPv6-Opts',
            61:'',
            62:'CFTP',
            63:'',
            64:'SAT-EXPAK',
            65:'KRYPTOLAN',
            66:'RVD',
            67:'IPPC',
            68:'',
            69:'SAT-MON',
            70:'VISA',
            71:'IPCV',
            72:'CPNX',
            73:'CPHB',
            74:'WSN',
            75:'PVP',
            76:'BR-SAT-MON',
            77:'SUN-ND',
            78:'WB-MON',
            79:'WB-EXPAK',
            80:'ISO-IP',
            81:'VMTP',
            82:'SECURE-VMTP',
            83:'VINES',
            84:'TTP',
            84:'IPTM',
            85:'NSFNET-IGP',
            86:'DGP',
            87:'TCF',
            88:'EIGRP',
            89:'OSPFIGP',
            90:'Sprite-RPC',
            91:'LARP',
            92:'MTP',
            93:'AX.25',
            94:'IPIP',
            95:'MICP (deprecated)',
            96:'SCC-SP',
            97:'ETHERIP',
            98:'ENCAP',
            99:'',
            100:'GMTP',
            101:'IFMP',
            102:'PNNI',
            103:'PIM',
            104:'ARIS',
            105:'SCPS',
            106:'QNX',
            107:'A/N',
            108:'IPComp',
            109:'SNP',
            110:'Compaq-Peer',
            111:'IPX-in-IP',
            112:'VRRP',
            113:'PGM',
            114:'',
            115:'L2TP',
            116:'DDX',
            117:'IATP',
            118:'STP',
            119:'SRP',
            120:'UTI',
            121:'SMP',
            122:'SM (deprecated)',
            123:'PTP',
            124:'ISIS over IPv4',
            125:'FIRE',
            126:'CRTP',
            127:'CRUDP',
            128:'SSCOPMCE',
            129:'IPLT',
            130:'SPS',
            131:'PIPE',
            132:'SCTP',
            133:'FC',
            134:'RSVP-E2E-IGNORE',
            135:'Mobility Header',
            136:'UDPLite',
            137:'MPLS-in-IP',
            138:'manet',
            139:'HIP',
            140:'Shim6',
            141:'WESP',
            142:'ROHC',
            143:'Ethernet'
        }

        conjunto=[]
        for p in PcapReader(self.source_artifact):
            protocol=protocols[p[IP].fields['proto']]
            try:
                time=p.time
            except AttributeError:
                time=''
            try:    
                source_ip=p[IP].src
            except AttributeError:
                source_ip=''
            try:
                dest_ip=p[IP].dst
            except AttributeError:
                dest_ip=''
            try:
                dest_port=p[IP].dport
            except AttributeError:
                dest_port=''
            conjunto.append((time,protocol,source_ip,dest_ip,dest_port))


        df = pandas.DataFrame(conjunto,columns=column_names)
        df["time"]=df["time"].astype('int').astype("datetime64[s]")
        df['dest_port'].replace('', np.nan, inplace=True)
        df.dropna(subset=['dest_port'], inplace=True)

        if self.focuslist:
            with open(self.focuslist) as f:
                focus_words= f.read().splitlines()
            df1=df.append(df[df["source_ip"].str.contains('|'.join(focus_words))], ignore_index=True)
            df1=df1.append(df[df["dest_ip"].str.contains('|'.join(focus_words))], ignore_index=True)
            df=df1

        if self.exclusionlist:
            with open(self.exclusionlist) as f:
                exclude_words= f.read().splitlines()
            df=df[~df["source_ip"].str.contains('|'.join(exclude_words))]
            df=df[~df["dest_ip"].str.contains('|'.join(exclude_words))]

        if self.only_first:
            df=df.sort_values('time').groupby(["source_ip","dest_ip","dest_port"],as_index=False).nth(0)
        
        if self.stats:
            print(f"SABONIS: Global statistics of {self.source_artifact}:")
            print()
            print(df.describe(include='all',datetime_is_numeric=True))
            print()
            print("Top 50 source IPs:")
            top50domains=df['source_ip'].value_counts().nlargest(50)
            with open("pcaptop50sourceIPs.csv",'a') as file1:
                for domain in top50domains.index:
                    file1.write(domain+ '\n')
            print(top50domains)
            print()
            print("Top 50 destination IPs:")
            top50destips=df['dest_ip'].value_counts().nlargest(50)
            with open("pcaptop50destIPs.csv",'a') as file1:
                for ip in top50destips.index:
                    file1.write(ip+ '\n')
            print(top50destips)
            print()
        self.df=df

    def write(self,filepath):
        self.df.to_csv(filepath, index = False, header=True)
        print(f"SABONIS: PCAP evidence has been processed succesfully and writen to {filepath}")


class PcapLoader:
    def __init__(self,csv_input,ne04j_url,ne04j_user):
        self.csv_input=csv_input
        self.ne04j_url=ne04j_url
        self.ne04j_user=ne04j_user
        self.graph = Graph(ne04j_url, user=ne04j_user, password=getpass.getpass("Enter ne04j database password: "))

    def load(self):
        transaction = self.graph.begin()
        df = pandas.read_csv(self.csv_input)
        for index, row in df.iterrows():



            transaction.evaluate(f'''
            MERGE (origin:host{{name:'{row['source_ip']}'}})
            MERGE (destination:host{{name:'{row['dest_ip']}'}})
            MERGE (origin)-[r:{row['proto']+str(int(row['dest_port']))}{{time:datetime("{row['time'].replace(' ','T')}"), port:{int(row['dest_port'])}, protocol:'{row['proto']}'}}]->(destination)
            ''')
        transaction.commit()
        answer=input (f"SABONIS: Data from {self.csv_input} has been correctly loaded. Press Y if you want to open it:")
        if answer=='Y':
            webbrowser.open(self.ne04j_url.replace("bolt", "http").replace("7687", "7474"), new=2)