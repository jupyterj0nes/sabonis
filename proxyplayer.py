import pandas
import tldextract
import getpass
#from py2neo import Graph, Node, Relationship
import webbrowser

def getmegs(bytes):
    return format(bytes/1024/1024/1024, ".5f")+ "GB"

class ProxyParser:
    def __init__(self,source_artifact,only_first="False",stats="False",exclusionlist=None,focuslist=None):
        self.source_artifact=source_artifact
        self.only_first=only_first
        self.stats=stats
        self.exclusionlist=exclusionlist
        self.focuslist=focuslist




    def read(self):
        good_words = ['ORIGINAL_DST','DIRECT']
        column_names=["time","duration","source_ip","resultcode","bytes","method","domain","user","dest_ip","type"]

        with open(self.source_artifact) as oldfile, open('access_temp.log', 'w') as newfile:
            for line in oldfile:
                if any(good_word in line for good_word in good_words) and not("]" in line):
                    newfile.write(line)
        
        df = pandas.read_csv('access_temp.log', header=None,names=column_names,delimiter=r"\s+")
        
        

        # convert unix timestamp to datetime UTC
        df["time"]=df["time"].astype('int').astype("datetime64[s]")
        # convert timezone from UTC to GMT+7
        df["time"] = df["time"].dt.tz_localize('UTC')
        df["time"] = df["time"].dt.tz_convert('Asia/Kolkata')
        df["dest_ip"]=df["dest_ip"].str.split('/').str[1]
        df["domain"]=df['domain'].apply(lambda url: tldextract.extract(url).domain +'.'+tldextract.extract(url).suffix)


        if self.focuslist:
            with open(self.focuslist) as f:
                focus_words= f.read().splitlines()
            df1=df[df["domain"].str.contains('|'.join(focus_words))]
            df1=df1.append(df[df["source_ip"].str.contains('|'.join(focus_words))], ignore_index=True)
            df1=df1.append(df[df["user"].str.contains('|'.join(focus_words))], ignore_index=True)
            df1=df1.append(df[df["dest_ip"].str.contains('|'.join(focus_words))], ignore_index=True)
            df=df1

        if self.exclusionlist:
            with open(self.exclusionlist) as f:
                exclude_words= f.read().splitlines()
            df=df[~df["domain"].str.contains('|'.join(exclude_words))]
            df=df[~df["source_ip"].str.contains('|'.join(exclude_words))]
            df=df[~df["user"].str.contains('|'.join(exclude_words))]
            df=df[~df["dest_ip"].str.contains('|'.join(exclude_words))]

        if self.only_first:
            df=df.sort_values('time').groupby(["source_ip","user","dest_ip"],as_index=False).nth(0)
        
        if self.stats:
            #pandas.set_option('display.max_columns', 15)
            print(f"SABONIS: Global statistics of {self.source_artifact}:")
            print()
            print(df.describe(include='all',datetime_is_numeric=True))
            print()
            print("Top 50 domains:")
            top50domains=df['domain'].value_counts().nlargest(50)
            with open("proxytop50domains.csv",'a') as file1:
                for domain in top50domains.index:
                    file1.write(domain+ '\n')
            print(top50domains)
            print()
            print("Top 50 destination IPs:")
            top50destips=df['dest_ip'].value_counts().nlargest(50)
            with open("proxytop50destips.csv",'a') as file1:
                for ip in top50destips.index:
                    file1.write(ip+ '\n')
            print(top50destips)
            print()
            
            pandas.set_option('display.max_rows', 25)
            dff = df.groupby(["source_ip","dest_ip"]).bytes.sum().reset_index()
            dff = dff.sort_values('bytes', ascending = False, ignore_index=True)
            print("SABONIS - EXFIL RANKER TOP TRAFFIC FLOWS are:")
            dff['bytes'] = dff['bytes'].apply(getmegs)
            print(dff)
            print()

            pandas.set_option('display.max_rows', 25)
            dff=df[df["method"].str.contains("GET")]
            dff = dff.groupby(["source_ip"]).bytes.sum().reset_index()
            dff = dff.sort_values('bytes', ascending = False, ignore_index=True)
            print("SABONIS - EXFIL RANKER TOP SENDERS are:")
            dff['bytes'] = dff['bytes'].apply(getmegs)
            print(dff)
            print()

            pandas.set_option('display.max_rows', 25)
            dff=df[df["method"].str.contains("POST")]
            dff = dff.groupby(["dest_ip"]).bytes.sum().reset_index()
            dff = dff.sort_values('bytes', ascending = False, ignore_index=True)
            print("SABONIS - EXFIL RANKER TOP RECEIVERS are:")
            dff['bytes'] = dff['bytes'].apply(getmegs)
            print(dff)
            print()

        df=df.sort_values('time')
        self.df=df

    def write(self,filepath):
        self.df.to_csv(filepath, index = False, header=True)
        print(f"SABONIS: Proxy evidence has been processed succesfully and writen to {filepath}")


class ProxyLoader:
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
            MERGE (origin:internal:host{{name:'{row['source_ip']}'}})
            MERGE (destination:external:host{{name:'{row['dest_ip']}'}})
            MERGE (origin)-[r:`{row['domain'].replace('.','_').replace('-','_')}`{{time:datetime("{row['time'].replace(' ','T')}"), user:'{row['user']}', result:'{row['resultcode']}', domain:'{row['domain']}' }}]->(destination)
            ''')
        transaction.commit()
        answer=input (f"SABONIS: Data from {self.csv_input} has been correctly loaded. Press Y if you want to open it:")
        if answer=='Y':
            webbrowser.open(self.ne04j_url.replace("bolt", "http").replace("7687", "7474"), new=2)