import elsearchObj
import json
import pandas
from DateFrameToEs import DataFreamToEs, EsToDataFream
import numpy as np
import LoadPcap

ip = "192.168.184.128"
port = 9200

if __name__ == "__main__":
    index_name = 'pcap'
    index_type = 'pcap_file'
    elobj = elsearchObj.IndexElsearchObj(index_name=index_name, index_type=index_type)
    # elobj.delete_index(index_name)
    # file_path = 'F:/jiangxi2019/20190813/20190813/20190813083534_10.20.173.1_10.20.173.84.pcap'
    # t = LoadPcap.load_pcap(file_path)
    # a = t[0]
    df = EsToDataFream(elobj)
    print(df)
