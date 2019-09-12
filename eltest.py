import elsearchObj
import json
import pandas
from DateFrameToEs import DataFreamToEs, EsToDataFream
import numpy as np

ip = "192.168.184.128"
port = 9200

if __name__ == "__main__":
    index_name = 'pcap'
    index_type = 'pcap_file'
    elobj = elsearchObj.IndexElsearchObj(index_name=index_name, index_type=index_type)
    elobj.delete_index(index_name)
    # df = EsToDataFream(elobj)
    # print(df.shape)
