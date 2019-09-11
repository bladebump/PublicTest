import LoadPcap
import pandas as pd
import os
import elsearchObj
import time
import gc

if __name__ == "__main__":
    index_name = 'pcap'
    index_type = 'pcap_file'
    elobj = elsearchObj.IndexElsearchObj(index_name=index_name, index_type=index_type)
    file_dir = "F:/jiangxi2019/20190813/20190813/"
    file_list = os.listdir(file_dir)
    file_list = list(map(lambda x: file_dir + x, file_list))
    j = 0
    i = ''
    k = 0
    t = []
    try:
        for j in range(0, 2000, 100):
            t = []
            for i in file_list[j:j + 100]:
                t.extend(LoadPcap.load_pcap(i))
            for k in range(0, len(t), 1000):
                elobj.saveBulk(t[k:k + 1000])
            time.sleep(10)
            gc.collect()
    except Exception as e:
        print(i)
        print(t[k])
        print(e)
