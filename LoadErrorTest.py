import os
import elsearchObj
import time
import gc
import LoadPcap

if __name__ == "__main__":
    index_name = 'pcap_2'
    index_type = 'pcap_file'
    elobj = elsearchObj.IndexElsearchObj(index_name=index_name, index_type=index_type)
    file_dir = "F:/jiangxi2019/20190813/20190813/"
    file_list = os.listdir(file_dir)
    file_list = list(map(lambda x: file_dir + x, file_list))
    index = file_list.index('F:/jiangxi2019/20190813/20190813/20190813084802_10.20.173.21_203.208.41.40.pcap')
    print(index)
    t = []
    for j in range(index, index+1):
        t.extend(LoadPcap.load_pcap(file_list[j]))
    # elobj.saveBulk(t)
