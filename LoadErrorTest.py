import elsearchObj
import LoadPcap

if __name__ == "__main__":
    # index_name = 'pcap_2'
    # index_type = 'pcap_file'
    # elobj = elsearchObj.IndexElsearchObj(index_name=index_name, index_type=index_type)
    file_path = "F:/jiangxi2019/20190813/20190813/20190813083723_180.163.25.38_10.20.173.83.pcap"
    t = LoadPcap.load_pcap(file_path)
    print(t)
