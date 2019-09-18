import pyshark
import pandas as pd
import LoadPcap
import re
import error


def trans_pcap_to_dict(x):
    ans = {'time': x.sniff_timestamp}
    for i in x.layers:
        highest_layer = None
        if i.layer_name == 'eth':
            highest_layer = 'eth'
            fields = ['eth.src', 'eth.dst', 'eth.type']
        elif i.layer_name == 'ip':
            highest_layer = 'ip'
            fields = ['ip.src', 'ip.dst', 'ip.flags', 'ip.len', 'ip.ttl', 'ip.proto', 'ip.id', 'ip.dsfield',
                      'ip.checksum', 'ip.version']
        elif i.layer_name == 'tcp':
            highest_layer = 'tcp'
            fields = ['tcp.srcport', 'tcp.dstport', 'tcp.stream', 'tcp.len', 'tcp.seq', 'tcp.nxtseq', 'tcp.ack',
                      'tcp.hdr_len', 'tcp.flags', 'tcp.window_size', 'tcp.checksum', 'tcp.checksum.status',
                      'tcp.urgent_pointer', 'tcp.time_relative', 'tcp.time_delta']
            if 'options' in i.field_names:
                ans['tcp.options'] = i.options
        elif i.layer_name == 'udp':
            highest_layer = 'udp'
            fields = ['udp.srcport', 'udp.dstport', 'udp.length', 'udp.checksum', 'udp.checksum.status', 'udp.stream',
                      'udp.time_relative', 'udp.time_delta']
        elif i.layer_name == 'data':
            if 'data' in i.field_names:
                fields = ['data', 'data.len']
            elif 'tcp_segments' in i.field_names:
                fields = ['tcp.segments', 'tcp.segment.count', 'tcp.reassembled.length']
            else:
                raise error.LayerNotDoneException
        else:
            partten = re.compile('flags?\.')
            highest_layer = i.layer_name
            fields = [k for k in i._all_fields.keys() if not partten.search(k) and k != '']
        if highest_layer:
            ans['highest_layer'] = highest_layer
        ans.update({k: i._all_fields[k] for k in fields})
    return ans


if __name__ == "__main__":
    file_path = "F:/jiangxi2019/20190813/20190813/20190813083546_218.30.103.58_10.20.173.84.pcap"
    # filt_list = LoadPcap.get_file_list(file_path)
    # for i in filt_list[2:5]:
    #     pcap = pyshark.FileCapture(i, keep_packets=False)
    #     for pkt in pcap:
    #         trans_pcap_to_dict(pkt)
    #     pcap.close()
    pcap = pyshark.FileCapture(file_path, keep_packets=False)
    t = []
    for pkt in pcap:
        try:
            t.append(trans_pcap_to_dict(pkt))
        except error.LayerNotDoneException as e:
            print(e)
            exit(-1)
    df = pd.DataFrame(t)
    print(df)
