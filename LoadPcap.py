from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.snmp import SNMP
from scapy.packet import Raw, Padding
from scapy.all import rdpcap


def trans_pcap_to_dict(x):
    """
    读取一个pcap包
    :param x:pcap包
    :return: 返回一个字典
    """
    layers = x.layers()
    if layers[-1] is SNMP:
        last_layer = 'SNMP'
    else:
        pcap_layers = list(map(lambda x: x._name, layers))
        last_layer = pcap_layers[-1] if pcap_layers[-1] not in ['Raw', 'Padding'] else pcap_layers[-2]
    ans = {'time': x.time, 'type': last_layer}
    for i in layers:
        t = x[i].fields
        if i in [HTTPRequest, HTTPResponse]:
            ans.update(get_http_feilds(i, t, x))
        elif i is SNMP:
            ans.update(get_SNMP_fields(t))
        elif i is Raw:
            ans.update(get_Raw_fields(i, t))
        elif i is Padding:
            ans.update(get_Padding_fields(i, t))
        else:
            ans.update(dict(zip([x[i].name + '_' + j for j in t.keys()],
                                [str(i) if not (isinstance(i, int) or isinstance(i, float)) else i for i in
                                 t.values()])))
    return ans


def get_Raw_fields(i, t):
    ans = {'Raw_load':t['load'].hex()}
    return ans


def get_Padding_fields(i, t):
    ans = {'Padding_load':t['load'].hex()}
    return ans


def get_SNMP_fields(t):
    ans = dict()
    ans['SNMP_version'] = t['version'].tag._value
    ans['SNMP_community'] = t['community'].tag._value
    ans['SNMP_PDU'] = t['PDU'].original.hex()
    return ans


def get_http_feilds(i, t, x):
    ans = dict()
    for (j, k) in t.items():
        if j == 'Unknown_Headers':
            for (j1, k1) in k.items():
                key = x[i].name + '_' + j1.decode()
                try:
                    ans[key] = k1.decode()
                except Exception as e:
                    ans[key] = k1.hex()
        else:
            key = x[i].name + '_' + j
            try:
                ans[key] = k.decode()
            except Exception as e:
                ans[key] = k.hex()
    return ans


def load_pcap(file):
    pcap = rdpcap(file)
    pcap_list = []
    for i in pcap:
        pcap_list.append(trans_pcap_to_dict(i))
    return pcap_list
