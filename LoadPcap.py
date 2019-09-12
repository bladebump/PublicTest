from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.snmp import SNMP
from scapy.packet import Raw, Padding
from scapy.all import rdpcap
from elsearchObj import IndexElsearchObj
import os
import configparser
import gc
import time
import logging

error_code = {
    'success': 0,
    'load_error': 1,
    'save_error': 2
}


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
            ans.update(get_http_feilds(x[i].name, t))
        elif i is SNMP:
            ans.update(get_SNMP_fields(t))
        elif i is Raw:
            ans.update(get_Raw_fields(t))
        elif i is Padding:
            ans.update(get_Padding_fields(t))
        else:
            ans.update(dict(zip([x[i].name + '_' + j for j in t.keys()],
                                [str(i) if not (isinstance(i, int) or isinstance(i, float)) else i for i in
                                 t.values()])))
    return ans


def get_Raw_fields(t) -> dict:
    """
    读取Raw层的内容
    :param t: t是Raw层的字典内容
    :return: 一个字典
    """
    ans = {'Raw_load': t['load'].hex()}
    return ans


def get_Padding_fields(t) -> dict:
    """
    读取Padding层的内容
    :param t: Padding层内容的字典
    :return: 一个字典
    """
    ans = {'Padding_load': t['load'].hex()}
    return ans


def get_SNMP_fields(t) -> dict:
    """
    读取SNMP层的内容
    :param t: SNMP内容的字典
    :return: 一个字典
    """
    ans = dict()
    ans['SNMP_version'] = t['version'].val
    ans['SNMP_community'] = t['community'].val.decode()
    ans['SNMP_PDU'] = t['PDU'].original.hex()
    return ans


def get_http_feilds(name, x: dict) -> dict:
    """
    处理http层的内容
    :param name: 层级名称
    :param x: 内容
    :return: 字典
    """
    ans = {}
    for (j, k) in x.items():
        if isinstance(k, dict):
            ans.update(get_http_feilds(name, k))
        else:
            if isinstance(j, bytes):
                j = j.decode()
            key = name + '_' + j
            try:
                ans[key] = k.decode()
            except Exception as e:
                ans[key] = k.hex()
    return ans


def load_pcap(file):
    """
    加载一个pcap包
    :param file:pcap包的路径
    :return: 一个报文构成的列表
    """
    pcap = rdpcap(file)
    pcap_list = []
    for i in pcap:
        pcap_list.append(trans_pcap_to_dict(i))
    return pcap_list


def get_file_list(file_path):
    """
    取得一个目录下的所有文件，并构成绝对路径
    :param file_path: 文件夹目录
    :return: 一个绝对路径的列表
    """
    file_list = os.listdir(file_path)
    file_list = list(map(lambda x: file_path + x, file_list))
    return file_list


def read_error():
    """
    上次读取错误后，避免重复读取数据写的逻辑
    :return:
    """
    if not os.path.exists('error'):
        return 0, 0, 0
    else:
        with open('error', 'r') as f:
            lines = f.readlines()
            code, i, j, k = tuple(map(lambda x: int(x.split('=')[-1].strip()), lines))
            if code == error_code['load_error']:
                return j, i, k
            elif code == error_code['save_error']:
                return i, j, k


def load_error(i, j):
    """
    加载数据包出错，记录报错的位置到文件
    :param i: 第几个数据包
    :param j: 辅助记录
    :return:
    """
    with open('error', 'w') as f:
        f.write('error_code=%d\n' % error_code['load_error'])
        f.write("i=%d\nj=%d\nk=%d" % (i, j, 0))
    logging.basicConfig(filename='log', format='%(asctime)s,\t%(levelname)s,\t%(message)s')
    logging.error("load pcap error!!!watch error file!!!")
    exit(0)


def save_error(i, j, k):
    """
    保存数据到数据库报错，记录报错的位置到文件
    :param i: 完成的的数据包
    :param j: 辅助记录
    :param k: 报错的报文位置
    :return:
    """
    with open('error', 'w') as f:
        f.write('error_code=%d\n' % error_code['save_error'])
        f.write("i=%d\nj=%d\nk=%d" % (i, j, k))
    logging.basicConfig(filename='log', format='%(asctime)s,\t%(levelname)s,\t%(message)s')
    logging.error("save data error!!!watch error file!!!")
    exit(0)


def load_dir(file_path, index_name, index_type):
    """
    加载一个文件夹的数据包到数据库
    :param file_path: 文件夹目录
    :param index_name: index的名称
    :param index_type: index的类型
    :return:
    """
    configfile = 'config'
    config_obj = configparser.ConfigParser()
    config_obj.read(configfile)
    file_size = int(config_obj.get('load_setting', 'file_size'))
    save_size = int(config_obj.get('load_setting', 'save_size'))
    elobj = IndexElsearchObj(index_name=index_name, index_type=index_type)
    file_list = get_file_list(file_path)
    i, j, k = read_error()
    for i in range(i, len(file_list[:5000]), file_size):
        t = []
        gc.collect()
        for j in range(i, i + file_size):
            try:
                t.extend(load_pcap(file_list[j]))
            except Exception:
                load_error(i, j)
        if k != 0:
            for k in range(k, len(t), save_size):
                elobj.saveBulk(t)
            continue
        for k in range(0, len(t), save_size):
            try:
                elobj.saveBulk(t)
            except Exception:
                save_error(i, j, k)
        k = 0
        time.sleep(10)
    if os.path.exists('error'):
        os.remove('error')
