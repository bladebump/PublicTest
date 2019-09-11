import elasticsearch
import configparser
import json

size = 1000


class IndexElsearchObj:
    def __init__(self, index_name: str, index_type: str):
        """
        创建一个es对象
        :param index_name: index的名称
        :param index_type: index的类型
        """
        configfile = 'config'
        config_obj = configparser.ConfigParser()
        config_obj.read(configfile)
        ip = config_obj.get('db', 'ip')
        port = int(config_obj.get('db', 'port'))
        mapping = json.loads(config_obj.get('db', 'mapping'))
        self.es = elasticsearch.Elasticsearch(hosts=ip, port=port)
        self.index_name = index_name
        self.index_type = index_type
        if self.es.indices.exists(index=self.index_name) is not True:
            self.es.index(index=index_name, doc_type=index_type, body=mapping)

    def saveItem(self, id: str, item: dict) -> bool:
        """
        保存一个对象到es数据库中
        :param id: 对象的id
        :param item: 对象的数据
        :return: 返回是否保存成功
        """
        res = self.es.create(index=self.index_name, doc_type=self.index_type, id=id, body=item, ignore=[409])
        if res.get('error'):
            return False
        else:
            return True

    def deleteItem(self, id: str) -> bool:
        """
        删除一个对象
        :param id: 对象的id
        :return: 是否删除成功
        """
        res = self.es.delete(index=self.index_name, doc_type=self.index_type, id=id, ignore=[404])
        if res.get('result') == 'not_found':
            return False
        else:
            return True

    def searchItemById(self, id: str) -> dict:
        """
        通过id查询一个对象
        :param id: 对象的id
        :return: 查询到的对象
        """
        res = self.es.get(index=self.index_name, id=id, doc_type=self.index_type)
        return res['_source']

    def getAll(self, _source: list = None) -> list:
        """
        取得这个index下保存的所有的对象
        :param size: 返回的数据量，默认为全部
        :param _source: 一个列表，用于指定返回的对象有哪些属性,默认为空
        :return: 对象的列表，加上id
        """
        items = self.getIndex()
        ans = []
        for item in items:
            item['_source']['id'] = item['_id']
            ans.append(item['_source'])
        return ans

    def getIndexCount(self) -> int:
        """
        取得这个index下的记录条数
        :return: 记录的总条数
        """
        res = self.es.indices.stats(self.index_name)
        return res['_all']['primaries']['docs']['count']

    def getIndex(self) -> list:
        """
        取得这个index下的所有的记录
        :return: 一个包含所有记录的列表
        """
        res = self.es.search(index=self.index_name, size=size, scroll='10m')
        scroll_id = res['_scroll_id']
        total = res['hits']['total']['value']
        items = list(map(lambda x: x['_source'], res['hits']['hits'][1:]))
        for i in range(int(total / size + 0.5)):
            res = self.es.scroll(scroll_id=scroll_id, scroll='10m')
            items.extend(list(map(lambda x: x['_source'], res['hits']['hits'])))
        return items

    def delete_index(self, index_name):
        """
        删除一整个索引
        :param index_name: 索引的名称
        :return:
        """
        if self.es.indices.exists(index=self.index_name):
            self.es.indices.delete(index_name)

    def getAllWithOutId(self, _source: list = None) -> list:
        """
        取得这个index下保存的所有的对象
        :param size: 返回的数据量，默认为全部
        :param _source: 一个列表，用于指定返回的对象有哪些属性,默认为空
        :return: 对象的列表，没有id
        """
        items = self.getIndex()
        ans = []
        for item in items:
            ans.append(item['_source'])
        return ans

    def searchItemByDSL(self, dsl: dict, _source=None) -> list:
        """
        用quarry查询记录
        :param dsl: 字典结构
        :param _source: 要查询的列
        :return: 对象的列表，加上id
        """
        res = self.es.search(index=self.index_name, body=dsl, _source=_source)
        ans = []
        for item in res['hits']['hits']:
            item['_source']['id'] = item['_id']
            ans.append(item['_source'])
        return ans

    def saveBulk(self, items: list) -> bool:
        """
        批量保存数据，但是数据不宜过大
        :param items: 数据列表
        :return:
        """
        Action = []
        for item in items:
            action = {
                "index": {
                    "_index": self.index_name
                }
            }
            Action.append(action)
            Action.append(item)
        res = self.es.bulk(Action, doc_type=self.index_type, index=self.index_name)
        if not res.get('errors'):
            return True
        else:
            return False
