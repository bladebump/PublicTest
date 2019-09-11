import pandas
import elsearchObj


def DataFreamToEs(df: pandas.DataFrame, index_ex_obj: elsearchObj.IndexElsearchObj):
    """
    将dataframe批量存储到elsearch数据库中
    :param df: 要存储的dataframe
    :param index_ex_obj: 要存储到的位置
    :return:
    """
    index_ex_obj.saveBulk(df.apply(lambda x: x.to_dict(), axis=1).to_list())


def EsToDataFream(index_ex_obj: elsearchObj.IndexElsearchObj):
    """
    从el对象中读取全部数据
    :param index_ex_obj:要读取的el对象
    :return:
    """
    return pandas.DataFrame(index_ex_obj.getAllWithOutId())
