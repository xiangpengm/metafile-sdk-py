import os
from enum import Enum

from bitsv.network.meta import Unspent
from sqlalchemy import Column, String, create_engine, BigInteger, TIMESTAMP, func, text, Integer, BLOB, Boolean
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base


class EnumMetaFileTask(str, Enum):
    # 正在进行上传任务
    doing = 'doing'
    # 上传任务成功
    success = 'success'


Base = declarative_base()


class ModelBase(object):
    id = Column(Integer, primary_key=True, autoincrement=True)

    def __repr__(self):
        return f'<{self.__class__.__name__} {self.id}>'


class MetaFileTask(Base, ModelBase):

    __tablename__ = 'meta_file_task'
    #
    size = Column(Integer, nullable=False)
    #
    md5 = Column(String(32), nullable=False, unique=True)
    #
    sha256 = Column(String(64), nullable=False, unique=True)
    #
    status = Column(String(64), nullable=False)
    #
    file_id = Column(String(64), nullable=False, unique=True)
    #
    chunk_size = Column(Integer, nullable=False)
    #
    data_type = Column(String(100), nullable=False)
    #
    chunks = Column(Integer, nullable=False)


class MetaFileTaskChunk(Base, ModelBase):
    # 设置表名
    __tablename__ = 'meta_file_task_chunk'
    # 关联的任务记录id
    file_id = Column(String(64), nullable=False)
    # 文件片的下标, 0 代表索引文件或者 未分片文件
    chunk_index = Column(Integer, nullable=False)
    # 分片的md值
    chunk_md5 = Column(String(32), nullable=False)
    # 分片的sha256值
    chunk_sha256 = Column(String(64), nullable=False, unique=True)
    # 上传任务分片状态
    status = Column(String(100), nullable=False)
    # 广播交易的id
    txid = Column(String(64))
    # 用户找零额度
    chunk_binary = Column(BLOB, nullable=False)
    # 存储分片原始数据的长度
    chunk_binary_length = Column(Integer, nullable=False)
    # 预计交易大小
    estimate_tx_size = Column(Integer, nullable=False)
    #
    unspents_txid = Column(String(64))
    #
    unspents_index = Column(Integer)
    #
    unspents_satoshi = Column(Integer)
    #
    is_sync_metafile = Column(Boolean)
    #
    service_fee = Column(Integer)

    def get_unspents(self):
        if self.unspents_txid and self.unspents_satoshi:
            u = Unspent(self.unspents_satoshi, 0, self.unspents_txid, self.unspents_index)
            return [u]

def get_session_by_metaid(cache_dir, metaid):
    full_db_path = os.path.join(cache_dir, f'.metafile_sdk_cache_{metaid}.db')
    engine = create_engine(f'sqlite:///{full_db_path}')
    Session = sessionmaker(bind=engine)
    return Session()


