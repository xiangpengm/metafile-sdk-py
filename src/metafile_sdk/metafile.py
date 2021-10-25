import math
import os
from typing import List

from bitsv import PrivateKey
from bitsv.network.fees import DEFAULT_FEE_SLOW
from sqlalchemy.orm import Session

from metafile_sdk.api import ShowmandbApi, WocApi, MetafileApi
from metafile_sdk.api.metafile import FilesRequest, ChunksRequest
from metafile_sdk.model.base import get_session_by_metaid, MetaFileTask, MetaFileTaskChunk, EnumMetaFileTask
from metafile_sdk.orm import MetaFileTaskOrm, MetaFileTaskChunkOrm
from metafile_sdk.utils import log, file_data_type
from metafile_sdk.transaction import Transaction, EnumScriptType
from metafile_sdk.hash_func import md5_file, sha256_file, md5_bytes, sha256_bytes


class ValueErrorMetafileProtocolNode(ValueError):
    pass


class ValueErrorPrivateKey(ValueError):
    pass


class MetaFileType():
    # 分片
    chunk = 'metafile/chunk'
    # 索引
    index = 'metafile/index'


def create_meta_file_extended_data_list(
        pubkey: str, meta_file_protocol_node: str, file_name: str,
        data: bytes, data_type: str, version: str):
    data_list = [
        b'meta',
        pubkey.encode(),
        meta_file_protocol_node.encode(),
        b'metaid',
        file_name.encode(),
        data,
        b'0',
        version.encode(),
        data_type.encode(),
        b'binary'
    ]
    return data_list

def tx_chunk_size(chunk: bytes):
    size = 148 + 2 + 4 + 67 + 65 + 7 + 67 + 9 + chunk.__len__()  + 2 + 7 + 21 + 7 + 10 + 34 * 2
    return size

def per_utxo_amount(chunk_bytes, feeb, data_list, service_fee_min_satoshis, service_fee_rate):
    data_len = sum([len(data) for data in data_list])
    service_fee = max(data_len * feeb * service_fee_rate, service_fee_min_satoshis)
    return math.ceil(tx_chunk_size(chunk_bytes) * feeb) + service_fee, service_fee


class Metafile():

    def __init__(self, cache_dir: str='./',
                 showmandb_base_url= 'https://api.showmoney.app/showMANDB/api',
                 showmandb_headers=None,
                 metafile_api_base_url='https://metafile.id',
                 metafile_api_headers=None,
                 woc_api_base_url='https://api.whatsonchain.com',
                 woc_api_headers=None,
         ):
        self.showmandb_api = ShowmandbApi(showmandb_base_url, showmandb_headers)
        self.metafile_api = MetafileApi(metafile_api_base_url, metafile_api_headers)
        self.woc_api = WocApi(woc_api_base_url, woc_api_headers)
        self.cache_dir = cache_dir
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)

    def upload_metafile_from_path(self, private_key: PrivateKey, metafile_protocol_node: str, file_path: str, metaid: str=None, feeb=0.5):
        """
        0. 检查文件存在 ok
        1. 验证metaid  ok
        2. 验证metafile_protocol_node的公钥与private_key对应的公钥一致 ok
        3. 验证计算sha256 计算md5 ok
        4. 生成task ok
        5. 拆分文件到sqlite
        6. 先获取一遍服务是否有chunk
        7. 计算切分utxo
        8. 多线程上传chunk
        9. 上传完成清理缓存, 返回上传结果
        :param metafile_protocol_node:
        :param file_path:
        :param metaid:
        :return:
        """
        # 验证文件存在
        if not os.path.exists(file_path):
            raise FileExistsError(file_path)
        # 验证metaid
        log('metaid', metaid)
        if metaid is None:
            # get metaid root node from showmandb
            metaid_node = self.showmandb_api.metanet_getnode(metafile_protocol_node)
            if metaid_node.code == 200:
                metaid = metaid_node.result.rootTxId
            else:
                raise ValueErrorMetafileProtocolNode(f'{metafile_protocol_node} node must have metaid node')
        log('metaid', metaid)
        tx_hex =  self.woc_api.tx_raw_hex(metafile_protocol_node)
        tx = Transaction.from_hex(tx_hex)
        # 验证公钥
        pk_valid = False
        for tx_output in tx.outputs:
            if tx_output.script.type == EnumScriptType.safe_op_return:
                if tx_output.script.get_data().__len__() == 10:
                    node_pubkey = tx_output.script.get_data()[1].decode()
                    log('data', private_key.public_key.hex(), node_pubkey)
                    if private_key.public_key.hex() == node_pubkey:
                        pk_valid = True
        if not pk_valid:
            raise ValueErrorPrivateKey(f'private_key must protocol node public key')
        log('pk_valid', pk_valid)
        _md5 = md5_file(file_path)
        _sha256 = sha256_file(file_path)
        file_stat = os.stat(file_path)
        file_size = file_stat.st_size
        log('file_size', type(file_size))
        data_type = file_data_type(file_path)
        # 构造任务
        files_request = FilesRequest(
            name=os.path.basename(file_path),
            size=file_size,
            md5=_md5,
            sha256=_sha256,
            metaid=metaid,
            data_type=data_type,
        )
        files_resp = self.metafile_api.files(files_request)
        log('filesRequest', files_request)
        log('response', files_resp)
        # 获取到session
        session: Session = get_session_by_metaid(self.cache_dir, metaid)
        # 创建表
        MetaFileTask.metadata.create_all(session.get_bind())
        MetaFileTaskChunk.metadata.create_all(session.get_bind())
        metaFileTaskOrm = MetaFileTaskOrm(session)
        metaFileTaskChunkOrm = MetaFileTaskChunkOrm(session)
        # 获取 or 创建任务
        task = metaFileTaskOrm.get_or_create(files_resp.file_id, defaults=dict(
            size=files_request.size,
            md5=files_request.md5,
            sha256=files_request.sha256,
            status=EnumMetaFileTask.doing,
            file_id=files_resp.file_id,
            chunk_size=files_resp.chunk_size,
            data_type=files_request.data_type,
            chunks=files_resp.chunks
        ))
        log("task", task)
        # 创建记录
        file_handler = open(file_path, 'rb')
        recv_list = []
        info = self.metafile_api.info()
        for i in range(1, files_resp.chunks+1):
            seek_start = (i - 1) * files_resp.chunk_size
            file_handler.seek(seek_start)
            chunk_bytes = file_handler.read(files_resp.chunk_size)
            file_chunk = metaFileTaskChunkOrm.get_or_create(files_resp.file_id, i, defaults=dict(
                file_id=files_resp.file_id,
                chunk_index=i,
                chunk_md5=md5_bytes(chunk_bytes),
                chunk_sha256=sha256_bytes(chunk_bytes),
                status=EnumMetaFileTask.doing,
                chunk_binary=chunk_bytes,
                chunk_binary_length=chunk_bytes.__len__(),
                estimate_tx_size = tx_chunk_size(chunk_bytes)
            ))
            log('chunk_bytes: ', chunk_bytes.__len__(), chunk_bytes)
            log('chunk_bytes: ', file_chunk)
            log('tx size', tx_chunk_size(chunk_bytes))
            #
            data_list = create_meta_file_extended_data_list(
                private_key.public_key.hex(),
                metafile_protocol_node,
                f'{task.sha256}_{file_chunk.chunk_index}',
                file_chunk.chunk_binary,
                MetaFileType.chunk,
                '0.0.1'
            )
            u, service_fee = per_utxo_amount(chunk_bytes, feeb, data_list, info.service_fee_min_satoshis, info.service_fee_rate)
            print(math.ceil(tx_chunk_size(chunk_bytes)))
            item = (private_key.address, u, 'satoshi')
            recv_list.append(item)
        # split utxo
        # print(info)
        # print(recv_list)
        # r = private_key.send(recv_list)
        # print(r)
        # create_tx
        item_list: List[MetaFileTaskChunk] = metaFileTaskChunkOrm.find_doing_chunk_by_number(files_resp.file_id, 5)
        from bitsv.network.services.whatsonchain import Whatsonchain
        woc = Whatsonchain()
        for item in item_list:
            # 获取绑定的utxo
            up = item.get_unspents()
            # 构造交易
            data_list = create_meta_file_extended_data_list(
                private_key.public_key.hex(),
                metafile_protocol_node,
                f'{task.sha256}_{item.chunk_index}',
                item.chunk_binary,
                MetaFileType.chunk,
                '0.0.1'
            )
            outputs = [
                (info.service_fee_address, item.service_fee, 'satoshi')
            ]
            tx = private_key.create_op_return_tx(data_list, outputs=outputs, unspents=up, fee=DEFAULT_FEE_SLOW)
            txid = woc.broadcast_rawtx(tx)
            log("txid", txid)
        log('is_all_success', metaFileTaskChunkOrm.is_all_success(files_resp.file_id))
        if metaFileTaskChunkOrm.is_all_success(files_resp.file_id):
            sync_items:List[MetaFileTaskChunk] = metaFileTaskChunkOrm.find_no_sync_metafile_chunk(files_resp.file_id)
            for sync_item in sync_items:
                chunk_request = ChunksRequest(
                    file_id=files_resp.file_id,
                    md5=sync_item.chunk_md5,
                    sha256=sync_item.chunk_sha256,
                    chunk_sequence=sync_item.chunk_index,
                    txid=sync_item.txid
                )
                chunk_resp = self.metafile_api.chunks(chunk_request)
                log(chunk_resp)

    def upload_metafile_from_bytes(private_key: PrivateKey, metafile_protocol_node: str, data_bytes: bytes, metaid: str=None):
        """
        :param metafile_protocol_node:
        :param data_bytes:
        :param metaid:
        :return:
        """
        pass

