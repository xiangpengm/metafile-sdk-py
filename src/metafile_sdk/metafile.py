import json
import math
import os
from typing import List

from metafile_sdk.bitsv import PrivateKey
from metafile_sdk.bitsv.network.fees import DEFAULT_FEE_SLOW
from metafile_sdk.bitsv.network.meta import Unspent
from sqlalchemy.orm import Session

from metafile_sdk.api import ShowmandbApi, WocApi, MetafileApi
from metafile_sdk.api.metafile import FilesRequest, ChunksRequest, InfoResponse, ChunksQueryResponse, \
    MetaFileFilesResponse
from metafile_sdk.model.base import get_session_by_metaid, MetaFileTask, MetaFileTaskChunk, EnumMetaFileTask
from metafile_sdk.orm import MetaFileTaskOrm, MetaFileTaskChunkOrm
from metafile_sdk.utils import log, file_data_type
from metafile_sdk.transaction import Transaction, EnumScriptType
from metafile_sdk.hash_func import sha256_file, sha256_bytes
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from metafile_sdk.version import __version__

class ValueErrorMetafileProtocolNode(ValueError):
    pass


class ValueErrorPrivateKey(ValueError):
    pass


class UploadFailed(Exception):
    pass


class MetaFileType():
    # 分片
    chunk = 'metafile/chunk'
    # 索引
    index = 'metafile/index'
    # 软连接
    link = 'metafile/link'


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


def tx_chunk_size(chunk_len: int):
    size = 148 + 2 + 4 + 67 + 65 + 7 + 67 + 9 + chunk_len + 2 + 7 + 21 + 7 + 10 + 34 * 2 + 3 + 2
    return size


def calculate_index_payload_size(file_size, file_name, data_type, chunk_size=102400):
    # 计算索引交易的字节数
    number = math.ceil(file_size/chunk_size)
    l = 2
    sha256 = 8 + 1 + 64 + 2 + 1
    fileSize = 10 + 1 + len(str(file_size)) + 1
    chunkNumber = 13 + 1 + len(str(number)) + 1
    chunkSize = 11 + 1 + len(str(chunk_size)) + 1
    dataType = 10 + 1 + len(data_type) + 2 + 1
    name = 6 + 1 + len(file_name) + 2 + 1
    item_len = 12 + 151 * number + 2 + (number - 1)
    return l + sha256 + fileSize + chunkNumber + chunkSize + dataType + name + item_len


def calculate_metafile_slice_all(file_size, file_name, data_type, service_fee_rate, service_fee_min_satoshis, feeb, chunk_size=102400):
    # 计算总花费的余额
    chunks = math.ceil(file_size / chunk_size)
    metaid_other_len = 232
    index_slice = calculate_index_payload_size(file_size, file_name, data_type, chunk_size)
    index_payload_len = index_slice + metaid_other_len
    index_payload_fee = max(math.ceil(index_payload_len * service_fee_rate), service_fee_min_satoshis)
    index_tx_fee = math.ceil(tx_chunk_size(index_slice) * feeb)  + index_payload_fee
    chunk_payload_len = chunk_size + metaid_other_len
    chunk_payload_fee = max(math.ceil(chunk_payload_len * service_fee_rate), service_fee_min_satoshis)
    chunk_tx_fee = math.ceil(tx_chunk_size(chunk_size) * feeb) + chunk_payload_fee
    return index_tx_fee + chunk_tx_fee * chunks


def calculate_metafile_slice_all_break(file_size, file_name, data_type, service_fee_rate, service_fee_min_satoshis, feeb, chunks, chunk_size=102400):
    # 计算总花费的余额
    metaid_other_len = 232
    index_slice = calculate_index_payload_size(file_size, file_name, data_type, chunk_size)
    index_payload_len = index_slice + metaid_other_len
    index_payload_fee = max(math.ceil(index_payload_len * service_fee_rate), service_fee_min_satoshis)
    index_tx_fee = math.ceil(tx_chunk_size(index_slice) * feeb)  + index_payload_fee
    chunk_payload_len = chunk_size + metaid_other_len
    chunk_payload_fee = max(math.ceil(chunk_payload_len * service_fee_rate), service_fee_min_satoshis)
    chunk_tx_fee = math.ceil(tx_chunk_size(chunk_size) * feeb) + chunk_payload_fee
    return index_tx_fee + chunk_tx_fee * chunks


def per_utxo_amount(chunk_bytes, feeb, data_list, service_fee_min_satoshis, service_fee_rate):
    data_len = sum([len(data) for data in data_list])
    service_fee = max(math.ceil(data_len * service_fee_rate), service_fee_min_satoshis)
    return math.ceil(tx_chunk_size(chunk_bytes.__len__()) * feeb) + service_fee, service_fee


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
        self._thread_num = 10
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)

    def _check_file(self, file_path: str):
        pass

    def _check_metaid(self, metaid, metafile_protocol_node):
        if metaid is None:
            # get metaid root node from showmandb
            metaid_node = self.showmandb_api.metanet_getnode(metafile_protocol_node)
            if metaid_node.code == 200:
                metaid = metaid_node.result.rootTxId
            else:
                raise ValueErrorMetafileProtocolNode(f'{metafile_protocol_node} node must have metaid node')
        return metaid

    def _check_protocol_node(self, private_key, metafile_protocol_node):
        tx_hex = self.woc_api.tx_raw_hex(metafile_protocol_node)
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

    def _get_files_resp(self, metaFileTaskOrm: MetaFileTaskOrm, metaFileTaskChunkOrm: MetaFileTaskChunkOrm, private_key: PrivateKey, metaid, file_path, info: InfoResponse, feeb):
        _sha256 = sha256_file(file_path)
        file_stat = os.stat(file_path)
        file_size = file_stat.st_size
        file_name = os.path.basename(file_path)
        data_type = file_data_type(file_path)
        # 构造任务
        task = metaFileTaskOrm.get_by_sha256(_sha256)
        log('_get_files_resp task', task)
        # 查询缓存, 如果没有则请求
        files_request = FilesRequest(
            name=file_name,
            size=file_size,
            sha256=_sha256,
            metaid=metaid,
            data_type=data_type,
        )
        if not task:
            # Todo 计算总需要余额
            need_satoshi = calculate_metafile_slice_all(file_size, file_name, data_type, info.service_fee_rate, info.service_fee_min_satoshis, feeb)
            balance  = private_key.get_balance()
            log(f"need satoshi: {need_satoshi}, balance: {balance}")
            if need_satoshi > int(balance):
                raise ValueError(f'balance must more than {need_satoshi}')
            files_resp = self.metafile_api.files(files_request)
        else:
            # Todo 获取缓存为上传的chunks计算花费
            chunks = metaFileTaskChunkOrm.no_success_chunks(task.file_id)
            log('chunks', chunks)
            need_satoshi = calculate_metafile_slice_all_break(file_size, file_name, data_type, info.service_fee_rate, info.service_fee_min_satoshis, feeb, chunks)
            balance  = private_key.get_balance()
            log(f"need satoshi: {need_satoshi}, balance: {balance}")
            if need_satoshi > int(balance):
                raise ValueError(f'balance must more than {need_satoshi}')
            files_resp = MetaFileFilesResponse(
                code=0,
                message='',
                chunk_size=task.chunk_size,
                chunks=task.chunks,
                file_id=task.file_id
            )
        return files_request, files_resp

    def _scan_chunk_record(self, private_key, metafile_protocol_node, file_path, files_resp, task, feeb, metaFileTaskChunkOrm, info):
        file_handler = open(file_path, 'rb')
        for i in range(1, files_resp.chunks+1):
            seek_start = (i - 1) * files_resp.chunk_size
            file_handler.seek(seek_start)
            chunk_bytes = file_handler.read(files_resp.chunk_size)
            data_list = create_meta_file_extended_data_list(
                private_key.public_key.hex(),
                metafile_protocol_node,
                f'{task.sha256}_{i}',
                chunk_bytes,
                MetaFileType.chunk,
                '1.0.2'
            )
            u, service_fee = per_utxo_amount(chunk_bytes, feeb, data_list, info.service_fee_min_satoshis, info.service_fee_rate)
            metaFileTaskChunkOrm.get_or_create(files_resp.file_id, i, defaults=dict(
                file_id=files_resp.file_id,
                chunk_index=i,
                chunk_sha256=sha256_bytes(chunk_bytes),
                status=EnumMetaFileTask.doing,
                chunk_binary=chunk_bytes,
                chunk_binary_length=chunk_bytes.__len__(),
                estimate_tx_size = tx_chunk_size(chunk_bytes.__len__()),
                service_fee=service_fee,
                unspents_satoshi=u
            ))

    def _scan_hash_processor(self, item: MetaFileTaskChunk, metaFileTaskChunkOrm):
        _sha256 = item.chunk_sha256
        chunks_query: ChunksQueryResponse = self.metafile_api.chunks_query(_sha256)
        item.scan_chunk = True
        if chunks_query.code == 0 and chunks_query.txid:
            item.status = EnumMetaFileTask.success
            item.txid = chunks_query.txid
        metaFileTaskChunkOrm.add(item)

    def _scan_hash(self, metaFileTaskChunkOrm, files_resp):
        with ThreadPoolExecutor(self._thread_num) as thread_pool:
            while True:
                items: List[MetaFileTaskChunk] = metaFileTaskChunkOrm.find_no_scan_chunk_by_number(files_resp.file_id, self._thread_num)
                if items.__len__() == 0:
                    break
                items_len = items.__len__()
                r = thread_pool.map(self._scan_hash_processor,
                                    items,
                                    (metaFileTaskChunkOrm for _ in range(items_len)),
                                    )
                result = [i for i in r]
                metaFileTaskChunkOrm.commit()
                log('result', result)

    def _split_utxo(self, private_key:PrivateKey, metaFileTaskChunkOrm: MetaFileTaskChunkOrm, file_id, woc):
        up = private_key.get_unspents()
        metaFileTaskChunkOrm.update_no_success_tx(file_id)
        while True:
            items:List[MetaFileTaskChunk] = metaFileTaskChunkOrm.find_no_unspent_chunk(file_id, 50)
            if items.__len__() == 0:
                break
            outputs = []
            for item in items:
                _i = (private_key.address, item.unspents_satoshi, 'satoshi')
                outputs.append(_i)
            tx_hex = private_key.create_transaction(outputs, unspents=up)
            txid = woc.broadcast_rawtx(tx_hex)
            log("split txid", txid)
            if txid:
                for index, item in enumerate(items):
                    item.unspents_txid = txid
                    item.unspents_index = index
                    metaFileTaskChunkOrm.save(item)
            _tx = Transaction.from_hex(tx_hex)
            op = _tx.outputs[-1]
            up = [
                Unspent(op.satoshi, 0, txid, len(_tx.outputs) - 1)
            ]

    def _push_chunk_to_chain_processor(self, item, private_key, metaFileTaskChunkOrm, metafile_protocol_node, task, info, woc):
        up = item.get_unspents()
        # 构造交易
        data_list = create_meta_file_extended_data_list(
            private_key.public_key.hex(),
            metafile_protocol_node,
            f'{task.sha256}_{item.chunk_index}',
            item.chunk_binary,
            MetaFileType.chunk,
            '1.0.2'
        )
        outputs = [
            (info.service_fee_address, item.service_fee, 'satoshi')
        ]
        tx = private_key.create_op_return_tx(data_list, outputs=outputs, unspents=up, fee=DEFAULT_FEE_SLOW)
        try:
            txid = woc.broadcast_rawtx(tx)
            if txid:
                item.status = EnumMetaFileTask.success
                item.txid= txid
                metaFileTaskChunkOrm.add(item)
        except Exception as e:
            log('e', e, item.id)
            pass

    def _push_chunk_to_chain(self,
                             private_key, metafile_protocol_node,
                             metaFileTaskChunkOrm, files_resp, task,
                             info, woc
        ):
        with ThreadPoolExecutor(self._thread_num) as thread_pool:
            while True:
                items: List[MetaFileTaskChunk] = metaFileTaskChunkOrm.find_doing_chunk_by_number(files_resp.file_id, self._thread_num)
                if items.__len__() == 0:
                    break
                items_len = items.__len__()
                # 广播交易
                r = thread_pool.map(self._push_chunk_to_chain_processor,
                                     items,
                                     (private_key for _ in range(items_len)),
                                     (metaFileTaskChunkOrm for _ in range(items_len)),
                                     (metafile_protocol_node for _ in range(items_len)),
                                     (task for _ in range(items_len)),
                                     (info for _ in range(items_len)),
                                     (woc for _ in range(items_len)))
                result = [i for i in r]
                log('result', result)
                # 上传服务
                r2 = thread_pool.map(self._push_chunk_to_metafile_processor,
                                    items,
                                    (files_resp for _ in range(items_len)),
                                    (metaFileTaskChunkOrm for _ in range(items_len)),
                                    )
                result = [i for i in r2]
                log('result2', result)
                metaFileTaskChunkOrm.commit()

    def _push_chunk_to_metafile_processor(self, sync_item: MetaFileTaskChunk, files_resp, metaFileTaskChunkOrm):
        #
        if sync_item.status == EnumMetaFileTask.success:
            chunk_request = ChunksRequest(
                file_id=files_resp.file_id,
                sha256=sync_item.chunk_sha256,
                chunk_sequence=sync_item.chunk_index,
                txid=sync_item.txid
            )
            chunk_resp = self.metafile_api.chunks(chunk_request)
            log('chunk_resp', sync_item.id, chunk_request.txid, chunk_resp)
            if chunk_resp.code == 0:
                sync_item.txid = chunk_resp.txid
                sync_item.is_sync_metafile = True
                metaFileTaskChunkOrm.add(sync_item)

    def _push_chunk_to_metafile(self, metaFileTaskChunkOrm, files_resp):
        with ThreadPoolExecutor(self._thread_num) as thread_pool:
            while True:
                sync_items:List[MetaFileTaskChunk] = metaFileTaskChunkOrm.find_no_sync_metafile_chunk(files_resp.file_id, self._thread_num)
                if sync_items.__len__() == 0:
                    break
                items_len = sync_items.__len__()
                r = thread_pool.map(self._push_chunk_to_metafile_processor,
                                         sync_items,
                                         (files_resp for _ in range(items_len)),
                                         (metaFileTaskChunkOrm for _ in range(items_len)),
                                         )
                log('result', r)
                result = [i for i in r]
                log('result', result)
                metaFileTaskChunkOrm.commit()

    def _push_index_to_metafile(self, private_key, metafile_protocol_node,
                feeb, metaFileTaskChunkOrm, files_resp, task, info, woc):
        if metaFileTaskChunkOrm.is_all_chunk_sync(files_resp.file_id) and not metaFileTaskChunkOrm.is_index_chunk_async(files_resp.file_id):
        # 创建index交易, 并广播
            log('is_index_chunk_async', metaFileTaskChunkOrm.is_index_chunk_async(files_resp.file_id))
            _chunk_list: List[MetaFileTaskChunk] = metaFileTaskChunkOrm.find_all(files_resp.file_id)
            chunk_list = [{
                'sha256': chunk.chunk_sha256,
                'txid': chunk.txid
            } for chunk in _chunk_list]
            log('_chunk_list', _chunk_list)
            payload = {
                'sha256': task.sha256,
                'fileSize': task.size,
                'chunkNumber': task.chunks,
                'chunkSize': task.chunk_size,
                'dataType': task.data_type,
                'name': task.name,
                'chunkList': chunk_list
            }
            log('258 payload', payload)
            index_bytes = json.dumps(payload, separators=(',', ':')).encode()
            data_list = create_meta_file_extended_data_list(
                private_key.public_key.hex(),
                metafile_protocol_node,
                f'{task.sha256}_{0}',
                index_bytes,
                MetaFileType.index,
                '1.0.2'
            )
            u, service_fee = per_utxo_amount(index_bytes, feeb, data_list, info.service_fee_min_satoshis, info.service_fee_rate)
            #
            log('270 payload', service_fee)
            file_index = metaFileTaskChunkOrm.get_or_create(files_resp.file_id, 0, defaults=dict(
                file_id=files_resp.file_id,
                chunk_index=0,
                chunk_sha256=sha256_bytes(index_bytes),
                status=EnumMetaFileTask.doing,
                chunk_binary=index_bytes,
                chunk_binary_length=index_bytes.__len__(),
                estimate_tx_size = tx_chunk_size(index_bytes.__len__()),
                service_fee=service_fee
            ))
            if file_index.status == EnumMetaFileTask.success:
                file_index.status = EnumMetaFileTask.success
                metaFileTaskChunkOrm.save(file_index)
            else:
                up = private_key.get_unspents()
                outputs = [
                    (info.service_fee_address, file_index.service_fee, 'satoshi')
                ]
                tx = private_key.create_op_return_tx(data_list, outputs=outputs, unspents=up, fee=DEFAULT_FEE_SLOW)
                txid = woc.broadcast_rawtx(tx)
                if txid:
                    file_index.status = EnumMetaFileTask.success
                    file_index.txid = txid
                    metaFileTaskChunkOrm.save(file_index)
            if file_index.is_sync_metafile:
                return file_index.txid
            else:
                chunk_request = ChunksRequest(
                    file_id=files_resp.file_id,
                    sha256=file_index.chunk_sha256,
                    chunk_sequence=file_index.chunk_index,
                    txid=file_index.txid
                )
                chunk_resp = self.metafile_api.chunks(chunk_request)
                log('chunk_resp', chunk_resp)
                log("payload", u)
                log("index is_sync_metafile", file_index.is_sync_metafile)
                if chunk_resp.code == 0:
                    file_index.is_sync_metafile = True
                    metaFileTaskChunkOrm.save(file_index)
                    return file_index.txid

    def upload_metafile_from_path(self, private_key: PrivateKey, metafile_protocol_node: str, file_path: str, metaid: str=None, feeb=0.5, retry_count=2):
        """
        0. 检查文件存在 ok
        1. 验证metaid  ok
        2. 验证metafile_protocol_node的公钥与private_key对应的公钥一致 ok
        3. 验证计算sha256 ok
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
        log('retry count', retry_count)
        if retry_count == 0:
            raise UploadFailed('上传失败请稍后重试')
        self._check_file(file_path)
        metaid = self._check_metaid(metaid, metafile_protocol_node)
        # 获取到session
        session: Session = get_session_by_metaid(self.cache_dir, metaid, __version__)
        # 创建表
        MetaFileTask.metadata.create_all(session.get_bind())
        MetaFileTaskChunk.metadata.create_all(session.get_bind())
        metaFileTaskOrm = MetaFileTaskOrm(session)
        metaFileTaskChunkOrm = MetaFileTaskChunkOrm(session)
        self._check_protocol_node(private_key, metafile_protocol_node)
        # 创建记录
        info = self.metafile_api.info()
        files_request, files_resp = self._get_files_resp(metaFileTaskOrm, metaFileTaskChunkOrm, private_key, metaid, file_path, info, feeb)
        # 检查是否存在
        resp = self.metafile_api.files_query(files_request.sha256, metaid)
        if resp.txid:
            return resp.txid
        log('filesRequest', files_request)
        log('response', files_resp)
        # 获取 or 创建任务
        task = metaFileTaskOrm.get_or_create(files_resp.file_id, defaults=dict(
            size=files_request.size,
            name=files_request.name,
            sha256=files_request.sha256,
            status=EnumMetaFileTask.doing,
            file_id=files_resp.file_id,
            chunk_size=files_resp.chunk_size,
            data_type=files_request.data_type,
            chunks=files_resp.chunks
        ))
        log("task", task)
        woc = private_key.network_api
        if files_resp.chunks == 0:
            #
            log('upload origin')
            file_bytes = open(file_path, 'rb').read()
            data_list = create_meta_file_extended_data_list(
                private_key.public_key.hex(),
                metafile_protocol_node,
                files_request.name,
                file_bytes,
                files_request.data_type,
                '1.0.0'
            )
            u, service_fee = per_utxo_amount(file_bytes, feeb, data_list, info.service_fee_min_satoshis, info.service_fee_rate)
            up = private_key.get_unspents()
            #
            outputs = [
                (info.service_fee_address, service_fee, 'satoshi')
            ]
            tx = private_key.create_op_return_tx(data_list, outputs=outputs, unspents=up, fee=DEFAULT_FEE_SLOW)
            try:
                txid = woc.broadcast_rawtx(tx)
                chunk_request = ChunksRequest(
                    file_id=files_resp.file_id,
                    sha256=files_request.sha256,
                    chunk_sequence=0,
                    txid=txid)
                chunk_resp = self.metafile_api.chunks(chunk_request)
                log('chunk_resp', chunk_resp)
                if chunk_resp.code == 0:
                    return txid
            except Exception as e:
                log('e', e)
                pass
            log(u, service_fee)
        else :
            self._scan_chunk_record(
                private_key,
                metafile_protocol_node,
                file_path,
                files_resp,
                task,
                feeb,
                metaFileTaskChunkOrm,
                info
            )
            self._scan_hash(metaFileTaskChunkOrm, files_resp)
            self._split_utxo(private_key, metaFileTaskChunkOrm, files_resp.file_id, woc)
            # multi thread
            self._push_chunk_to_chain(private_key, metafile_protocol_node, metaFileTaskChunkOrm, files_resp, task, info, woc)
            log('is_all_success', metaFileTaskChunkOrm.is_all_success(files_resp.file_id))
            # multi thread
            self._push_chunk_to_metafile(metaFileTaskChunkOrm, files_resp)
            txid = self._push_index_to_metafile(private_key, metafile_protocol_node, feeb, metaFileTaskChunkOrm, files_resp, task, info, woc)
            if txid:
                # delete task
                metaFileTaskOrm.delete_instant(task)
                # delete chunks
                metaFileTaskChunkOrm.delete_by_file_id(files_resp.file_id)
                return txid
            else:
                retry_count -= 1
                return self.upload_metafile_from_path(private_key, metafile_protocol_node, file_path)

    def upload_metafile_from_bytes(private_key: PrivateKey, metafile_protocol_node: str, data_bytes: bytes, metaid: str=None):
        """
        :param metafile_protocol_node:
        :param data_bytes:
        :param metaid:
        :return:
        """
        pass

