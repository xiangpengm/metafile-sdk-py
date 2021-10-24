import os
from bitsv import PrivateKey
from metafile_sdk.api import ShowmandbApi, WocApi, MetafileApi
from metafile_sdk.api.metafile import FilesRequest
from metafile_sdk.model.base import get_session_by_metaid
from metafile_sdk.utils import log, file_data_type
from metafile_sdk.transaction import Transaction, EnumScriptType
from metafile_sdk.hash_func import md5_file, sha256_file, md5_bytes, sha256_bytes


class ValueErrorMetafileProtocolNode(ValueError):
    pass


class ValueErrorPrivateKey(ValueError):
    pass


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

    def upload_metafile_from_path(self, private_key: PrivateKey, metafile_protocol_node: str, file_path: str, metaid: str=None):
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
        session = get_session_by_metaid(self.cache_dir, metaid)
        log("session", session)
        # 创建记录



    def upload_metafile_from_bytes(private_key: PrivateKey, metafile_protocol_node: str, data_bytes: bytes, metaid: str=None):
        """
        :param metafile_protocol_node:
        :param data_bytes:
        :param metaid:
        :return:
        """
        pass

