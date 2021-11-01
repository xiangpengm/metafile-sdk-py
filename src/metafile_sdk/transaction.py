from enum import Enum
from io import BytesIO
from typing import List, Optional

from metafile_sdk.bitsv.base58 import b58encode_check
from metafile_sdk.bitsv.format import MAIN_PUBKEY_HASH
from pydantic import BaseModel


class TxBytesIO(BytesIO):

    def read_hex(self, bytes_num):
        b = self.read(bytes_num)
        return b.hex()

    def read_int(self, bytes_num):
        bs = self.read(bytes_num)
        if bs == b'':
            return None
        return int.from_bytes(bs, byteorder='little')

    def read_var_int(self):
        b = self.read(1)
        if not b:
            raise IOError('数据错误')
        b = ord(b)
        if b <= 0xfc:
            return b
        elif b == 0xfd:
            return self.read_int(2)
        elif b == 0xfe:
            return self.read_int(4)
        elif b == 0xff:
            return self.read_int(8)
        else:
            raise ValueError(f'数据错误{b}')


class EnumScriptType(str, Enum):
    # 解锁脚本
    unlock = 'unlock'
    # 支付公钥哈希
    p2pkh = 'p2pkh'
    # 标准的p2pkh
    safe_op_return = 'safe_op_return'
    # 未知不支持
    unknown = 'unknown'


def read_op_return_data(stream: TxBytesIO):
    # 读取数据长度
    op_code = stream.read_int(1)
    if op_code is None:
        return None
    if 1 <= op_code <= 75:
        data_len = op_code
    elif op_code == 76:
        data_len = stream.read_int(1)
    elif op_code == 77:
        data_len = stream.read_int(2)
    elif op_code == 78:
        data_len = stream.read_int(4)
    else:
        return ''
    data = stream.read(data_len)
    return data


def parse_op_return_data(script_code: bytes):
    stream = TxBytesIO(script_code)
    stream.read(2)
    data_list = []
    while True:
        data = read_op_return_data(stream)
        if data is not None:
            data_list.append(data)
        else:
            break
    return data_list


def parse_unlock_data(script_code: bytes):
    stream = TxBytesIO(script_code)
    data_list = []
    while True:
        data = read_op_return_data(stream)
        if data is not None:
            data_list.append(data)
        else:
            break
    return data_list


class Script(BaseModel):
    # 脚本类型
    type: EnumScriptType
    # 解锁脚本长度
    script_len: int
    # 脚本
    script_code: bytes
    # 缓存的解析数据 适用于
    cache_data: List[bytes] = None

    def _parse_init(self):
        if self.cache_data is None:
            if self.type == EnumScriptType.safe_op_return:
                self.cache_data = parse_op_return_data(self.script_code)
            elif self.type == EnumScriptType.unlock:
                self.cache_data = parse_unlock_data(self.script_code)

    def get_signature(self) -> str:
        if self.type != EnumScriptType.unlock:
            raise TypeError(f'不支持的脚本类型{self.type}')
        self._parse_init()
        return self.cache_data[0].hex()

    def get_public_key(self):
        if self.type != EnumScriptType.unlock:
            raise TypeError(f'不支持的脚本类型{self.type}')
        self._parse_init()
        return self.cache_data[1].hex()

    def get_data(self) -> List[bytes]:
        if self.type != EnumScriptType.safe_op_return:
            raise TypeError(f'不支持的脚本类型{self.type}')
        self._parse_init()
        return self.cache_data

    def get_public_key_hash(self) -> str:
        if self.type != EnumScriptType.p2pkh:
            raise TypeError(f'不支持的脚本类型{self.type}')
        return self.script_code[3:23].hex()

    def get_p2pkh_address(self):
        if self.type != EnumScriptType.p2pkh:
            raise TypeError(f'不支持的脚本类型{self.type}')
        return b58encode_check(MAIN_PUBKEY_HASH + self.script_code[3:23])


class TxInput(BaseModel):
    # 前置交易id
    pre_tx_id: str
    # 前置交易输出下标
    pre_tx_outputs_index: int
    # 脚本
    script: Script
    #
    n_sequence: int


class TxOutput(BaseModel):
    # 锁定聪
    satoshi: int
    # 脚本
    script: Script


class Transaction(BaseModel):
    # 交易版本号
    version: int
    # 交易输入数量
    inputs_count: int
    # 交易输入
    inputs: List[TxInput]
    # 交易输出数量
    outputs_count: int
    # 交易输出
    outputs: List[TxOutput]
    # nlocktime
    nlocktime: int


    @classmethod
    def _from_bytes(cls, bytes_data: bytes) -> 'Transaction':
        stream = TxBytesIO(bytes_data)
        version = stream.read_int(4)
        if version != 1:
            raise ValueError(f'不支持的版本号{version}')
        inputs_count = stream.read_var_int()
        inputs = []
        for _ in range(inputs_count):
            pre_tx_id = stream.read_hex(32)
            pre_tx_outputs_index = stream.read_int(4)
            script_len = stream.read_var_int()
            script_code = stream.read(script_len)
            n_sequence = stream.read_int(4)
            script = Script(
                type=EnumScriptType.unlock,
                script_len=script_len,
                script_code=script_code,
            )
            tx_input = TxInput(
                pre_tx_id=pre_tx_id,
                pre_tx_outputs_index=pre_tx_outputs_index,
                script=script,
                n_sequence=n_sequence
            )
            inputs.append(tx_input)
        outputs_count = stream.read_var_int()
        outputs = []
        for _ in range(outputs_count):
            satoshi = stream.read_int(8)
            script_len = stream.read_var_int()
            script_code = stream.read(script_len)
            if len(script_code) == 25 and script_code.startswith(b'v\xa9\x14'):
                script_type = EnumScriptType.p2pkh
            elif script_code.startswith(b'\x00j'):
                script_type = EnumScriptType.safe_op_return
            else:
                script_type = EnumScriptType.unknown
            script = Script(
                type=script_type,
                script_len=script_len,
                script_code=script_code,
            )
            tx_output = TxOutput(
                satoshi=satoshi,
                script=script
            )
            outputs.append(tx_output)
        nlocktime = stream.read_int(4)
        tx = Transaction(
            version=version,
            inputs_count=inputs_count,
            inputs=inputs,
            outputs_count=outputs_count,
            outputs=outputs,
            nlocktime=nlocktime
        )
        return tx


    @classmethod
    def _from_hex(cls, tx_hex_string: str) -> 'Transaction':
        try:
            tx_binary = bytes.fromhex(tx_hex_string)
        except:
            raise ValueError(f'请输入hex字符串')
        return cls._from_bytes(tx_binary)

    @classmethod
    def from_hex(cls, tx_hex_string: str) -> Optional['Transaction']:
        try:
            return cls._from_hex(tx_hex_string)
        except:
            return None

    @classmethod
    def from_bytes(cls, bytes_data: bytes) -> Optional['Transaction']:
        try:
            return cls._from_bytes(bytes_data)
        except:
            return None
