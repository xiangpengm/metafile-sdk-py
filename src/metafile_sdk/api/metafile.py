from pydantic import BaseModel, Field, validator

from metafile_sdk.api.api_base import ApiBase


class InfoResponse(BaseModel):
    # bsv 上链的费率
    feeb: float = 0.5
    # 用户支付费用的地址
    service_fee_address: str
    # 服务收取费用的比例 payload size * feeb * service_charge_feeb
    service_fee_rate: float
    # 服务交易最少收取的交易费用
    service_fee_min_satoshis: int


class FilesRequest(BaseModel):
    # name
    name: str
    # 文件大小
    size: int = Field(gt=0)
    # 文件md5值
    md5: str = Field(min_length=32, max_length=32)
    # 文件sha256值
    sha256: str = Field(min_length=64, max_length=64)
    # 用户的metaid
    metaid: str = Field(min_length=64, max_length=64)
    # 数据类型
    data_type: str = Field(max_length=100)

    @validator('md5')
    def md5_hex(cls, v):
        try:
            bytes.fromhex(v)
        except Exception as _:
            raise ValueError('md5 must be hex string')
        return v

    @validator('sha256')
    def sha256_hex(cls, v):
        try:
            bytes.fromhex(v)
        except Exception as _:
            raise ValueError('metaid must be hex string')
        return v

    @validator('metaid')
    def metaid_hex(cls, v):
        try:
            bytes.fromhex(v)
        except Exception as _:
            raise ValueError('metaid must be hex string')
        return v


class ChunksRequest(BaseModel):
    # 上传任务id
    file_id: str = Field(min_length=32, max_length=32)
    # 分片的哈希
    md5: str = Field(min_length=32, max_length=32)
    # sha256
    sha256: str = Field(min_length=64, max_length=64)
    # 文件片的下标
    chunk_sequence: int = Field(ge=0)
    #
    txid: str = Field(min_length=64, max_length=64)



class MetaFileBaseResponse(BaseModel):
    # 错误码
    code: int
    # 提示
    message: str


class MetaFileFilesResponse(MetaFileBaseResponse):
    #
    chunk_size: int
    #
    chunks: int
    #
    file_id: str


class MetafileApi(ApiBase):
    # 获取服务详情信息
    _info = '/info'
    # 创建上传任务接口
    _files = '/v1/files'
    # 上传任务分片tx接口
    _chunks = '/v1/chunks'

    def __init__(self, base_url: str, headers):
        super().__init__(base_url, headers)
        self._headers = {}
        if headers is not None:
            self._headers.update(headers)
        self.base_url = base_url

    def info(self) -> InfoResponse:
        data = self._get(self._info)
        return InfoResponse(**data)

    def files(self, args: FilesRequest) -> MetaFileFilesResponse:
        data = self._post(self._files, args.dict())
        return MetaFileFilesResponse(**data)

    def chunks(self, args: ChunksRequest) -> MetaFileBaseResponse:
        data = self._post(self._chunks, args.dict())
        return MetaFileBaseResponse(**data)