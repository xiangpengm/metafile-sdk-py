from typing import Optional
from pydantic import BaseModel

from metafile_sdk.api.api_base import ApiBase


class MetanetNodeInfo(BaseModel):
    nodeTxId: Optional[str]
    nodeAddress: Optional[str]
    nodePublicKey: Optional[str]
    parentTxId: Optional[str]
    parentAddress: Optional[str]
    parentPublicKey: Optional[str]
    outputIndex: Optional[int]
    blockHeight: Optional[int]
    rootTxId: Optional[str]
    rootAddress: Optional[str]
    rootPublicKey: Optional[str]
    timestamp: Optional[int]
    isValid: Optional[bool]
    reason: Optional[str]


class MetanetGetNode(BaseModel):
    code: int
    msg: str
    time: int
    error: str
    result: MetanetNodeInfo


class ShowmandbApi(ApiBase):

    _metanet_getnode = '/v1/metanet/getNode/{}'

    def __init__(self, base_url: str, headers):
        super().__init__(base_url, headers)
        self._headers = {}
        if headers is not None:
            self._headers.update(headers)
        self.base_url = base_url


    def metanet_getnode(self, txid):
        path = self._metanet_getnode.format(txid)
        data = self._get(path)
        return MetanetGetNode(**data)
