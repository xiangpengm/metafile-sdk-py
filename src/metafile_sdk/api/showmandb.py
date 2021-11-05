from typing import Optional, Union
from pydantic import BaseModel

from metafile_sdk.api.api_base import ApiBase


class MetanetNodeInfo(BaseModel):
    txId: str
    nodeId: str
    metanetId: str
    rootTxId: str
    size: str
    address: str
    publicKey: str
    parentTxId: str
    metaIdTag: str
    nodeName: str
    blockHeight: str
    metaBlockHeight: int
    confirmState: bool
    fee: str
    timestamp: str


class MetanetGetNode(BaseModel):
    code: int
    data: MetanetNodeInfo = None


class ShowmandbApi(ApiBase):

    _metanet_getnode = '/aggregation/v2/app/meta/getMetaDataNode/{}'

    def __init__(self, base_url: str, headers):
        super().__init__(base_url, headers)
        self._headers = {}
        if headers is not None:
            self._headers.update(headers)
        self.base_url = base_url


    def metanet_getnode(self, txid):
        path = self._metanet_getnode.format(txid)
        try:
            data = self._get(path)
            return MetanetGetNode(**data)
        except:
            return MetanetGetNode(code=1)
