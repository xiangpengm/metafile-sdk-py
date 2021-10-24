from metafile_sdk.api.api_base import ApiBase


class WocApi(ApiBase):

    _tx_hex = '/v1/bsv/main/tx/{}/hex'

    def __init__(self, base_url: str, headers):
        super().__init__(base_url, headers)
        self._headers = {}
        if headers is not None:
            self._headers.update(headers)
        self.base_url = base_url


    def tx_raw_hex(self, txid):
        path = self._tx_hex.format(txid)
        data = self._get(path, raw=True)
        return data.decode()
