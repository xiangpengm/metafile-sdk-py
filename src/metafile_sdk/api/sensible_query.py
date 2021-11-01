from metafile_sdk.bitsv.network.meta import Unspent
from metafile_sdk.bitsv.transaction import calc_txid
from metafile_sdk.api.api_base import ApiBase


class SensibleQueryApi(ApiBase):
    # 获取utxo
    _address_utxo = '/address/{}/utxo'
    # 广播消息
    _pushtx = '/pushtx'

    def __init__(self, base_url='https://api.sensiblequery.com', headers=None):
        super(SensibleQueryApi, self).__init__(base_url, headers)
        self._headers = {}
        if headers is not None:
            self._headers.update(headers)
        self.base_url = base_url

    def get_unspents(self, address):
        # 获取utxo
        utxo_list = []
        path = self._address_utxo.format(address)
        buffer_size = 100
        start = 0
        while True:
            sub_utxo_resp = self._get(path, params={
                'cursor': start,
                'size': buffer_size
            })
            sub_utxo = sub_utxo_resp['data']
            utxo_list.extend(sub_utxo)
            if len(sub_utxo) <= buffer_size:
                break
            start += buffer_size
        result_list = []
        for utxo in utxo_list:
            new_utxo = Unspent(amount=utxo['satoshi'],
                               confirmations=0,
                               txid=utxo['txid'],
                               txindex=utxo['vout'])
            result_list.append(new_utxo)
        return result_list

    def broadcast_rawtx(self, rawtx):
        path = self._pushtx
        data = {
            'txHex': rawtx
        }
        resp = self._post(path, data, headers={
            'accept': 'application/json',
            'Content-Type': 'application/json'
        })
        code = resp['code']
        if code == 0:
            return calc_txid(rawtx)
        else:
            raise ValueError(resp.json())
