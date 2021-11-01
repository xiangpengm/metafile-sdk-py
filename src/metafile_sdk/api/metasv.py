from metafile_sdk.bitsv.network.meta import Unspent
from metafile_sdk.bitsv.transaction import calc_txid
from metafile_sdk.api.api_base import ApiBase


class MetasvApi(ApiBase):
    # 获取utxo
    _address_utxo = '/address/{}/utxo'
    # 广播消息
    _pushtx = '/tx/broadcast'

    def __init__(self, metasv_api_key, base_url='https://apiv2.metasv.com', headers=None):
        super(MetasvApi, self).__init__(base_url, headers)
        self._headers = {
            'Authorization': f'Bearer {metasv_api_key}'
        }
        if headers is not None:
            self._headers.update(headers)
        self.base_url = base_url

    def get_unspents(self, address):
        # 获取utxo
        path = self._address_utxo.format(address)
        utxo_list = self._get(path)
        result_list = []
        for utxo in utxo_list:
            new_utxo = Unspent(amount=utxo['value'],
                               confirmations=0,
                               txid=utxo['txid'],
                               txindex=utxo['outIndex'])
            result_list.append(new_utxo)
        return result_list

    def broadcast_rawtx(self, rawtx):
        path = self._pushtx
        data = {
            'hex': rawtx
        }
        resp = self._post(path, data, headers={
            'accept': 'application/json',
            'Content-Type': 'application/json'
        })
        if resp['txid']:
            return calc_txid(rawtx)
        else:
            message = resp['message']
            raise ValueError(message)

