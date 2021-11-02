# Metafile Python SDK

## SDK demo

```python
import time
from metafile_sdk import Metafile
from metafile_sdk.bitsv import PrivateKey
from metafile_sdk.api.metasv import MetasvApi
from metafile_sdk.api.sensible_query import SensibleQueryApi

# metafile protocol node of your metaid
metafile_protocol = ''
# wif that can add child nodes under your metafile protocol node
wif = ''
# path to the file
file_path = ''


def whatsonchain_demo():
    metafile = Metafile()
    pk: PrivateKey = PrivateKey(wif)
    print(pk.address)
    print(pk.get_balance())
    t1 = time.time()
    txid = metafile.upload_metafile_from_path(pk, metafile_protocol, file_path)
    t2 = time.time()
    print('main txid', txid)
    print('main txid', f'https://metafile.id/download/{txid}')
    print('main txid', t2 - t1)


def sensible_query_demo():
    metafile = Metafile()
    pk: PrivateKey = PrivateKey(wif)
    # use sensible query api
    sensible_query_api = SensibleQueryApi()
    pk.network_api = sensible_query_api
    print(pk.address)
    print(pk.get_balance())
    t1 = time.time()
    txid = metafile.upload_metafile_from_path(pk, metafile_protocol, file_path)
    t2 = time.time()
    print('main txid', txid)
    print('main txid', f'https://metafile.id/download/{txid}')
    print('main txid', t2 - t1)


def metasv_demo():
    metafile = Metafile()
    pk: PrivateKey = PrivateKey(wif)
    # use metasv api
    metasv_api_key = ''
    metasv = MetasvApi(metasv_api_key)
    pk.network_api = metasv
    print(pk.address)
    print(pk.get_balance())
    t1 = time.time()
    txid = metafile.upload_metafile_from_path(pk, metafile_protocol, file_path)
    t2 = time.time()
    print('main txid', txid)
    print('main txid', f'https://metafile.id/download/{txid}')
    print('main txid', t2 - t1)


def main():
    #  pip install metafile-sdk
    # whatsonchain_demo()
    sensible_query_demo()
    # metasv_demo()


if __name__ == '__main__':
    main()
```