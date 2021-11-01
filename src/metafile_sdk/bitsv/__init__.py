from metafile_sdk.bitsv.format import verify_sig
from metafile_sdk.bitsv.network.rates import SUPPORTED_CURRENCIES, set_rate_cache_time
from metafile_sdk.bitsv.network.services import set_service_timeout, FullNode
from metafile_sdk.bitsv.wallet import Key, PrivateKey, wif_to_key

__version__ = '0.11.5'
