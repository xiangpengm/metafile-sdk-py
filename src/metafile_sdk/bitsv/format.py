from coincurve import verify_signature as _vs

from metafile_sdk.bitsv.base58 import b58decode_check, b58encode_check
from metafile_sdk.bitsv.crypto import ripemd160_sha256
from metafile_sdk.bitsv.curve import x_to_y

# See https://en.bitcoin.it/wiki/List_of_address_prefixes
# Referred to henceforth as the "prefix"
MAIN_PUBKEY_HASH = b'\x00'
MAIN_SCRIPT_HASH = b'\x05'
MAIN_PRIVATE_KEY = b'\x80'
MAIN_BIP32_PUBKEY = b'\x04\x88\xb2\x1e'
MAIN_BIP32_PRIVKEY = b'\x04\x88\xad\xe4'
TEST_PUBKEY_HASH = b'\x6f'
TEST_SCRIPT_HASH = b'\xc4'
TEST_PRIVATE_KEY = b'\xef'
TEST_BIP32_PUBKEY = b'\x045\x87\xcf'
TEST_BIP32_PRIVKEY = b'\x045\x83\x94'
PUBLIC_KEY_UNCOMPRESSED = b'\x04'
PUBLIC_KEY_COMPRESSED_EVEN_Y = b'\x02'
PUBLIC_KEY_COMPRESSED_ODD_Y = b'\x03'
PRIVATE_KEY_COMPRESSED_PUBKEY = b'\x01'


def verify_sig(signature, data, public_key):
    """Verifies some data was signed by the owner of a public key.

    :param signature: The signature to verify.
    :type signature: ``bytes``
    :param data: The data that was supposedly signed.
    :type data: ``bytes``
    :param public_key: The public key.
    :type public_key: ``bytes``
    :returns: ``True`` if all checks pass, ``False`` otherwise.
    """
    return _vs(signature, data, public_key)


def address_to_public_key_hash(address):
    get_prefix(address)
    return b58decode_check(address)[1:]


def get_prefix(address):
    prefix = b58decode_check(address)[:1]

    if prefix == MAIN_PUBKEY_HASH:
        return 'main'
    elif prefix == TEST_PUBKEY_HASH:
        return 'test'
    else:
        raise ValueError('{} does not correspond to a mainnet nor '
                         'testnet address.'.format(prefix))


def bytes_to_wif(private_key, prefix='main', compressed=False):

    if prefix == 'test':
        prefix = TEST_PRIVATE_KEY
    else:
        prefix = MAIN_PRIVATE_KEY

    if compressed:
        suffix = PRIVATE_KEY_COMPRESSED_PUBKEY
    else:
        suffix = b''

    private_key = prefix + private_key + suffix

    return b58encode_check(private_key)


def wif_to_bytes(wif):

    private_key = b58decode_check(wif)

    prefix = private_key[:1]

    if prefix == MAIN_PRIVATE_KEY:
        prefix = 'main'
    elif prefix == TEST_PRIVATE_KEY:
        prefix = 'test'
    else:
        raise ValueError('{} does not correspond to a mainnet nor '
                         'testnet address.'.format(prefix))

    # Remove prefix byte and, if present, compression flag.
    if len(wif) == 52 and private_key[-1] == 1:
        private_key, compressed = private_key[1:-1], True
    else:
        private_key, compressed = private_key[1:], False

    return private_key, compressed, prefix


def wif_checksum_check(wif):

    try:
        decoded = b58decode_check(wif)
    except ValueError:
        return False

    if decoded[:1] in (MAIN_PRIVATE_KEY, TEST_PRIVATE_KEY):
        return True

    return False


def public_key_to_address(public_key, prefix='main'):
    if prefix == 'test':
        prefix = TEST_PUBKEY_HASH
    elif prefix == 'main':
        prefix = MAIN_PUBKEY_HASH
    else:
        raise ValueError('Invalid prefix.')

    # 33 bytes compressed, 65 uncompressed.
    length = len(public_key)
    if length not in (33, 65):
        raise ValueError('{} is an invalid length for a public key.'.format(length))

    return b58encode_check(prefix + ripemd160_sha256(public_key))


def public_key_to_coords(public_key):

    length = len(public_key)

    if length == 33:
        flag, x = int.from_bytes(public_key[:1], 'big'), int.from_bytes(public_key[1:], 'big')
        y = x_to_y(x, flag & 1)
    elif length == 65:
        x, y = int.from_bytes(public_key[1:33], 'big'), int.from_bytes(public_key[33:], 'big')
    else:
        raise ValueError('{} is an invalid length for a public key.'.format(length))

    return x, y


def coords_to_public_key(x, y, compressed=True):

    if compressed:
        y = PUBLIC_KEY_COMPRESSED_ODD_Y if y & 1 else PUBLIC_KEY_COMPRESSED_EVEN_Y
        return y + x.to_bytes(32, 'big')

    return PUBLIC_KEY_UNCOMPRESSED + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')


def point_to_public_key(point, compressed=True):
    return coords_to_public_key(point.x, point.y, compressed)
