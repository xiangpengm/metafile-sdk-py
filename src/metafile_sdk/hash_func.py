from hashlib import sha256


def sha256_file(file_path: str):
    buffer_size = 2048
    with open(file_path, 'rb') as f:
        sha256_obj = sha256()
        while f:
            buffer = f.read(buffer_size)
            sha256_obj.update(buffer)
            if  buffer == b'':
                break
        return sha256_obj.hexdigest()


def sha256_bytes(b: bytes):
    sha256_obj = sha256()
    sha256_obj.update(b)
    return sha256_obj.hexdigest()
