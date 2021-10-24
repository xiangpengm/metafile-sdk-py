import os
from datetime import datetime
import mimetypes


def log(*args, **kwargs):
    is_debug = os.environ.get('METAFILE_DEBUG')
    if is_debug and is_debug == 'True':
        print(datetime.now(), *args, **kwargs)


def file_data_type(path):
    r = mimetypes.guess_type(path)
    mime = r[0]
    if mime is None:
        return 'application/octet-stream'
    else:
        return mime
