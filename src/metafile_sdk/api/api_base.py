import requests

from metafile_sdk.utils import log


class ApiBase(object):

    def __init__(self, base_url: str, headers):
        self._headers = {}
        if headers is not None:
            self._headers.update(headers)
        self.base_url = base_url

    def _post(self, path, body: dict, headers=None):
        if headers:
            headers.update(self._headers)
        else:
            headers = self._headers
        url = f'{self.base_url}{path}'
        resp = requests.post(url, json=body, headers=headers)
        log(f"{self.__class__.__name__} POST {path}", resp.content)
        resp.raise_for_status()
        return resp.json()

    def _get(self, path, params: dict = None, raw=False):
        url = f'{self.base_url}{path}'
        resp = requests.get(url, params=params, headers=self._headers)
        log(f"{self.__class__.__name__}  GET {path}", resp.content)
        resp.raise_for_status()
        if raw:
            return resp.content
        else:
            return resp.json()
