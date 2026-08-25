"""Base class for all POC modules."""
import os
import requests
from collections import namedtuple
from loguru import logger

from IngramPro.utils.net import base_url as _base_url


class POCTemplate:
    """Template that every individual POC must inherit from."""

    level = namedtuple('level', 'high medium low')('high', 'medium', 'low')
    poc_classes = []

    @staticmethod
    def register_poc(cls):
        """Register a POC class so the scanner can discover and use it."""
        POCTemplate.poc_classes.append(cls)

    def __init__(self, config):
        self.config = config
        self.name = self.get_file_name(__file__)
        self.product = 'base'
        # Optional extra brand keys this POC should also run against
        # (Amcrest is Dahua OEM, etc.). Consumed by get_poc_dict().
        self.products = None
        # Set False on reference-only modules (no safe HTTP oracle) so they are
        # registered but never scheduled.
        self.enabled = True
        self.product_version = ''
        self.ref = ''
        self.level = self.level.low
        self.desc = ''
        self.session = requests.Session()
        self.session.headers.update({
            'Connection': 'keep-alive',
            'User-Agent': self.config.user_agent,
        })
        # One weak-password probe per camera can take a while; cap retries so a
        # flaky host does not stall a whole greenlet.
        from requests.adapters import HTTPAdapter
        self.session.mount('http://', HTTPAdapter(max_retries=1))
        self.session.mount('https://', HTTPAdapter(max_retries=1))

    def get_file_name(self, file):
        """Return the stem of the given file path (used as POC name)."""
        return os.path.basename(file).split('.')[0]

    def url(self, ip, port, path=''):
        """Build http(s)://ip:port/path, honoring TLS ports."""
        if path and not path.startswith('/'):
            path = '/' + path
        return f'{_base_url(ip, port)}{path}'

    def verify(self, ip, port):
        """
        Probe the target for this vulnerability.

        Returns:
            tuple (ip, port, product, user, password, poc_name) on success,
            None on failure.
        """
        pass

    def _snapshot(self, url, img_file_name, auth=None) -> int:
        """Download an image from *url* and save it to the snapshots directory."""
        img_path = os.path.join(self.config.out_dir, self.config.snapshots, img_file_name)
        try:
            kwargs = dict(timeout=self.config.timeout, verify=False, stream=True)
            if auth:
                kwargs['auth'] = auth
            res = self.session.get(url, **kwargs)
            ctype = (res.headers.get('Content-Type') or '').lower()
            blob = res.content[:8] if res.content else b''
            looks_image = (
                blob.startswith(b'\xff\xd8\xff')          # JPEG
                or blob.startswith(b'\x89PNG\r\n\x1a\n')  # PNG
                or ctype.startswith('image/')
            )
            if res.status_code == 200 and looks_image:
                with open(img_path, 'wb') as f:
                    for chunk in res.iter_content(10240):
                        f.write(chunk)
                return 1
        except Exception as e:
            logger.error(e)
        return 0

    def exploit(self, results: tuple) -> int:
        """Post-exploitation: capture a snapshot. Returns number of snapshots saved."""
        return 0
