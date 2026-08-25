"""Network utility functions."""
import re

import IPy
import random
import requests
from lxml import etree


_TLS_PORTS = {443, 8443}


def looks_like_target(value: str) -> bool:
    """True if *value* is an IP / CIDR / range instead of a filename."""
    s = (value or '').strip()
    if not s or s.startswith('#'):
        return False
    if '/' in s:
        return True
    if '-' in s:
        a, _, b = s.partition('-')
        a = a.split(':')[0]
        if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', a):
            return bool(
                re.match(r'^\d{1,3}$', b) or
                re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', b)
            )
        return False
    return bool(re.match(r'^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$', s))


def base_url(ip, port) -> str:
    """http(s)://ip:port — 443/8443 use TLS. Cameras on those ports were
    previously probed only as http:// and silently missed."""
    scheme = 'https' if int(port) in _TLS_PORTS else 'http'
    return f'{scheme}://{ip}:{port}'


def get_ip_segment(start: str, end: str) -> str:
    """Derive a CIDR network string from a start/end IP pair."""
    return IPy.IP(f"{start}-{end}", make_net=True).strNormal()


def get_ip_seg_len(ip_seg: str) -> int:
    """Return the number of host addresses in an IP range or CIDR block."""
    if '-' in ip_seg or '/' in ip_seg:
        return IPy.IP(ip_seg, make_net=True).len()
    return 1


def get_all_ip(ip_seg: str):
    """Yield every IP address in a range or CIDR block."""
    if '-' in ip_seg or '/' in ip_seg:
        for i in IPy.IP(ip_seg, make_net=True):
            yield i.strNormal()
    else:
        yield ip_seg


def scrapy_useragent() -> None:
    """Scrape User-Agent strings from useragentstring.com."""
    base = 'https://useragentstring.com/pages/'
    browsers = ['Chrome', 'Firefox', 'Edge', 'Safari', 'Opera']
    res = {i: [] for i in browsers}
    for browser in browsers:
        page = requests.get(f"{base}{browser}/")
        tree = etree.HTML(page.text)
        items = tree.xpath('/html/body/div[2]/div[2]/div/ul')
        for i in items[:100]:
            res[browser].append(i.xpath('li/a')[0].text)
    print(res)


def get_user_agent(name='random') -> str:
    """Return a current-looking User-Agent. The old dump was ~350 obsolete
    strings (Chrome 15, Opera 6, …) which made probes look like scanners."""
    user_agents = {
        'Chrome': [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
        ],
        'Firefox': [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
        ],
        'Edge': [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0',
        ],
        'Safari': [
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15',
        ],
        'Opera': [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0',
        ],
    }
    if name in user_agents:
        return random.choice(user_agents[name])
    return random.choice(random.choice(list(user_agents.values())))
