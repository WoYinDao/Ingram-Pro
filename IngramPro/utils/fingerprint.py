"""Device fingerprinting based on HTTP responses and rules.csv."""
import hashlib
import re
from collections import defaultdict

import requests

from loguru import logger
from lxml import etree


def _parse(req, rule_val):
    """
    Check whether an HTTP response matches a fingerprint rule expression.

    *rule_val* may be a compound AND expression: 'cond1&&cond2&&...'
    Each condition has the form: key=`value`
    Supported keys: md5, title, body, headers, status_code
    """
    def check_one(item):
        left, right = re.search(r'(.*)=`(.*)`', item).groups()

        if left == 'md5':
            return hashlib.md5(req.content).hexdigest() == right

        elif left == 'title':
            try:
                html = etree.HTML(req.text)
                title_node = html.xpath('//title')
                if title_node:
                    return right.lower() in title_node[0].xpath('string(.)').lower()
            except Exception:
                pass

        elif left == 'body':
            try:
                html = etree.HTML(req.text)
                body_nodes = html.xpath('//body')
                if body_nodes:
                    for node in body_nodes[0]:
                        if right.lower() in node.xpath('string(.)').lower():
                            return True
            except Exception:
                pass

        elif left == 'headers':
            for header_item in req.headers.items():
                if right.lower() in ''.join(header_item).lower():
                    return True

        elif left == 'status_code':
            return int(req.status_code) == int(right)

        return False

    return all(map(check_one, rule_val.split('&&')))


def fingerprint(ip, port, config):
    """
    Identify the product running on ip:port using fingerprint rules.

    Returns the product name string on match, or None if unrecognised.
    """
    # Group rules by path so each unique path is requested exactly once per
    # target (the old per-rule cache re-requested any non-200 path repeatedly).
    rules_by_path = defaultdict(list)
    for rule in config.rules:
        rules_by_path[rule.path].append(rule)

    headers = {'Connection': 'close', 'User-Agent': config.user_agent}
    with requests.Session() as session:
        for path, rules in rules_by_path.items():
            try:
                req = session.get(
                    f'http://{ip}:{port}{path}',
                    headers=headers,
                    timeout=config.timeout,
                )
            except Exception as e:
                logger.error(e)
                continue
            for rule in rules:
                try:
                    if _parse(req, rule.val):
                        return rule.product
                except Exception as e:
                    logger.error(e)

    return None
