#!/usr/bin/env python3
# coding: utf-8
# Ingram-Pro: Network camera vulnerability scanner (enhanced edition)
# Based on Ingram; extended with 2021-2024 CVE POCs.
# Brands covered: Hikvision, Dahua, EZVIZ, Reolink, Hanwha, TP-Link, D-Link, LB-Link, etc.

import warnings; warnings.filterwarnings("ignore")
from gevent import monkey; monkey.patch_all(thread=False)
import urllib3; urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import os
import sys
from multiprocessing import Process

from loguru import logger

from IngramPro import get_config, Core
from IngramPro.utils import color, common, get_parse, log
from IngramPro.utils.logo import logo
from IngramPro.utils.net import looks_like_target


def run():
    p = None
    try:
        for icon, font in zip(*logo):
            print(f"{color.yellow(icon, 'bright')}  {color.magenta(font, 'bright')}")

        config = get_config(get_parse())

        os.makedirs(os.path.join(config.out_dir, config.snapshots), exist_ok=True)

        if not os.path.isfile(config.in_file):
            if looks_like_target(config.in_file):
                inline = os.path.join(config.out_dir, '.inline_targets.txt')
                with open(inline, 'w', encoding='utf-8') as fh:
                    fh.write(config.in_file.strip() + '\n')
                config = config._replace(in_file=inline)
            else:
                print(
                    f"{color.red('Input file')} "
                    f"{color.yellow(config.in_file)} "
                    f"{color.red('does not exist!')}"
                )
                sys.exit(1)

        log.config_logger(os.path.join(config.out_dir, config.log), config.debug)

        p = Process(target=Core(config).run)
        if common.os_check() == 'windows':
            p.run()
        else:
            p.start()
            p.join()

    except KeyboardInterrupt:
        logger.warning('Interrupted by user (Ctrl+C)')
        if p is not None:
            try:
                p.kill()
            except Exception:
                pass
        sys.exit(0)

    except Exception as e:
        logger.error(e)
        sys.exit(1)


if __name__ == '__main__':
    run()
