import os
import time
from collections import defaultdict
from threading import Thread

import gevent
from loguru import logger
from gevent.pool import Pool as geventPool

from .data import Data, SnapshotPipeline
from .pocs import get_poc_dict
from .utils import color, common, fingerprint, port_scan, status_bar, timer


@common.singleton
class Core:

    def __init__(self, config):
        self.config = config
        self.data = Data(config)
        self.snapshot_pipeline = SnapshotPipeline(config)
        self.poc_dict = get_poc_dict(self.config)

    def finish(self):
        return (
            self.data.done >= self.data.total
            and self.snapshot_pipeline.task_count <= 0
            and self.snapshot_pipeline.empty()
        )

    def report(self):
        results_file = os.path.join(self.config.out_dir, self.config.vulnerable)
        if not os.path.exists(results_file):
            return
        with open(results_file, "r", encoding="utf-8") as f:
            items = [l.strip().split(",") for l in f if l.strip()]
        if not items:
            return
        results = defaultdict(lambda: defaultdict(int))
        for i in items:
            dev = i[2].split("-")[0]
            vul = i[-1]
            results[dev][vul] += 1
        total = len(items)
        max_cnt = max(v for d in results.values() for v in d.values())
        print("\n")
        print("-" * 19, "扫描报告", "-" * 19)
        for dev in results:
            vuls = list(results[dev].items())
            dev_sum = sum(c for _, c in vuls)
            print(color.red(f"{dev} {dev_sum}", "bright"))
            for vul_name, vul_count in vuls:
                blocks = int(vul_count / max_cnt * 25)
                print(color.green(f"{vul_name:>28} | {'▥' * blocks} {vul_count}"))
        print(color.yellow(f"{'总计: ' + str(total):>46}", "bright"), flush=True)
        print("-" * 46)
        print("\n")

    def _scan_port(self, ip, port):
        if port_scan(ip, port, self.config.timeout):
            logger.info(f"{ip} port {port} is open")
            if product := fingerprint(ip, port, self.config):
                logger.info(f"{ip}:{port} is {product}")
                verified = False
                for poc in self.poc_dict[product]:
                    if results := poc.verify(ip, port):
                        verified = True
                        self.data.add_found()
                        self.data.add_vulnerable([str(x) for x in results[:6]])
                        if not self.config.disable_snapshot:
                            self.snapshot_pipeline.put((poc.exploit, results))
                if not verified:
                    self.data.add_not_vulnerable([ip, str(port), product])

    def _scan(self, target):
        items = target.split(":")
        ip = items[0]
        ports = [items[1]] if len(items) > 1 else self.config.ports
        jobs = [gevent.spawn(self._scan_port, ip, port) for port in ports]
        gevent.joinall(jobs)
        self.data.add_done()
        self.data.record_running_state()

    def run(self):
        logger.info(f"running at {timer.get_time_formatted()}")
        logger.info(
            f"config: in={self.config.in_file} out={self.config.out_dir} "
            f"ports={len(self.config.ports)} th={self.config.th_num} "
            f"timeout={self.config.timeout} snapshot={not self.config.disable_snapshot}"
        )
        try:
            self.status_bar_thread = Thread(target=status_bar, args=[self], daemon=True)
            self.status_bar_thread.start()
            if not self.config.disable_snapshot:
                self.snap_thread = Thread(
                    target=self.snapshot_pipeline.process, args=[self], daemon=True)
                self.snap_thread.start()
            # imap_unordered keeps at most th_num greenlets in flight (the old
            # spawn-all-then-join queue could hold the entire IP list in RAM).
            scan_pool = geventPool(self.config.th_num)
            for _ in scan_pool.imap_unordered(self._scan, self.data.ip_generator):
                pass
            self._shutdown()
            self.report()
        except KeyboardInterrupt:
            self._shutdown()
        except Exception as e:
            logger.error(e)
            self._shutdown()

    def _shutdown(self):
        """Drain snapshot queue, stop workers, persist state, close files."""
        try:
            if not self.config.disable_snapshot:
                # wait until queued snapshots are consumed and finished
                deadline = timer.get_time_stamp() + 30
                while not self.snapshot_pipeline.empty() or self.snapshot_pipeline.task_count > 0:
                    if timer.get_time_stamp() > deadline:
                        break
                    time.sleep(0.1)
                self.snapshot_pipeline.workers.shutdown(wait=True)
        except Exception as e:
            logger.error(e)
        try:
            self.data.close()
        except Exception as e:
            logger.error(e)
        try:
            self.status_bar_thread.join(timeout=1)
        except Exception:
            pass
