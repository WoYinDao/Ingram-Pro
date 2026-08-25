"""Data pipeline: IP generation, result writing, progress tracking."""
import hashlib
import itertools
import os
import time
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from threading import Lock, RLock, Thread

from loguru import logger

from .utils import common, timer, net


@common.singleton
class Data:

    def __init__(self, config):
        self.config = config
        self.create_time = timer.get_time_stamp()
        self.runned_time = 0
        self.taskid = hashlib.md5(
            (self.config.in_file + self.config.out_dir).encode("utf-8")
        ).hexdigest()
        self.total = 0
        self.done = 0
        self.found = 0
        self.total_lock = Lock()
        self.found_lock = Lock()
        self.done_lock = Lock()
        self.vulnerable_lock = Lock()
        self.not_vulneralbe_lock = Lock()
        self.state_lock = Lock()
        self.preprocess()

    def _load_state_from_disk(self):
        if self.config.no_resume:
            return
        state_file = os.path.join(self.config.out_dir, f".{self.taskid}")
        if os.path.exists(state_file):
            with open(state_file, "r") as f:
                if line := f.readline().strip():
                    _done, _found, _runned_time = line.split(",")
                    self.done = int(_done)
                    self.found = int(_found)
                    self.runned_time = float(_runned_time)

    def _cal_total(self):
        with open(self.config.in_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if (s := line.strip()) and not s.startswith("#"):
                    try:
                        self.add_total(net.get_ip_seg_len(s))
                    except Exception as e:
                        logger.warning(f"skip bad target line {s!r}: {e}")

    def _generate_ip(self):
        # Skip the first `done` targets when resuming, then yield the rest.
        # The old loop re-entered the file from the top after the resume point
        # and re-scanned already-finished segments.
        seen = 0
        with open(self.config.in_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if (s := line.strip()) and not s.startswith("#"):
                    try:
                        for ip in net.get_all_ip(s):
                            if seen < self.done:
                                seen += 1
                                continue
                            yield ip
                    except Exception as e:
                        logger.warning(f"skip bad target line {s!r}: {e}")

    def preprocess(self):
        out = self.config.out_dir
        self.vulnerable = open(os.path.join(out, self.config.vulnerable), "a", encoding="utf-8")
        self.not_vulneralbe = open(os.path.join(out, self.config.not_vulnerable), "a", encoding="utf-8")
        self._load_state_from_disk()
        t = Thread(target=self._cal_total)
        t.start()
        self.ip_generator = self._generate_ip()
        t.join()

    def add_total(self, item=1):
        with self.total_lock:
            self.total += item if isinstance(item, int) else sum(item)

    def add_found(self, item=1):
        with self.found_lock:
            self.found += item if isinstance(item, int) else sum(item)

    def add_done(self, item=1):
        with self.done_lock:
            self.done += item if isinstance(item, int) else sum(item)

    def add_vulnerable(self, item):
        with self.vulnerable_lock:
            self.vulnerable.write(",".join(item) + "\n")
            self.vulnerable.flush()

    def add_not_vulnerable(self, item):
        with self.not_vulneralbe_lock:
            self.not_vulneralbe.write(",".join(item) + "\n")
            self.not_vulneralbe.flush()

    def record_running_state(self, force=False):
        # Throttle to every 20 targets during the scan; force=True always writes
        # so Ctrl+C / exit does not lose the last partial batch.
        if not force and self.done % 20 != 0:
            return
        elapsed = self.runned_time + timer.get_time_stamp() - self.create_time
        state = os.path.join(self.config.out_dir, f".{self.taskid}")
        with self.state_lock:
            tmp = state + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(f"{self.done},{self.found},{elapsed}")
            os.replace(tmp, state)

    def close(self):
        """Flush state and close result files. Called by Core._shutdown."""
        try:
            self.record_running_state(force=True)
        except Exception as e:
            logger.error(e)
        for fh in (self.vulnerable, self.not_vulneralbe):
            try:
                fh.close()
            except Exception:
                pass

    def __del__(self):
        try:
            self.close()
        except Exception as e:
            logger.error(e)


@common.singleton
class SnapshotPipeline:

    def __init__(self, config):
        self.config = config
        self.var_lock = RLock()
        self.pipeline = Queue(self.config.th_num * 2)
        self.workers = ThreadPoolExecutor(self.config.th_num)
        snap_dir = os.path.join(self.config.out_dir, self.config.snapshots)
        self.done = len(os.listdir(snap_dir))
        self.task_count = 0
        self.task_count_lock = Lock()

    def put(self, msg):
        with self.task_count_lock:
            self.task_count += 1
        self.pipeline.put(msg)

    def empty(self):
        return self.pipeline.empty()

    def get_done(self):
        with self.var_lock:
            return self.done

    def add_done(self, num=1):
        with self.var_lock:
            self.done += num

    def _snapshot(self, exploit_func, results):
        if res := exploit_func(results):
            self.add_done(res)
        with self.task_count_lock:
            self.task_count -= 1

    def process(self, core):
        while not core.finish():
            try:
                exploit_func, results = self.pipeline.get(timeout=5)
            except Exception:
                continue
            self.workers.submit(self._snapshot, exploit_func, results)
            time.sleep(0.1)
