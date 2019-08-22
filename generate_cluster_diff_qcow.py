import json
import os
import queue
import subprocess
import threading
import time
import uuid

import xlogging

_logger = xlogging.getLogger(__name__)


@xlogging.convert_exception_to_value(None)
def _remove_no_exception(path):
    if os.path.exists(path):
        os.remove(path)


class MainLogic(object):

    def __init__(self, params):
        self._name = 'cluster_diff_{}'.format(uuid.uuid4().hex[:6])
        self._params = params
        self._work_params = queue.Queue()
        for params in self._params['qcows']:
            self._work_params.put(params)
        self._works = list()
        self._error = None
        self._end_flag = object()

    def work(self):
        self._start_worker()
        self._wait_consumed()
        self._stop_worker()

        if self._error:
            raise self._error
        else:
            pass  # successful

    def _stop_worker(self):
        _logger.info('_stop_worker {} begin'.format(self._name))
        for _ in self._works:
            self._work_params.put(self._end_flag)
        for wk in self._works:
            wk.join()
        _logger.info('_stop_worker {} end'.format(self._name))

    def _wait_consumed(self):
        _logger.info('_wait_consumed begin {} : {} {}'.format(self._name, self._work_params.empty(), self._error))
        while (not self._work_params.empty()) and (not self._error):
            time.sleep(1)
        _logger.info('_wait_consumed end {} : {} {}'.format(self._name, self._work_params.empty(), self._error))

    def _start_worker(self):
        for i in range(min(self._work_params.qsize(), 4)):
            name = '{}-{}'.format(self._name, i)
            wk = threading.Thread(name=name, target=self._worker,
                                  args=(name,))
            wk.setDaemon(True)
            wk.start()
            self._works.append(wk)

    def _worker(self, name):
        _logger.info('{} worker begin'.format(name))
        while not self._error:
            params = self._work_params.get()
            tmp_file = '/tmp/cluster_gen_qcow{}.json'.format(uuid.uuid4().hex)
            try:
                if params is self._end_flag:
                    break
                with open(tmp_file, 'w') as f:
                    json.dump(params, f)
                cmd = 'python /sbin/aio/logic_service/generate_cluster_diff_qcow_task.py {}'.format(tmp_file)
                with subprocess.Popen(cmd,
                                      shell=True,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,
                                      universal_newlines=True) as p:
                    stdout, stderr = p.communicate()
                if p.returncode != 0:
                    xlogging.raise_system_error('生成QCOW失败', 'error:{}|{}|{}'.format(p.returncode, stdout, stderr), 3073)
            except Exception as e:
                self._error = e
            finally:
                _remove_no_exception(tmp_file)
                self._work_params.task_done()
        _logger.info('{} worker end'.format(name))


if __name__ == '__main__':
    test_args = {
        "qcows": [{
            "host_ident": "0150731cf853471a9c75f9003834adb2",
            "disk_id": 0,
            "source_snapshots": [{
                "path": "/home/mnt/nodes/b7f1e05d286d4aad933fd49ff8eeceb9/images/fa6a075a1afc4731b6e205ea12f51d73/24d37840c1494eb5b2cf4c31a187586a.qcow",
                "ident": "01376bc7b0534051af2ec57a9ec98776"
            }
            ],
            "hash_path": "/tmp/new.hash",
            "new_qcow": {
                "path": "/tmp/new.qcow",
                "ident": "1234567890",
                "disk_bytes": 100 * 1024 ** 3
            },
            "new_qcow_hash": '/tmp/new_qcow_hash'
        }
        ]
    }
    MainLogic(test_args).work()
