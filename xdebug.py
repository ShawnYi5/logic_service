import json
import os
import sys
import threading
import time
import traceback

import xlogging

_logger = xlogging.getLogger(__name__)

PYCHARM_DEBUG_FILE = r'/var/aio/LogicService/pycharm-debug-py3k.egg'
# {"address":"172.16.6.80", "cfg":{"port":21000}}
PYCHARM_DEBUG_CONFIG = r'/var/aio/LogicService/pycharm-debug-py3k.json'

if os.path.isfile(PYCHARM_DEBUG_FILE) and os.path.isfile(PYCHARM_DEBUG_CONFIG):
    sys.path.append(PYCHARM_DEBUG_FILE)
    import pydevd

    with open(PYCHARM_DEBUG_CONFIG) as f:
        pycharm_debug_cfg = json.load(f)
    _logger.info(r'pycharm_debug_cfg : {}'.format(pycharm_debug_cfg))

    pydevd.settrace(pycharm_debug_cfg['address'], **pycharm_debug_cfg['cfg'])


class XDebugHelper(threading.Thread):
    TIMER_INTERVAL_SECS = 10

    DUMP_ALL_THREAD_STACK_FILE = r'/var/aio/LogicService/dump_stack'

    def __init__(self):
        threading.Thread.__init__(self)
        self.pycharm_debug = False

    def run(self):
        while True:
            try:
                self.do_run()
                break
            except Exception as e:
                _logger.error(r'XDebugHelper run Exception : {}'.format(e), exc_info=True)

    def do_run(self):
        while True:
            time.sleep(self.TIMER_INTERVAL_SECS)

            self.dump_all_thread_stack_when_file_exist()

            # self.stop_pycharm_debug()
            # self.begin_pycharm_debug()

    def dump_all_thread_stack_when_file_exist(self):
        try:
            if not os.path.isfile(self.DUMP_ALL_THREAD_STACK_FILE):
                return
            self.dump_all_thread_stack()
        except Exception as e:
            _logger.error(r'XDebugHelper dump_all_thread_stack_when_file_exist Exception : {}'.format(e), exc_info=True)

    def stop_pycharm_debug(self):
        try:
            if self.pycharm_debug and (not os.path.isfile(PYCHARM_DEBUG_CONFIG)):
                pydevd.stoptrace()
                self.pycharm_debug = False
        except Exception as e:
            _logger.error(r'XDebugHelper stop_pycharm_debug Exception : {}'.format(e), exc_info=True)

    def begin_pycharm_debug(self):
        try:
            if self.pycharm_debug or (not os.path.isfile(PYCHARM_DEBUG_FILE)) \
                    or (not os.path.isfile(PYCHARM_DEBUG_CONFIG)):
                return

            with open(PYCHARM_DEBUG_CONFIG) as f:
                debug_cfg = json.load(f)
            _logger.info(r'pycharm_debug_cfg : {}'.format(debug_cfg))

            pydevd.settrace(debug_cfg['address'], **debug_cfg['cfg'])

            self.pycharm_debug = True
        except Exception as e:
            _logger.error(r'XDebugHelper begin_pycharm_debug Exception : {}'.format(e), exc_info=True)

    @staticmethod
    def dump_all_thread_stack():
        id2name = dict((th.ident, th.name) for th in threading.enumerate())
        for thread_id, stack in sys._current_frames().items():
            _logger.info('Thread {} - {}\n>{}'
                         .format(thread_id, id2name[thread_id], '>'.join(traceback.format_stack(stack))))
