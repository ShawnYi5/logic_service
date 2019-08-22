import json
import time
import threading
import os

import xlogging

KVM_HOST_START_TIMEOUTS_SECONDS = 60 * 10
FILE_BACKUP_LOGIC_START_TIMEOUTS_SECONDS = 60 * 60

import CustomizedOS
import Utils

_logger = xlogging.getLogger(__name__)


class RemoteProxy(object):

    def __init__(self, host_ip, communicator, logger, check_func=None):
        self._proxy = None
        self._host_ip = host_ip
        self._communicator = communicator
        self.logger = logger
        self.name = '<RemoteProxy {}>'.format(self._host_ip)
        self._locker = threading.Lock()
        self._quit = False
        self._loader_prx = None
        self._prx = None
        self._python_path = r'/usr/bin/python3'
        self._check_func = check_func if check_func else lambda: False
        xlogging.TraceDecorator(logger=self.logger).decorate()
        xlogging.IceExceptionToSystemErrorDecorator(msg_map=list(), logger=self.logger).decorate()

    def set_python_path(self, new_path):
        self._python_path = new_path

    def create(self):
        self._connect(self._host_ip, KVM_HOST_START_TIMEOUTS_SECONDS)
        ip_address = self._config_gateway()
        runner_dir = self._fetch_patch(ip_address)
        self._start_logic(runner_dir)
        self._check_connect(self._host_ip, FILE_BACKUP_LOGIC_START_TIMEOUTS_SECONDS, self._get_prx, False)
        return self._prx

    def _connect(self, ip, timeout_seconds):
        self._check_connect(ip, timeout_seconds, self._get_loader_prx, True)
        self._ip = ip

    def _fetch_patch(self, ip_address):
        self._check_func()
        runner_dir = '/opt/runner'
        cmd = r'mkdir -p {runner_dir} ; cd {runner_dir} ; ' \
              r'/usr/bin/icepatch2client -t' \
              r' --IcePatch2Client.Proxy="IcePatch2/server:tcp -h {ip_address} -p 20090"' \
              r' .'.format(ip_address=ip_address, runner_dir=runner_dir)

        self.logger.info('fetch_patch cmd : {}'.format(cmd))
        try:
            rc = json.loads(self._get_loader_prx().popen(json.dumps({
                'async': False, 'shell': True, 'cmd': cmd, 'work_dir': None, 'timeouts_seconds': 60 * 2
            })))
        except Exception as e:
            xlogging.raise_system_error(r'配置备份代理失败', 'fetch_patch {}'.format(e), 1, logger=self.logger)
            raise  # fix pycharm warn

        logger_msg = r'fetch_patch rc : {}'.format(rc)

        if rc['returned_code'] != 0:
            xlogging.raise_system_error(r'配置备份代理失败', logger_msg, 1, logger=self.logger)
        else:
            self.logger.info(logger_msg)

        return runner_dir

    def _start_logic(self, runner_dir):
        self._check_func()
        work_dir = os.path.join(runner_dir, 'agent_application')
        cmd = r'{} application_main.py'.format(self._python_path)
        self.logger.info('fetch_patch cmd : {}       work_dir : {}'.format(cmd, work_dir))

        try:
            rc = json.loads(self._get_loader_prx().popen(json.dumps({
                'async': True, 'shell': False, 'cmd': cmd, 'work_dir': work_dir, 'timeouts_seconds': None
            })))
        except Exception as e:
            xlogging.raise_system_error(r'启动备份代理失败', 'start_logic {}'.format(e), 1, logger=self.logger)
            raise  # fix pycharm warn

        logger_msg = r'start_logic rc : {}'.format(rc)
        if not rc['pid']:
            xlogging.raise_system_error(r'启动备份代理失败', logger_msg, 1, logger=self.logger)
        else:
            self.logger.info(logger_msg)

    def _get_loader_prx(self, ip=None):
        if self._loader_prx is None and ip:
            self._loader_prx = CustomizedOS.MiniLoaderPrx.checkedCast(
                self._communicator.stringToProxy('loader : tcp -h {} -p 10000'.format(ip)))
        assert self._loader_prx
        return self._loader_prx

    def _get_prx(self, ip=None):
        if self._prx is None and ip:
            self._prx = Utils.CallablePrx.checkedCast(
                self._communicator.stringToProxy('callable : tcp -h {} -p 10001'.format(ip)))
        assert self._prx
        return self._prx

    def _check_connect(self, ip, timeout_seconds, check_fn, change_name):
        end_time = time.time() + timeout_seconds
        last_e = None
        loop_count = 1

        while time.time() < end_time:
            self._check_func()
            loop_count += 1
            time.sleep(1)
            try:
                check_fn(ip)
                if change_name:
                    self.name = '{} {}'.format(self.name, ip)
                return
            except Exception as e:
                last_e = r'{} connect {} failed {} will retry : {}'.format(check_fn.__name__, ip, e,
                                                                           int(end_time - time.time()))
                if loop_count % 10 == 0:
                    self.logger.debug(last_e)

        xlogging.raise_system_error(r'启动备份代理超时', last_e, 1, logger=self.logger)

    def _config_gateway(self):
        self._check_func()
        prx = self._get_loader_prx()
        connection = prx.ice_getConnection()
        connection_info = connection.getInfo()
        ip_address = connection_info.localAddress

        cmd = 'ip route del default ; ip route add default via {}'.format(ip_address)
        self.logger.info('config_gateway cmd : {}'.format(cmd))
        try:
            rc = json.loads(prx.popen(json.dumps({
                'async': False, 'shell': True, 'cmd': cmd, 'work_dir': None, 'timeouts_seconds': 60 * 2
            })))
        except Exception as e:
            xlogging.raise_system_error(r'配置备份代理网络参数失败', 'config_gateway {}'.format(e), 1, logger=self.logger)
            raise  # fix pycharm warn

        logger_msg = r'config_gateway rc : {}'.format(rc)
        if rc['returned_code'] != 0:
            xlogging.raise_system_error(r'配置备份代理网络参数失败', logger_msg, 1, logger=self.logger)
        else:
            self.logger.info(logger_msg)

        return ip_address


class ModuleMapper(object):

    def __init__(self, module_path, module_name, proxy, logger, args_dict=None, raw_input=b''):
        self._module_path = module_path
        self._module_name = module_name
        self._args_dict = args_dict
        self._raw_input = raw_input
        self._ins_id = None
        self._proxy = proxy
        self.logger = logger
        xlogging.TraceDecorator(logger=self.logger).decorate()
        xlogging.IceExceptionToSystemErrorDecorator(msg_map=list(), logger=self.logger).decorate()

    def __str__(self):
        return '<RemoteHelper {} {}>'.format(self._module_path, self._module_name)

    def __del__(self):
        if self._ins_id:
            args = {
                'action': 'del_instance',
                'module_or_instance': self._ins_id
            }
            self._proxy.execute(json.dumps(args), '{}', b'')
        self._ins_id = None

    def execute(self, func_name, args_dict=None, raw_input=b''):
        args = {
            'action': 'call_function',
            'module_or_instance': self._get_inst_id(),
            'func_name': func_name
        }
        args_dict = args_dict if args_dict else dict()
        return self._proxy.execute(json.dumps(args), json.dumps(args_dict), raw_input)

    def _get_inst_id(self):
        if not self._ins_id:
            args = {
                'action': 'new_instance',
                'module_or_instance': self._module_path,
                'func_name': self._module_name
            }
            args_dict = self._args_dict if self._args_dict else dict()
            self._ins_id, _ = self._proxy.execute(json.dumps(args), json.dumps(args_dict), self._raw_input)
        return self._ins_id


class FunctionMapper(object):

    def __init__(self, proxy, logger):
        self._proxy = proxy
        self.logger = logger

        xlogging.TraceDecorator(logger=self.logger).decorate()
        xlogging.IceExceptionToSystemErrorDecorator(msg_map=list(), logger=self.logger).decorate()

    def execute(self, module_path, func_name, args_dict=None, raw_input=b''):
        args = {
            'action': 'call_function',
            'module_or_instance': module_path,
            'func_name': func_name
        }
        args_dict = args_dict if args_dict else dict()
        return self._proxy.execute(json.dumps(args), json.dumps(args_dict), raw_input)


if __name__ == '__main__':
    import logging
    import pdb
    import Ice
    import sys

    pdb.set_trace()

    _logger.addHandler(logging.StreamHandler())

    initData = Ice.InitializationData()
    initData.properties = Ice.createProperties()
    initData.properties.setProperty(r'Ice.LogFile', r'/var/log/aio/logic_service_ice.log')
    initData.properties.setProperty(r'Ice.ThreadPool.Server.Size', r'8')
    initData.properties.setProperty(r'Ice.ThreadPool.Server.SizeMax', r'64')
    initData.properties.setProperty(r'Ice.ThreadPool.Server.StackSize', r'8388608')
    initData.properties.setProperty(r'Ice.ThreadPool.Client.Size', r'8')
    initData.properties.setProperty(r'Ice.ThreadPool.Client.SizeMax', r'64')
    initData.properties.setProperty(r'Ice.ThreadPool.Client.StackSize', r'8388608')
    initData.properties.setProperty(r'Ice.Default.Host', r'localhost')
    initData.properties.setProperty(r'Ice.Warn.Connections', r'1')
    initData.properties.setProperty(r'Ice.ACM.Heartbeat', r'3')
    initData.properties.setProperty(r'Ice.ThreadPool.Client.ThreadIdleTime', r'0')
    initData.properties.setProperty(r'Ice.ThreadPool.Server.ThreadIdleTime', r'0')

    _communicator = Ice.initialize(sys.argv, initData)

    # create proxy
    _proxy = RemoteProxy('172.29.130.1', _communicator, _logger, lambda: False).create()

    # instance remote class `Foo` and call its func
    _remote_ins = ModuleMapper('demo', 'Foo', _proxy, _logger)
    _remote_ins.execute('hello', {'name': 'xiao ming'}, bytearray(100))
    _remote_ins.execute('get_name', {}, b'')

    # call remote func
    _call_proxy = FunctionMapper(_proxy, _logger)
    _call_proxy.execute('demo', 'foo')
    print('end...')
