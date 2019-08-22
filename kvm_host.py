import datetime
import json
import os
import sys
import time
from io import StringIO

import paramiko
from paramiko import SSHClient

g_dbg = 0
if g_dbg == 0:
    import xlogging
else:
    import logging as xlogging

_logger = xlogging.getLogger(__name__)


class kvm_host_Popen(object):
    def __init__(self, pid, kvm_host_inst):
        self.pid = pid
        self.kvm_host_inst = kvm_host_inst

    def check_pid(self, kvm_host_inst, pid, timeout_secondes=600):
        cmd = "ps -aux|awk '{{print $2}}' |grep {}".format(pid)
        timeout_datetime = datetime.datetime.now() + datetime.timedelta(seconds=timeout_secondes)
        while datetime.datetime.now() <= timeout_datetime:
            try:
                stdin, stdout, stderr = kvm_host_inst.remote_exe_cmd(cmd)
                one_line = stdout.readline()
                if -1 != one_line.find(pid):
                    return True
                return False
            except Exception as e:
                _logger.error('check_pid failed : {}'.format(e))
            time.sleep(10)
        xlogging.raise_system_error(r'远程主机通信失败', r'check_pid timeout {}'.format(self.kvm_host_inst.name), 0, _logger)

    def fetch_return_code(self, kvm_host_inst, file_name):
        try:
            returned_txt_path = self.kvm_host_inst.get_full_path_by_relative(file_name)
            cmd = "cat {} ".format(returned_txt_path)
            stdin, stdout, stderr = kvm_host_inst.remote_exe_cmd(cmd)
            one_line = stdout.readline()
            return_from_file = int(one_line.strip())
            return return_from_file
        except Exception as e:
            xlogging.raise_system_error(r'获取程序运行返回值失败', r'returncode failed {}'.format(e), 0, _logger)

    # 获得进程返回值
    # 如果进程正在执行中，那么等待进程结束
    # 如果等待进程结束过程中，与远端主机失去链接，使用 xlogging.raise_system_error 抛出日志可用异常
    @property
    def returncode(self):
        while self.check_pid(self.kvm_host_inst, self.pid):
            time.sleep(3)
        return_from_file = self.fetch_return_code(self.kvm_host_inst, 'returned.txt')
        return return_from_file


class kvm_host(object):
    def __init__(self, connect_config):
        try:
            _password_login = connect_config.get('password_login', None)
            if _password_login:
                # 使用用户名密码登陆
                self._password_login_name = connect_config['password_login']['name']
                self._password_login_pwd = connect_config['password_login']['pwd']
                self._public_key_login_private = None
                self._public_key_login_pwd = None
            else:
                # 使用公钥登陆
                self._password_login_name = None
                self._password_login_pwd = None
                self._public_key_login_private = connect_config['public_key_login']["key"]
                self._public_key_login_pwd = connect_config['public_key_login']["pwd"]

            self._host_ip = connect_config['remote_ip']
            self._host_port = connect_config['remote_port']

            # 为了区分多进程，此目录必须要有。
            self._host_dir = connect_config['remote_dir']
            if self._host_dir is None:
                xlogging.raise_system_error(r'连接远程主机,系统初始化路径失败',
                                            r'kvm_host init failed self._host_dir is None', 0, _logger)

            if 0 == len(self._host_dir):
                xlogging.raise_system_error(r'连接远程主机，系统初始化路径失败',
                                            r'kvm_host init failed 0 == len(self._host_dir)', 0, _logger)

            # paramiko.util.log_to_file(r'/var/log/aio/paramiko.log')
            self.ssh = SSHClient()
            if _password_login:
                self.ssh.load_system_host_keys()
                self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.ssh.connect(hostname=self._host_ip, port=self._host_port, username=self._password_login_name,
                                 password=self._password_login_pwd)
            else:
                self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                # 保存密码到临时文件。
                with open(r'/tmp/remote_host_debug', 'w') as key_file_handle:
                    key_file_handle.write(self._public_key_login_private)
                fake_key_file_object = StringIO(self._public_key_login_private)
                con_key = paramiko.RSAKey.from_private_key(fake_key_file_object)
                self.ssh.connect(hostname=self._host_ip, port=self._host_port, pkey=con_key)

            _logger.info(r'kvm_host init end {}'.format(self.name))
        except Exception as e:
            _logger.error(r'kvm_host init failed {}'.format(e), exc_info=True)
            xlogging.raise_system_error(r'连接远程主机失败', r'kvm_host init failed {}'.format(e), 0, _logger)

    def __del__(self):
        try:
            _logger.info(r'kvm_host del start {}'.format(self.name))
            if self.ssh is not None:
                self.ssh.close()
        except Exception as e:
            _logger.error(r'kvm_host del failed {}'.format(e), exc_info=True)

    def get_full_path_by_relative(self, remote_relative_path):
        return os.path.join(self._host_dir, remote_relative_path)

    # 将本地文件推送到self._host_dir目录中
    # 如果推送失败，使用 xlogging.raise_system_error 抛出日志可用异常
    def push_file(self, local_file_path, remote_relative_path):
        try:
            mkdir_cmd = r'mkdir -p "{}"'.format(os.path.split(self.get_full_path_by_relative(remote_relative_path))[0])
            self.ssh.exec_command(mkdir_cmd)
            # Issue #2057 远程文件夹不存在
            time.sleep(2)
            sftp = self.ssh.open_sftp()
            sftp.put(local_file_path, self.get_full_path_by_relative(remote_relative_path))
            sftp.close()
        except Exception as e:
            xlogging.raise_system_error(r'推送文件失败', r'push_files failed {}'.format(e), 0, _logger)

    # 从self._host_dir目录中拉取文件到本地
    # 如果拉去失败，使用 xlogging.raise_system_error 抛出日志可用异常
    def pull_file(self, remote_relative_path, local_file_path):
        try:
            sftp = self.ssh.open_sftp()
            sftp.get(self.get_full_path_by_relative(remote_relative_path), local_file_path)
            sftp.close()
        except Exception as e:
            xlogging.raise_system_error(r'获取文件失败', r'push_files failed {}'.format(e), 0, _logger)

    @property
    def host_dir(self):
        return self._host_dir

    @property
    def name(self):
        return r'{}:{}-{}'.format(self._host_ip, self._host_port, self._host_dir)

    # 在Host中启动进程，功能类似 subprocess.Popen
    # 当在Host中启动进程能够获得pid后就返回 kvm_host_Popen 对象
    # 如果在启动过程失败，使用 xlogging.raise_system_error 抛出日志可用异常
    # 支持“同时”启动多个进程
    # 将进程的输出重定向到远端主机的文件中， stderr、stdout 为相对与self._host_dir的路径
    def Popen(self, cmd, std_output=('stderr.out', 'stdout.out')):
        stderr = self.get_full_path_by_relative(std_output[0])
        stdout = self.get_full_path_by_relative(std_output[1])
        return_log = self.get_full_path_by_relative('returned.txt')
        try:
            new_cmd = 'cd "{}"; echo $$ && {} > {} 2>&1; echo $? > {}'.format(self._host_dir, cmd, stdout, return_log)
            stdin, stdout, stderr = self.ssh.exec_command(new_cmd)
            pid = stdout.readline().strip()
            return kvm_host_Popen(pid, self)
        except Exception as e:
            xlogging.raise_system_error(r'打开进程失败', r'Popen failed {}'.format(e), 0, _logger)

    def remote_exe_cmd(self, cmd):
        try:
            stdin, stdout, stderr = self.ssh.exec_command(cmd)
            return stdin, stdout, stderr
        except Exception as e:
            _logger.error('call {} remote_exe_cmd failed : {}.'.format(self.name, e))
            raise e

    # {'ret_num': 10, 'path': '/tmp/nbd10'}
    def get_remote_nbd_info(self, exe_path, min_index, max_index, file_dir='/tmp'):
        try:
            cmd = '{} func_get_nbd_num {} {} "{}"'.format(exe_path, min_index, max_index, file_dir)
            stdin, stdout, stderr = self.remote_exe_cmd(cmd)
            lines = self.get_lines_by_std(stdout)
            for one_line in lines:
                if -1 != one_line.find(r'{"ret_num":'):
                    ret_dict = json.loads(one_line.strip())
                    return ret_dict
            return min_index - 1
        except Exception as e:
            _logger.error('call {} get_remote_nbd_info failed : {}.'.format(self.name, e), exc_info=True)
            return None

    def func_check_readable(self, exe_path, dev_path, offset, bytes_len):
        try:
            cmd = '{} func_check_readable {} {} {}'.format(exe_path, dev_path, offset, bytes_len)
            stdin, stdout, stderr = self.remote_exe_cmd(cmd)
            lines = self.get_lines_by_std(stdout)
            for one_line in lines:
                if -1 != one_line.find('func_check_readable:success'):
                    return True
            return False
        except Exception as e:
            _logger.error('call {} func_check_readable failed : {}.'.format(self.name, e), exc_info=True)
            return None

    def print_lines(self, lines):
        try:
            for line in lines:
                print(line.strip())
        except Exception as e:
            _logger.error('call {} print_lines failed : {}.'.format(self.name, e), exc_info=True)

    def get_lines_by_std(self, std):
        try:
            lines = list()
            while True:
                line = std.readline()
                if (line is not None) and (len(line) != 0):
                    lines.append(line)
                else:
                    break
            return lines
        except Exception as e:
            _logger.error('call {} get_lines_by_std failed : {}.'.format(self.name, e), exc_info=True)
            return []

    def print_std(self, std):
        try:
            lines = self.get_lines_by_std(std)
            self.print_lines(lines)
        except Exception as e:
            _logger.error('call {} print_std failed : {}.'.format(self.name, e), exc_info=True)


def get_logger_file_name(prefix):
    prefix = prefix.replace('/', '_').strip()
    return '{}_stderr.out'.format(prefix), '{}_stdout.out'.format(prefix)


def kvm_host_exec_helper(kvm_host_object, cmd, logger_prefix, logger_object):
    logger_object.info(r'begin [{}] on [{}]'.format(cmd, kvm_host_object.name))
    cmd_runner = kvm_host_object.Popen(cmd, get_logger_file_name(logger_prefix))
    logger_object.info("pid {} | [{}] on [{}]".format(cmd_runner.pid, cmd, kvm_host_object.name))
    return_code = cmd_runner.returncode
    logger_object.info("pid {} return : {}  {} on {} ".format(cmd_runner.pid, return_code, cmd, kvm_host_object.name))
    return return_code


if __name__ == "__main__":
    xlogging.basicConfig(stream=sys.stdout, level=xlogging.NOTSET)
    con_config = {'remote_ip': '172.16.1.199', 'remote_port': 22, 'remote_dir': '/home/wolf',
                  'password_login': {'name': 'wolf', 'pwd': 'f'}}
    # con_config = {'host': {'ip': '172.16.1.199', 'port': 22, 'dir': '/home/wolf'}, 'public_key_login':
    #     '-----BEGIN RSA PRIVATE KEY-----\n'
    #     'MIIEpQIBAAKCAQEAwEpCBOY2qiu6cYVWjNnmGAq74g5uY3ZHLJt/7aVDXITbrv4y\n'
    #     'zBrDA4vCgMz8wZuMdjatSpzsw5/MP9e82Kf5/5HxwYkedeE7zl5vx0XDJxQnpNPj\n'
    #     '3OgCXjIM+AWSDz5Tb5V9gSciYm62FKOeDKZRacH6f9/bCXDnCF7EvEZLEf5aqWdB\n'
    #     'bG4xXh26NUlQ5Q9FjqbD3HyOquu0oxcwOZwFIJt8kQ3wu3ytO+AgiQyJ48xG/ALz\n'
    #     'd+oQ9YcXbMM86hQFJzAAji+jTaBoGJi4oh+GsDKCsgcFqkRmw1QupGv4pOsB2otU\n'
    #     '0Cc7qn5CmgUYcldONmqKrZfw78h4yGtRmi+lhQIDAQABAoIBAQCNa0+omMNlXemu\n'
    #     'Kblgt7Sww9wwQhrPjaKE3Qw19BBZj+Cdj5g+YgRArF3tKlVN8p9YJZhHQqgiq3il\n'
    #     'D350/P0xB938T2MWoQLCINQmg1kmeX06jReNVRjAvCCrnDUyfs0QSKpX/Tcdm3zQ\n'
    #     'KxFHDl7b3+zidPl7tQxFLKWWLkBxxw4W99xqEUj8elrUw7f7Thi+f6pr8ihsvL7i\n'
    #     '0n8/H+Doj2qYGrnEudDKUGzBYJuP1fxkfRI33VYBtw2h3ZUpSPuwQH0QIprKwNJs\n'
    #     'FXn+50k2OOhejfyjlqLW6WG0yeNZtTcVk4L50WC0SXoGcAq3+dsoZTdRnEQKg4qW\n'
    #     'hwUVNzvhAoGBAPcqDkeQ6pdPNfodKWzFWoBGcqKMJhfFg4bn6bhjsq3JdnwvKLzJ\n'
    #     '7vTWLY3/huZQJUHi88sSVDNW3FPoRId8hRtEBrpbg4mtcNr7iIUHxzUYjzUyFRaG\n'
    #     'duc0IPfmnbq4x2bAOC7IeH2ubY+hI8h4hxRAXvUD3X1VI8WlkeDPdgmZAoGBAMcq\n'
    #     'BCm1HWgRxCm1hb4BIkCiVvpjpuRFxkafTULiQRrqpK9FRAFVwPSvbvFuH9UAYfoY\n'
    #     'e64cBq2+S6xnNQ0frtnG4gK5mkaVhypsrNOT4S9y0bnM4gKB1S/RVdnXIHcw7vuD\n'
    #     '0KAafk40WoObObJ3/xvRbVSKungoM+RoqHYz72bNAoGBANzb5bqpkhb3HyKKYHPj\n'
    #     'vkUVrmX1mixvwGISZdTwsb99YLUDZwGb6D08DaTvitnPEBvZ80Oo8ziVC3im+mWf\n'
    #     'LUn59ZEdKWMjas8jKRDGrImTkpRUVme0bBeZi0Q5/QPXDceRSCL13EViUmCf+1ut\n'
    #     '5/Z+ttt2Qrs2EysQElSyzaUxAoGAJF7H49XvSNH1wKglhE0wtBzxRUhtccJMMxlk\n'
    #     'QpKO0RuId3lusc+3LPfcirpRldQ8EC/oZiM4FQJrT1CJn5vpklt/an/6bGliBZ1S\n'
    #     '8lBPDxsosYV4wHx1MgZIZz+h7iJBgizQLGyqJB3raZ0vLCg9rhbQoF+1Lbwpvcxe\n'
    #     '9zcEwQECgYEAnPnp4QQo8TgCke/Y80y+g5YTju3Ks7USoa90MboRLOSc5Kocy9Ru\n'
    #     'm+BAaEpB90/3qL1aOFnbOsAa9tK5E6gYd2G8ZYqCdrMYrTVgMVnAv8z+LjZdWUhN\n'
    #     'wW363zT/I8Z2N9B5C1IKDHlXcHLjuzQDxQj3XW6el9jHRvSTtpZaQAw=\n'
    #     '-----END RSA PRIVATE KEY-----'}
    host_class = kvm_host(con_config)
    # host_class.push_files('/home/git_log_2017_05_17-19_55_45.txt','git_log_2017_05_17-19_55_45.txt')
    # host_class.pull_files('git_log_2017_05_17-19_55_45.txt', '/home/git_log_2017_05_17-19_55_45.txt')
    # host_class.get_remote_nbd_info('/home/wolf/tmp/remotehlp.exe', 1, 10, '/home/wolf/tmp/test')
    host_class.func_check_readable('/home/wolf/tmp/remotehlp.exe', '/dev/sda1', 0, 65536)
    kvm_host_Popen_inst = host_class.Popen(' /home/wolf/qemu-kvm-rhev/qemu-2.3.0/qemu-img test24 10')
    return_code = kvm_host_Popen_inst.returncode
    print(return_code)
    print('end')
