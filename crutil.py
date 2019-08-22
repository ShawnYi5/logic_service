# coding:utf-8
import os
import logging
import pdb
import subprocess
import sys
import time
from logging.handlers import RotatingFileHandler

try:
    from subprocess import getstatusoutput
except ImportError:
    from commands import getstatusoutput


def add_logger_consoleout(logger):
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter('%(asctime)-20s %(name)-10s %(levelname)-7s: %(message)s'))
    logger.addHandler(handler)


def sf_logger(name):
    if not os.path.exists(os.path.join('/tmp', 'outfc')):
        print('current logger model : normal')
        return None
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    log_fn = os.path.join('/tmp', 'log', name + '.log')
    mkdir_p(os.path.dirname(log_fn))
    handler = RotatingFileHandler(filename=log_fn, mode='a', maxBytes=31457280, backupCount=5)
    handler.setFormatter(logging.Formatter("%(asctime)-20s %(name)-10s %(levelname)-7s: %(message)s"))
    logger.addHandler(handler)
    add_logger_consoleout(logger)
    return logger


def get_logger(name):
    try:
        import xlogging
        logger = xlogging.getLogger(name)
        # print('bootinit using xlogging logger')
        return logger
    except ImportError as e:
        pass
    return sf_logger(name)


class DynamicLogger():

    def __init__(self, name):
        self.name = name
        self._xlogger = get_logger(name)
        self._sflogger = sf_logger('c-'+name)

    def _get_logger(self):
        if os.path.exists(os.path.join('/tmp', 'outfc')):
            if self._sflogger is None:
                self._sflogger = sf_logger('c-' + self.name)
            return self._sflogger
        else:
            return self._xlogger

    # noinspection PyMethodMayBeStatic
    def _format_msg(self, msg):
        try:
            line = sys._getframe(2).f_lineno
            func = sys._getframe(2).f_code.co_name
            msg = '{ln:>4} : {fn} : {mg}'.format(ln=line, fn=func, mg=msg)
        except Exception as ex:
            pass
        return msg

    def debug(self, msg, *args, **kwargs):
        self._get_logger().debug(self._format_msg(msg), *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        self._get_logger().info(self._format_msg(msg), *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self._get_logger().warning(self._format_msg(msg), *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self._get_logger().error(self._format_msg(msg), *args, **kwargs)

    def exception(self, msg, *args, **kwargs):
        self._get_logger().exception(self._format_msg(msg), *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        self._get_logger().critical(self._format_msg(msg), *args, **kwargs)


def unrefer_arg(arg):
    return arg


def dbg_break():
    if os.path.exists('crunch_debug'):
        pdb.set_trace()


def dbg_stop(stop_file, wait_interval, logger, debug_msg):
    while os.path.exists(stop_file):
        logger.debug('{msg}'.format(msg=debug_msg))
        time.sleep(wait_interval)


def exec_chmod(path, mode):
    cmd = 'chmod {mode} {path}'.format(mode=mode, path=path)
    tmp_res, out_str = wrap_getstatusoutput(cmd)
    if tmp_res != 0:
        return False, out_str

    return True, out_str


def exec_shell_cmd_dir(cmd, curr_dir):
    """
    execute shell cmd
    :param cmd: shell cmd line
    :param curr_dir: cmd work dir
    :return: the output lines
    """
    out_lines = list()
    p = subprocess.Popen(cmd,
                         stdout=subprocess.PIPE,
                         universal_newlines=True,
                         shell=True,
                         cwd=curr_dir,
                         stderr=subprocess.PIPE)
    p.wait()

    for line in p.stdout:
        out_lines.append(line.rstrip())

    for line in p.stderr:
        out_lines.append(line.rstrip())

    return p.returncode, out_lines


def exec_shell_cmd_status(cmd):
    """
    execute shell cmd
    :param cmd: shell cmd line
    :return: the output lines
    """
    out_lines = list()
    pcmd = cmd + ' 2>&1'  # cmd line with pipe output
    tmp_int, tmp_str = getstatusoutput(pcmd)
    if len(tmp_str) > 0:
        out_lines = tmp_str.splitlines()
    return tmp_int, out_lines


def wrap_getstatusoutput(cmd):
    """
    for python 2.6, 2.7
    :param cmd:
    :return:
    """
    return getstatusoutput(cmd)


def find_in_lines(lines, cstr):
    """
    find words
    :param cstr: charactor string to find
    :param lines: lines list
    :return:
    """
    for line in lines:
        if -1 != line.find(cstr):
            return True, line
    return False, ''


def mkdir_p(dir_path):
    if len(dir_path) > 0:
        if os.path.exists(dir_path):
            return True, 'already exists'
        cmd = 'mkdir -p {}'.format(dir_path)
        _, out_str = wrap_getstatusoutput(cmd)
        if os.path.exists(dir_path):
            return True, 'successed'
        else:
            return False, out_str
    return False, 'input len(dir_path) is 0'


def cp_f(src, tar):
    if len(src) > 0 and len(tar) > 0:
        import platform
        if platform.system() == 'Windows':
            cmd = 'copy {} {} /y'.format(src, tar)
        else:
            cmd = '\cp {} {}'.format(src, tar)
        tmp_res, out_str = wrap_getstatusoutput(cmd)
        if tmp_res != 0:
            return False, out_str
        if os.path.exists(tar):
            return True, 'successed'
        else:
            return False, out_str
    return False, 'src or tar file invalid'


def s_link(target, link_name):
    cmd = 'ln -sf {} {}'.format(target, link_name)
    return wrap_getstatusoutput(cmd)


def get_distribver(platform_str):
    s = platform_str.find('with')
    if s != -1:
        s += len('with-')
        if len(platform_str) > s:
            l = platform_str[s:].split('-')
            if 2 < len(l):
                return l[0:2]
    return []


def stdout_fn():
    config = ['[loggers]\n',
              'keys=root,simpleExample\n',
              '\n[handlers]\n',
              'keys=consoleHandler\n',
              '\n[formatters]\n',
              'keys=simpleFormatter\n',
              '\n[logger_root]\n',
              'level=DEBUG\n',
              'handlers=consoleHandler\n',
              '\n[logger_simpleExample]\n',
              'level=DEBUG\n',
              'handlers=consoleHandler\n',
              'qualname=simpleExample\n',
              'propagate=0\n',
              '\n[handler_consoleHandler]\n',
              'class=StreamHandler\n',
              'level=DEBUG\n',
              'formatter=simpleFormatter\n',
              'args=(sys.stdout,)\n',
              '\n[formatter_simpleFormatter]\n',
              'format=%(asctime)s - %(name)s - %(levelname)s - %(message)s\n',
              'datefmt=\n']
    fn = r'crunch.log.config'
    fn = os.path.join(os.getcwd(), fn)
    with open(fn, 'w+') as fd:
        fd.writelines(config)
    return fn


# ======================================================================================================================
# test main
# ======================================================================================================================


if __name__ == "__main__":
    # print('befor:{}'.format(os.getcwd()))
    # g_status, g_outlines = exec_shell_cmd_dir('dir', r'E:\temp\DebugWait')
    # print('exec_cmd: cmd={}, out={}'.format(g_status, g_outlines))
    # print('after:{}'.format(os.getcwd()))

    logger1 = get_logger('crunch:initramfs')
    logger1.debug('我是一个中国人')
    logger2 = get_logger('logger2')
    logger2.debug('我是一个中国人, 我是中国重庆人')
    logger3 = get_logger('logger3')
    logger3.debug('我是一个中国人, 我是中国重庆人, 我是重庆九龙坡区人')
    logger4 = get_logger('logger4')
    logger4.debug('我是一个中国人, 我是中国重庆人, 我是重庆九龙坡区人, 我是九龙坡区石桥铺街道人')
