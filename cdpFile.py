import shlex
import subprocess
import uuid
import os

import xlogging

_logger = xlogging.getLogger(__name__)

_cdp_wrapper_path = r'/sbin/aio/cdp_wrapper'


def _get_cmd_result(cmd, error_msg):
    split_cmd = shlex.split(cmd)
    with subprocess.Popen(split_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True) as p:
        stdout, stderr = p.communicate()
    return_code = p.returncode
    if return_code == 0:
        return stdout
    else:
        error_description = '{}，错误码：{}'.format(error_msg, return_code)
        error_debug = '_get_cmd_result call {} api failed. {} || [{}]'.format(cmd, stdout, return_code)
        xlogging.raise_system_error(error_description, error_debug, return_code, _logger)


def _run_cmd(cmd, debug_string, error_msg):
    result = _get_cmd_result(cmd, error_msg)
    _logger.info(debug_string.format(result, cmd))
    return result


def queryTimestampRange(path, discard_dirty_data):
    cmd = r'{} -get_time_range {} {}'.format(_cdp_wrapper_path, path, 'use_flag' if discard_dirty_data else '')
    return _run_cmd(cmd, r'queryTimestampRange result:{} cmd:{}', r'查询CDP文件时间范围失败')


def queryTimestamp(path, timestamp):
    timestamp = '{0}|{1}'.format(timestamp, 'forwards') if ('|' not in timestamp) else timestamp
    timestamp, mode = timestamp.split('|')[0], timestamp.split('|')[1]

    if mode == 'forwards':  # mode: 'forwards', 'backwards'
        cmd = r'{} -locate_time {} {}'.format(_cdp_wrapper_path, path, timestamp)
    else:
        cmd = r'{} -locate_time_back {} {}'.format(_cdp_wrapper_path, path, timestamp)
    return _run_cmd(cmd, r'queryTimestamp result:{} cmd:{}', r'查询CDP文件失败')


def formatTimestamp(timestamp):
    cmd = r'{} -format_time {}'.format(_cdp_wrapper_path, timestamp)
    return _run_cmd(cmd, r'formatTimestamp result:{} cmd:{}', r'格式化CDP时间失败')


def merge(cdp_file, cdp_time_range, disk_bytes, qcow_file, qcow_ident, last_snapshots, nbd_object):
    # cdp_wrapper -merge_qemu nbd_path cdp_file_name time_range qemu_file_name qemu_snapshot  ... diskBytes
    cmd = r'{} -merge_qemu {} {} {}'.format(_cdp_wrapper_path, nbd_object.device_path, cdp_file, cdp_time_range)
    for snapshot in last_snapshots:
        cmd += ' {} {}'.format(snapshot['path'], snapshot['ident'])
    cmd += ' {} {}'.format(qcow_file, qcow_ident)
    cmd += ' {}'.format(disk_bytes)
    return _run_cmd(cmd, r'merge cdp2qcow result:{} cmd:{}', r'合并CDP文件失败')


def mergeFiles(config):
    # cdp_wrapper -merge_cdp disk_bytes new_cdp_file_name_pre cdp_file_name0 cdp_file_name1 ...
    cmd = r'{} -merge_cdp {} {}'.format(_cdp_wrapper_path, config['disk_bytes'], config['cdp_file_path_pre'])
    for file_path in config['cdp_files']:
        cmd += r' {}'.format(file_path)
    return _run_cmd(cmd, r'merge cdp files result:{} cmd:{}', r'合并CDP文件流失败')


def cut(config):
    # cdp_wrapper -cut_cdp disk_bytes new_cdp_file_name cdp_file_name cdp_time_range
    cmd = r'{} -cut_cdp {} {} {} {}'.format(
        _cdp_wrapper_path, config['disk_bytes'], config['new_path'], config['path'], config['range'])
    return _run_cmd(cmd, r'merge cdp files result:{} cmd:{}', r'拆分CDP文件失败')


def get_bitmap(cdp_file, cdp_time_range):
    map_file = '{}.{}_{}.binmap'.format(cdp_file, cdp_time_range, uuid.uuid4().hex)
    try:
        cmd = r'{} -cdp_bmf {} {} {}'.format(_cdp_wrapper_path, cdp_file, cdp_time_range, map_file)
        _run_cmd(cmd, r'get cdp bit map result:{} cmd:{}', r'获取CDP文件位图失败')
        with open(map_file, 'rb') as f:
            bitmap = bytearray(f.read())
    finally:
        if os.path.exists(map_file):
            os.remove(map_file)
    return bitmap
