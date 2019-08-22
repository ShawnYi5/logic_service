import json
import logging
import os
import threading
import time
import copy
import io
import sys
import net_common
import xlogging
import loadIce
import uuid

_logger = xlogging.getLogger(__name__)

_TMP_VM_DIR = '/home/ext.aio/tmp/'


def check_is_elf_file(file_name):
    try:
        with open(file_name, 'rb') as f:
            bs_head = f.read(4)
            if bs_head == B'\x7fELF':
                return True
            else:
                return False
    except Exception as e:
        xlogging.raise_system_error('drv3: file({}) not exist:{}'.format(file_name, e),
                                    'drv3: 文件({})不存在:{}'.format(file_name, e), 8, _logger)

def is_include_setion(elf_file, section_name):
    cmd = 'readelf  -S  "{}"'.format(elf_file)
    retval, outs, errinfo = net_common.get_info_from_syscmd(cmd)
    _logger.info("drv3: runcmd {} return:{} out:{} errorinfo:{}".format(retval, cmd, outs, errinfo))
    if retval != 0:
        return False
    if section_name in outs:
        return True
    return False

def get_ext_vmlinux(src_vm):

    # 已经是解压缩文件，并且可用。
    try:
        if check_is_elf_file(src_vm):
            if is_include_setion(src_vm):
                with open(src_vm, "rb") as f:
                    return io.BytesIO(f.read())
    except:
        # 忽略错误。
        pass

    try:
        os.makedirs(_TMP_VM_DIR)
    except:
        pass

    exe_sc = os.path.join(loadIce.current_dir, "extract_vmlinux")
    tmp_file = os.path.join(_TMP_VM_DIR, str(uuid.uuid4().hex))

    try:
        # extract-vmlinux >> /tmp/xxxx.bmp
        cmd = "{} {} >> {}".format(exe_sc, src_vm, tmp_file)
        retval, outs, errinfo = net_common.get_info_from_syscmd(cmd)
        _logger.info("drv3: runcmd {} return:{} out:{} errorinfo:{}".format(retval, cmd, outs, errinfo))
        if not check_is_elf_file(tmp_file):
            _str = "drv3: 不是标准的elf文件:{}".format(tmp_file)
            _logger.error(_str)
            raise Exception(_str)

        # 有可能没有开始CRC 功能。
        #if not is_include_setion(tmp_file, "__kcrctab"):
        #    _str = "drv3: elf文件:{}不包含__kcrctab".format(tmp_file)
        #    _logger.error(_str)
        #    raise Exception(_str)

        f = open(tmp_file, "rb")
        _vm_iobs = io.BytesIO(f.read())
        f.close()
        os.remove(tmp_file)
        return _vm_iobs

    except Exception as e:
        try:
            os.remove(tmp_file)
        except:
            pass
        xlogging.raise_system_error('drv3: decompress vm ({}) failed{}'.format(src_vm, e),
                                    '解开({})vm 失败:{}'.format(src_vm, e), 8, _logger)

    try:
        os.remove(tmp_file)
    except:
        pass
    xlogging.raise_system_error('drv3: error vmlinux file ({}) failed'.format(src_vm),
                                    "错误的vm file({})vm".format(src_vm), 9, _logger)


if __name__ == '__main__':

    print("ok")
