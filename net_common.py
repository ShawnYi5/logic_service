import os
import signal
import subprocess
import tempfile
import traceback

import xlogging

_logger = xlogging.getLogger('network_r')


def get_info_from_file(in_file):
    if os.path.isfile(in_file):
        try:
            with open(in_file) as fd:
                mstr = fd.read()
                fd.close()
                _logger.info("read file {} success,info {}".format(in_file, mstr))
                return 0, mstr
        except Exception as e:
            _logger.error("read file {} failed {},{}".format(in_file, e, traceback.format_exc()))
    else:
        _logger.error("read file {} failed,file not exist".format(in_file))
    return -1, None


def set_info_to_file(in_file, in_str, in_format):
    # if os.path.isfile(in_file):
    try:
        with tempfile.NamedTemporaryFile(in_format, dir=os.path.dirname(in_file), delete=False) as tf:
            tf.write(in_str)
            tempname = tf.name
            tf.flush()
            os.fdatasync(tf)
            os.rename(tempname, in_file)
            dirfd = os.open(os.path.dirname(in_file), os.O_DIRECTORY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
            _logger.debug("write file {} success,info {}".format(in_file, in_str))
            return 0
    except Exception as e:
        _logger.error("write file {} failed {},{}".format(in_file, e, traceback.format_exc()))
    # else:
    #     _logger.error("read file {} failed,file not exist".format(in_file))
    return -1


def get_itemdict_from_str(in_str, in_dict):
    mlist = in_str.split('\n')
    for i in range(len(mlist)):
        mstr = mlist[i].strip('\n').strip()
        for key in in_dict:
            if mstr.startswith(key):
                mstr = mstr[len(key):].strip()
                if in_dict[key] is None:
                    in_dict[key] = list()
                if mstr not in in_dict[key]:
                    in_dict[key].append(mstr)
                break
    return


# 设置字符串in_str指定行数据,in_dict是字典，value需要是list类型，add_new等于yes时in_str中未找到时会新增行
def set_itemdict_in_str(in_str, in_dict):
    mlist = in_str.split('\n')
    mlen = len(mlist) - 1
    while mlen >= 0:
        mstr = mlist[mlen].strip()
        if mstr == '':
            del mlist[mlen]
        else:
            mlist[mlen] = mstr
        mlen -= 1
    lost_num = 0
    for key in in_dict:
        mtype = in_dict[key][0]
        mvalue = in_dict[key][1]
        if mtype == 'ca':
            mlist.clear()
            new_str = key + mvalue
            mlist.append(new_str)
            _logger.info("key {} value {} add to new line {}".format(key, mvalue, mlist[len(mlist) - 1]))
        elif mtype == 'a':
            for i in range(len(mlist)):
                mstr = mlist[i]
                if mstr.startswith(key):
                    if mstr[len(key):] == mvalue:
                        break
            else:
                new_str = key + mvalue
                mlist.append(new_str)
                _logger.info("key {} value {} add to new line {}".format(key, mvalue, mlist[len(mlist) - 1]))
        elif mtype == 'd':
            mlen = len(mlist) - 1
            while mlen >= 0:
                mstr = mlist[mlen]
                if mstr.startswith(key):
                    _logger.info("index {} key {} delete mstr {}".format(mlen, key, mstr))
                    del mlist[mlen]
                mlen -= 1
        elif mtype == 'ma' or mtype == 'm':
            for i in range(len(mlist)):
                mstr = mlist[i]
                if mstr.startswith(key):
                    mlist[i] = mstr[:len(key)] + mvalue
                    _logger.info("key {} value {} modify to new line {}".format(key, mvalue, mlist[i]))
                    break
            else:
                if mtype == 'ma':
                    new_str = key + mvalue
                    mlist.append(new_str)
                    _logger.info(
                        "key {} value {} add to new line {}".format(key, mvalue, mlist[len(mlist) - 1]))
                else:
                    _logger.info("key {} value {} lost".format(key, in_dict[key]))
                    lost_num += 1
    mstr = ''
    mlen = len(mlist)
    for i in range(mlen):
        mstr += mlist[i]
        if i <= mlen - 1:
            mstr += '\n'
    return lost_num, mstr


def set_itemdict_in_file(file_name, in_dict):
    retval = get_info_from_file(file_name)
    if retval[0] != 0 or retval[1] is None or len(retval[1]) < 2:
        _logger.error("get file {} info failed,ret value {}".format(file_name, retval[0]))
        return -1

    file_str = retval[1]
    retval = set_itemdict_in_str(file_str, in_dict)
    if retval[0] != 0 or retval[1] is None or len(retval[1]) < 2:
        _logger.error("modify str failed,ret value {}".format(retval[0]))
        return -1

    file_str = retval[1]
    retval = set_info_to_file(file_name, file_str, 'w')
    if retval != 0:
        _logger.error("update file {} failed,info is {}".format(file_name, file_str))
        return -1
    return 0


def get_itemdict_from_file(in_file, in_dict):
    if os.path.isfile(in_file):
        try:
            with open(in_file) as fd:
                mstr = fd.read()
                get_itemdict_from_str(mstr, in_dict)
        except Exception as e:
            _logger.error("read file {} failed {},{}".format(in_file, e, traceback.format_exc()))

    return 0


def get_info_from_syscmd(in_cmd_line, timeout=120):
    if len(in_cmd_line) <= 0:
        _logger.error("invalid cmd line")
        return -1, None
    try:
        _logger.info("start cmd {}".format(in_cmd_line))
        p = subprocess.Popen(in_cmd_line, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            outs, errs = p.communicate(timeout=timeout)
            retval = p.returncode
        except subprocess.TimeoutExpired:
            os.kill(p.pid, signal.SIGKILL)
            _logger.warning('cmd {} process killed,timer {} begin'.format(in_cmd_line, timeout))
            outs, errs = p.communicate()
            retval = p.returncode
            _logger.warning('cmd {} process killed,timer {} end {}'.format(in_cmd_line, timeout, retval))

        _logger.info("run cmd {} ret {} | {} | {}".format(in_cmd_line, retval, outs, errs))
        return retval, outs.decode("utf-8", "replace"), errs.decode()
    except Exception as e:
        _logger.error("run cmd {} error {} - {}".format(in_cmd_line, e, traceback.format_exc()))
        return -1, None, None


def get_local_iplist():
    iplist = list()
    retval = get_info_from_syscmd('ifconfig')
    type_info = ''
    if retval[0] == 0:
        linelist = retval[1].split('\n')
        for i in range(len(linelist)):
            mstr = linelist[i].strip()
            if mstr.find('flags=') >= 0:
                if mstr.startswith('bond'):
                    type_info = 'bond'
                elif mstr.startswith('eno'):
                    type_info = 'eno'
                else:
                    type_info = ''
            if mstr.startswith('inet ') and (type_info == 'eno' or type_info == 'bond'):
                netstr = mstr.split('  ')[0].strip()[5:]
                iplist.append(netstr)
    return iplist
