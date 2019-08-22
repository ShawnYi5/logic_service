import json
import os
import shutil
import subprocess
import uuid

import Initramfs
import chgrub
import clerware_linux_driver
import modlink
import xlogging

_logger = xlogging.getLogger(__name__)

g_LinuxAgentPacket = '/var/www/static/download/client/linux/aio.tar.gz'
g_InstallAgentTmp = '/dev/shm/install_agent_tmp'

g_bRemoveDirectory = True
g_bLinkModule = False  # 控制在服务器上链接
g_bRemoteInstall = False
g_bReconfigGrub = False

# g_drivers: 为安装驱动的配置, 增加驱动时, 按照驱动安装的顺序添加
# name: 驱动模块名, 同时也作为驱动在context中的key
# ko: 驱动短文件名
# cb_func: 安装驱动的回调函数, 返回驱动安装的脚本
# cb_args: 回调函数静态配置参数
# to_initrd: 是否要安装到initrd中
# must_success: 是否是必须成功步骤

g_drivers = Initramfs.get_sbd_driver_config()


def execute_agent_cmd(RuntimeCtx, cmd, curr_dir=''):
    session = RuntimeCtx['session']
    _g = RuntimeCtx['_g']

    flagjson = json.dumps({"curr_dir": curr_dir, "call_py": "false"})

    (return_code, msg_out, msg_err) = _g.getBoxPrx().executeCommandOnAgentSetup(session, cmd, flagjson)

    if return_code != 0:
        log_info_msg('[execute_agent_cmd] return_code = ' + str(return_code))
        log_info_msg('[execute_agent_cmd] msg_out = ' + str(msg_out))
        log_info_msg('[execute_agent_cmd] msg_err = ' + str(msg_err))

    exec_result = (return_code, msg_out, msg_err)
    return exec_result


def execute_agent_method(RuntimeCtx, method, json_arg):
    session = RuntimeCtx['session']
    _g = RuntimeCtx['_g']

    json_arg["call_py"] = "true"
    flagjson = json.dumps(json_arg)

    return_code = 0
    msg_out = None
    msg_err = None

    log_info_msg('[execute_agent_method] call executeCommandOnAgentSetup ')
    try:
        (return_code, msg_out, msg_err) = _g.getBoxPrx().executeCommandOnAgentSetup(session, method, flagjson)
    except Exception as e:
        return_code = -1
        log_error_msg("[execute_agent_method] Except {}".format(e))
        log_error_msg('[execute_agent_method] call executeCommandOnAgentSetup error')

    log_info_msg('[execute_agent_method] call executeCommandOnAgentSetup finish')

    log_info_msg(return_code)
    log_info_msg(msg_out)
    log_info_msg(msg_err)

    exec_result = (return_code, msg_out, msg_err)
    return exec_result


def log_install_message(RuntimeCtx, msg_type, msg_info):
    json_arg = {
        "msg_type": msg_type,
        "msg_info": msg_info,
    }

    (ret_val, out_msg, err_msg) = execute_agent_method(RuntimeCtx, 'log_install_msg', json_arg)
    if ret_val != 0:
        log_error_msg('[log_install_message] execute_agent_method failed')
        log_error_msg('[log_install_message] json_arg = {}'.format(json_arg))
        log_error_msg('[log_install_message] ret_val = {}'.format(ret_val))
        log_error_msg('[log_install_message] out_msg = {}'.format(out_msg))
        log_error_msg('[log_install_message] err_msg = {}'.format(err_msg))
        return -1

    return 0


def openAgentFile(RuntimeCtx, file, flagjson):
    session = RuntimeCtx['session']
    _g = RuntimeCtx['_g']

    return _g.getBoxPrx().openOnAgentSetup(session, file, flagjson)


def readAgentFile(RuntimeCtx, remote, offset, chunk_size):
    session = RuntimeCtx['session']
    _g = RuntimeCtx['_g']

    # log_info_msg('[readAgentFile] begin read')
    data = _g.getBoxPrx().preadOnAgentSetup(session, remote, offset, chunk_size)
    # log_info_msg('[readAgentFile] finish read')
    return data


def writeAgentFile(RuntimeCtx, file, offset, count, data):
    session = RuntimeCtx['session']
    _g = RuntimeCtx['_g']

    return _g.getBoxPrx().pwriteOnAgentSetup(session, file, offset, count, data)


def closeAgentFile(RuntimeCtx, file):
    session = RuntimeCtx['session']
    _g = RuntimeCtx['_g']

    return _g.getBoxPrx().closeOnAgentSetup(session, file)


def getAgentFileInfo(RuntimeCtx, file, flagJson):
    session = RuntimeCtx['session']
    _g = RuntimeCtx['_g']

    log_info_msg('getAgentFileInfo enter....')
    result = {'size': ''}

    try:
        info = _g.getBoxPrx().getFileInfoOnAgentSetup(session, file, flagJson)
        result = json.loads(info)
    except Exception as e:
        result['size'] = ''
        result['md5'] = ''
        log_error_msg('getAgentFileInfo faile, file = {} - {}'.format(file, e))

    log_info_msg(result)
    return result


def get_local_file_md5(file):
    cmd = "md5sum {filepath}".format(filepath=file)
    with subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True) as p:
        stdout, stderr = p.communicate()
    if p.returncode != 0:
        err_msg1 = "get_local_file_md5 filepath:{}, error:{}".format(file, stderr)
        log_error_msg(err_msg1)
        xlogging.raise_system_error("setup error", err_msg1, 0)
        return None
    else:
        if stdout and len(stdout.strip().split()[0]) == 32:
            return stdout.strip().split()[0]
        else:
            err_msg2 = "get_local_file_md5 fail filepath:{}, stdout:{}".format(file, stdout)
            log_error_msg(err_msg2)
            xlogging.raise_system_error("setup error", err_msg2, 0)
            return None


def log_error_msg(msg):
    msg = '' if msg is None else msg
    str_msg = '[SetUp_I]' + str(msg)
    # print(str_msg)
    _logger.error(str_msg, exc_info=True)


def log_info_msg(msg):
    msg = '' if msg is None else msg
    str_msg = '[SetUp_I]' + str(msg)
    # print(str_msg)
    _logger.info(str_msg)


def copy_from_agent(RuntimeCtx, src, dst):
    log_info_msg('[copy_from_agent] src = ' + src)
    log_info_msg('[copy_from_agent] dst = ' + dst)

    remote = None
    ret_val = -1
    try:
        info = getAgentFileInfo(RuntimeCtx, src, '')
        length = info['size']
        flag = {"mode": "rb"}

        log_info_msg('[copy_from_agent] begin read data')

        remote = openAgentFile(RuntimeCtx, src, json.dumps(flag))
        chunk_size = 1024 * 64
        with open(dst, "wb") as f:
            offset = 0
            while offset < length:
                read_size = length - offset
                if read_size > chunk_size:
                    read_size = chunk_size
                data = readAgentFile(RuntimeCtx, remote, offset, read_size)
                ret = len(data)

                if data:
                    f.write(data)
                    offset += ret
                else:
                    log_error_msg(r'copy_from_agent readAgentFile failed')
                    break
        md5_local = get_local_file_md5(dst)
        if info['md5'] != md5_local:
            log_error_msg(r'copy_from_agent md5 not the same')
        else:
            log_info_msg('copy_from_agent succes...')
            ret_val = 0

    except Exception as e:
        log_error_msg('copy_from_agent except...')
        xlogging.raise_system_error("setup error", "copy file fail error{}".format(e), 0)

    finally:
        closeAgentFile(RuntimeCtx, remote)
        return ret_val


# 仅仅拷贝aio server上的文件到安装目标机, 并作MD5校验
def write_to_agent(RuntimeCtx, local_path, agent_path):
    ret_val = -1
    has_error = 0
    remote = None
    local_md5 = None
    flag = {"mode": "wb"}
    chunk_size = 1024 * 64
    byteOffset = 0

    log_info_msg("write_to_agent local_path = " + local_path)
    log_info_msg("write_to_agent agent_path = " + agent_path)

    try:

        local_md5 = get_local_file_md5(local_path)
        remote = openAgentFile(RuntimeCtx, agent_path, json.dumps(flag))

        with open(local_path, "rb") as f:
            while True:
                data = f.read(chunk_size)
                read_len = len(data)
                if data:
                    writeAgentFile(RuntimeCtx, remote, byteOffset, read_len, data)
                    byteOffset += read_len
                else:
                    break

    except Exception as e:
        err_msg = "write_to_agent fail error{}".format(e)
        log_error_msg(err_msg)
        xlogging.raise_system_error("setup error", err_msg, 0)
        has_error = 1

    finally:
        closeAgentFile(RuntimeCtx, remote)
        if has_error:
            return -1

        info = getAgentFileInfo(RuntimeCtx, agent_path, '')
        agent_md5 = info['md5']
        if local_md5 != agent_md5:
            log_error_msg(r'write_to_agent md5 not the same')
            log_error_msg('agent_md5 = ' + str(agent_md5))
            log_error_msg('local_md5 = ' + str(local_md5))
        else:
            ret_val = 0
        return ret_val


def make_install_dir():
    inst_tmp_root = g_InstallAgentTmp

    if not os.path.exists(inst_tmp_root):
        os.mkdir(inst_tmp_root)

    dir_id = uuid.uuid4()
    inst_tmp_agent = inst_tmp_root + '/' + str(dir_id)

    os.mkdir(inst_tmp_agent)

    return inst_tmp_agent


def copy_extra_initramfs_files(RuntimeCtx, context, tmp_dir):
    log_info_msg('[copy_extra_initramfs_files] Enter...')

    boot_symvers = context['boot_symvers']
    system_map = context['system_map']

    log_info_msg('[copy_extra_initramfs_files] boot_symvers = ' + boot_symvers)
    log_info_msg('[copy_extra_initramfs_files] system_map = ' + system_map)

    if boot_symvers != '':
        short_syms = os.path.basename(boot_symvers)
        dst_syms = os.path.join(tmp_dir, short_syms)
        log_info_msg('[copy_extra_initramfs_files] dst_syms = ' + dst_syms)
        ret_val = copy_from_agent(RuntimeCtx, boot_symvers, dst_syms)
        if ret_val != 0:
            log_error_msg('copy_from_agent failed, file = ' + boot_symvers)
            log_error_msg('Not fatal, build driver no longer use symvers')
            # 2018-11-24 comment
            # return -1
        else:
            log_info_msg('copy_from_agent success, file = ' + boot_symvers)

    if system_map != '':
        short_map = os.path.basename(system_map)
        dst_map = os.path.join(tmp_dir, short_map)
        log_info_msg('[copy_extra_initramfs_files] dst_map = ' + dst_map)
        ret_val = copy_from_agent(RuntimeCtx, system_map, dst_map)
        if ret_val != 0:
            log_error_msg('copy_from_agent failed, file = ' + system_map)
            return -1
        else:
            log_info_msg('copy_from_agent success, file = ' + system_map)

    log_info_msg('[copy_extra_initramfs_files] Success...')

    return 0


def make_agent_initramfs(RuntimeCtx, context):
    log_info_msg('make_agent_initramfs enter...')

    tmp_dir = context['tmp_dir']
    src = context['initrdfs_path']
    knl_ver = context['release']
    dst_dir = tmp_dir + '/initramfs_tmp'
    os.mkdir(dst_dir)
    index = src.rfind('/')
    in_ramfs = dst_dir + '/' + src[index + 1:]
    clrd_name = 'initramfs-' + knl_ver + '.clrd.img'
    out_ramfs = dst_dir + '/' + clrd_name
    write_rd = src[:index] + '/' + clrd_name
    ramfs_dir = os.path.dirname(src)
    short_name = os.path.basename(src)

    context['clrd_name'] = clrd_name

    log_info_msg('src:' + src)
    log_info_msg('dst_dir:' + dst_dir)
    log_info_msg('in_ramfs:' + in_ramfs)
    log_info_msg('clrd_name:' + clrd_name)
    log_info_msg('out_ramfs:' + out_ramfs)
    log_info_msg('write_rd:' + write_rd)

    ret_val = copy_from_agent(RuntimeCtx, src, in_ramfs)
    if ret_val != 0:
        log_error_msg(r'make_agent_initramfs copy_from_agent failed, file=' + src)
        return -1, 'Get initrd failed'

    log_info_msg('make_agent_initramfs copy_from_agent success')

    ret_val = copy_extra_initramfs_files(RuntimeCtx, context, dst_dir)
    if ret_val != 0:
        log_error_msg(r'copy_extra_initramfs_files failed')
        return -1, 'Get initrd related files failed'

    extract_dir = tmp_dir + '/initramfs_extract'
    os.mkdir(extract_dir)

    distrib_ver = context['platform']

    log_info_msg('make_agent_initramfs call Initramfs...')
    initramfs = Initramfs.Initramfs(in_ramfs, out_ramfs, extract_dir, distrib_ver, knl_ver)

    log_info_msg('make_agent_initramfs call extract...')
    (res, x_dir) = initramfs.extract()
    if res is False:
        return -1, 'Extract initrd failed'

    log_info_msg('x_dir = ' + x_dir)
    # disksbd_drv = context['disksbd_linux']
    # disksbd_drv = '/lib/modules/3.10.0-327.el7.x86_64/kernel/fs/xfs/xfs.ko'

    # log_info_msg('disksbd_drv = ' + disksbd_drv)
    # log_info_msg('make_agent_initramfs call add_driver...')
    # initramfs.add_driver(x_dir, disksbd_drv, 0, True)

    # log_info_msg('make_agent_initramfs call do_depmod...')
    # initramfs.do_depmod(x_dir)

    log_info_msg('x_dir = ' + x_dir)

    # disksbd_drv = context['disksbd_linux']
    # log_info_msg('make_agent_initramfs disksbd_drv = ' + disksbd_drv)
    # if disksbd_drv == '':
    #     log_error_msg('make_agent_initramfs invalid disksbd_drv')
    #     return -1
    #
    # pdisk_lba = context['pdisk_lba']
    # pdisk_label = context['pdisk_label']
    # args = 'pdisk_lba={} pdisk_label={}'.format(pdisk_lba, pdisk_label)
    # drv_info = [('driver', disksbd_drv, os.path.basename(disksbd_drv), args, 'disksbd_linux')]
    #
    # log_info_msg('make_agent_initramfs drv_info = {}'.format(drv_info))
    # log_info_msg('make_agent_initramfs call add_files...')

    drv_info_list = list()
    for driver in g_drivers:
        drv_fullpath = context[driver['name']]
        if os.path.exists(drv_fullpath) is False:
            log_error_msg('make_agent_initramfs file not exist of driver: {}'.format(drv_fullpath))
            return -1, 'File {} not exist'.format(driver['name'])
        args = None
        if driver['cb_func'] is not None:
            args = eval(driver['cb_func'])(driver['cb_args'], **context)
        drv_info = ('driver', drv_fullpath, driver['ko_name'], args, driver['name'])
        log_info_msg('make_agent_initramfs drv_info = {}'.format(drv_info))
        drv_info_list.append(drv_info)

    log_info_msg('make_agent_initramfs call add_files...')

    ret_val = initramfs.add_files(x_dir, drv_info_list)
    if ret_val != 0:
        log_error_msg('make_agent_initramfs call add_files failed, ret_val=' + str(ret_val))
        return -1, 'Config initrd failed, error code: {}'.format(ret_val)

    log_info_msg('make_agent_initramfs call pack...')
    initramfs.pack(x_dir)

    log_info_msg('write_rd = ' + write_rd)

    log_info_msg('make_agent_initramfs call write_to_agent...')
    ret_val = write_to_agent(RuntimeCtx, out_ramfs, write_rd)
    if ret_val != 0:
        log_error_msg(r'make_agent_initramfs write_to_agent failed, file=' + write_rd)
        return -1, 'Write back initrd failed'

    log_info_msg('make_agent_initramfs write_to_agent success')

    replace_cmd = 'mv -f ' + clrd_name + ' ' + short_name
    log_info_msg('replace_cmd = ' + replace_cmd)

    if context['tunnel_mode']:
        json_arg = {
            "cmd": replace_cmd,
            "dir": ramfs_dir,
            "must_success": 1
        }

        log_info_msg('make_agent_initramfs tunnel mode, excute post command')
        (ret_val, out_msg, err_msg) = execute_agent_method(RuntimeCtx, 'post_execute_cmd', json_arg)

        if ret_val != 0:
            return -1, 'Tunnel mode post execute command failed'
        else:
            return 0, ''

    (ret_val, out_msg, err_msg) = execute_agent_cmd(RuntimeCtx, replace_cmd, ramfs_dir)
    if ret_val != 0:
        log_error_msg('make_agent_initramfs replace ramfs failed')
        return -1, 'Write replace initrd failed'

    log_info_msg('make_agent_initramfs replace ramfs success')

    return 0, ''


def report_install_status(RuntimeCtx, current, total, text):
    session = RuntimeCtx['session']
    _g = RuntimeCtx['_g']

    flagJson = {
        'state': str(current),
        'text': str(text),
        'total': str(total),
    }

    strJson = json.dumps(flagJson)

    log_info_msg(strJson)

    _g.getBoxPrx().reportStatusOnAgentSetup(session, strJson)

    return


"""
para_dict = {
    'kernel_ver': '3.10.0',
    'bit_opt': '64',
    'vermagic': '3.10.0-327.el7.x86_64 SMP mod_unload modversions ',
    'src_dir': '/mnt/sdb1/pjt/test/link-example/3.10.0-64',
    'tmp_dir': '/mnt/sdb1/pjt/test/link-example/3.10.0-64/tmp',
    'syms_file': '/mnt/sdb1/pjt/test/link-example/3.10.0-64/KModule.symvers',
    'kconfig_file': '/mnt/sdb1/pjt/test/link-example/3.10.0-64/config-3.10.0-327.el7.x86_64'
}
"""


def static_driver_info(driver_path):
    log_info_msg('static_driver_info enter: {}'.format(driver_path))

    cmd = 'strings {file}'.format(file=driver_path) + r'|grep "sbd_driver_version:[[:digit:]]\{4\}"'
    status, output = subprocess.getstatusoutput(cmd)
    log_info_msg('static_driver_info exec cmd: {}, return: {}, {}'.format(cmd, status, output))
    if status != 0:
        log_error_msg("static_driver_info return: -1, None, None, {}".format(output))
        return -1, None, None

    # 这里grep做了严格限制, 所以只要搜出来, 一定是这个格式
    ver_dig = output.split(':')[1]
    major_ver = int(ver_dig[0:2])
    minor_ver = int(ver_dig[2:])

    log_info_msg("static_driver_info return: 0, {}, {}".format(major_ver, minor_ver))
    return 0, major_ver, minor_ver


def make_agent_driver(RuntimeCtx, context):
    log_info_msg("make_agent_driver enter...")

    kernel_version = context['kernel_ver']
    release_version = context['platform']
    arch = context['bit_opt']
    version_magic = context['vermagic']

    log_info_msg('[make_agent_driver] kernel_version = ' + kernel_version)
    log_info_msg('[make_agent_driver] release_version = ' + release_version)
    log_info_msg('[make_agent_driver] arch = ' + arch)
    log_info_msg('[make_agent_driver] version_magic = ' + version_magic)

    try:
        src = context['vmlinuz_path']
        dst_dir = context['tmp_dir'] + '/vmlinux_tmp'
        os.mkdir(dst_dir)
        index = src.rfind('/')
        tmp_vmlinux = dst_dir + '/' + src[index + 1:]

        log_info_msg('src:' + src)
        log_info_msg('dst_dir:' + dst_dir)
        log_info_msg('tmp_vmlinux:' + tmp_vmlinux)

        ret_val = copy_from_agent(RuntimeCtx, src, tmp_vmlinux)
        if ret_val != 0:
            log_error_msg('[make_agent_driver] copy_from_agent failed, file = ' + tmp_vmlinux)
        else:
            context['tmp_vmlinux'] = tmp_vmlinux

    except SystemError as ex:
        log_info_msg('copy vmlinux failed:{}'.format(ex))

    # 建议这里如果没有找到驱动,应该报告出去,让安装的人知道是因为驱动无法匹配,导致不能安装
    try:
        disksbd_drv = clerware_linux_driver.get_disksbd_ko(kernel_version, release_version, arch, version_magic,
                                                           g_drivers,
                                                           context.get('real_vermagic', None),
                                                           context.get('tmp_vmlinux', None))
        log_info_msg('make_agent_initramfs disksbd_drv = ' + disksbd_drv)

    except SystemError as ex:
        log_error_msg('No matched driver of: ex = {}'.format(ex))
        return -1, 'Not support OS version, please connect Clerware support.'

    driver_dir = os.path.dirname(disksbd_drv)
    log_info_msg('[make_agent_driver] v2: driver_dir={}'.format(driver_dir))
    drivers_version = dict()
    for driver in g_drivers:
        name = driver['name']
        src_drv_path = os.path.join(driver_dir, driver['ko_name'])
        context[name] = src_drv_path
        log_info_msg('[make_agent_driver] v2: context[{}]={}'.format(name, context[name]))
        if os.path.exists(context[name]) is False:
            return -2, 'Not found the file {}, the AIO server mismatch with ClwDRClient.'.format(driver['ko_name'])

        # 在这里先执行strings grep driver版本, ubuntu没有strings命令, Issue #1712
        ret_val, major_ver, minor_ver = static_driver_info(src_drv_path)
        drivers_version[name] = dict()
        drivers_version[name]['major_ver'] = major_ver
        drivers_version[name]['minor_ver'] = minor_ver

    try:
        # 这里除了会发生ICE异常外, 是不会返回错误的, 所以不必冗错
        execute_agent_method(RuntimeCtx, 'post_drivers_version', drivers_version)
        log_info_msg("post_drivers_version done: {}".format(drivers_version))
    except Exception as ex:
        log_info_msg("post_drivers_version failed, maybe client not support: {}".format(str(ex)))

    if not g_bLinkModule:  # crunch: 直接返回了, 现在不用实时连接了
        return 0, ''

    log_info_msg('kernel_ver = ' + str(context['kernel_ver']))
    log_info_msg('bit_opt = ' + str(context['bit_opt']))
    log_info_msg('vermagic = ' + str(context['vermagic']))
    log_info_msg('syms_file = ' + str(context['syms_file']))
    log_info_msg('kconfig_file = ' + str(context['kconfig_file']))

    link_tmp = context['tmp_dir'] + '/link_tmp'
    log_info_msg('link dir = ' + link_tmp)
    os.mkdir(link_tmp)

    link_out = link_tmp + '/link_out'
    log_info_msg('link_out = ' + link_out)
    os.mkdir(link_out)

    sym_src = context['syms_file']
    index = sym_src.rfind('/')
    sym_short = sym_src[index + 1:]
    sym_dst = link_tmp + '/' + sym_short
    log_info_msg('sym_src = ' + sym_src)
    log_info_msg('sym_dst = ' + sym_dst)

    kconfig_src = context['kconfig_file']
    index = kconfig_src.rfind('/')
    kconfig_short = kconfig_src[index + 1:]
    kconfig_dst = link_tmp + '/' + kconfig_short
    log_info_msg('kconfig_src = ' + kconfig_src)
    log_info_msg('kconfig_dst = ' + kconfig_dst)

    log_info_msg('begin to copy sym_src = ' + sym_src)
    ret_val = copy_from_agent(RuntimeCtx, sym_src, sym_dst)
    if ret_val != 0:
        log_error_msg('[make_agent_driver] copy_from_agent failed, file = ' + sym_src)
        return -1

    log_info_msg('begin to copy kconfig_src = ' + kconfig_src)
    ret_val = copy_from_agent(RuntimeCtx, kconfig_src, kconfig_dst)
    if ret_val != 0:
        log_error_msg('[make_agent_driver] copy_from_agent failed, file = ' + kconfig_src)
        return -1

    para = {
        'kernel_ver': context['kernel_ver'],
        'bit_opt': context['bit_opt'],
        'vermagic': context['vermagic'],
        'syms_file': sym_dst,
        'kconfig_file': kconfig_dst,
        'tmp_dir': link_out,
    }

    log_info_msg('kernel_ver = ' + para['kernel_ver'])
    log_info_msg('bit_opt = ' + para['bit_opt'])
    log_info_msg('vermagic = ' + para['vermagic'])
    log_info_msg('syms_file = ' + para['syms_file'])
    log_info_msg('kconfig_file = ' + para['kconfig_file'])
    log_info_msg('src_dir = ' + para['src_dir'])
    log_info_msg('tmp_dir = ' + para['tmp_dir'])

    log_info_msg('begin to module link')

    (ret_val, ret_str) = modlink.modlink(para)
    if ret_val != 0:
        log_error_msg('modlink failed:')
        log_error_msg('ret_val = ' + str(ret_val))
        log_error_msg('ret_str = ' + ret_str)
        return -1

    link_file = link_out + '/test.ko'
    log_info_msg('link_out = ' + link_out)

    if not os.path.exists(link_out):
        log_error_msg(link_out + 'not exist')
        return -1

    log_error_msg('link success')
    context['disksbd_linux'] = link_file
    # context[SBD_FUN_LINUX] # do nothing, no link, not reached
    return 0


def extract_target_file(RuntimeCtx, target_path):
    log_info_msg(target_path)

    index = target_path.rfind('/')
    target = target_path[index + 1:]
    x_dir = target_path[:index]

    cmd = 'tar -xmf ' + target

    log_info_msg(cmd)
    log_info_msg(x_dir)

    (return_code, msg_out, msg_err) = execute_agent_cmd(RuntimeCtx, cmd, x_dir)

    if return_code != 0:
        log_error_msg('[extract_target_file] execute_agent_cmd failed')
        log_error_msg('[extract_target_file] msg_out = ' + str(msg_out))
        log_error_msg('[extract_target_file] msg_err = ' + str(msg_err))
        xlogging.raise_system_error("setup error", "extract_target_file, error:{}".format(str(msg_out)), 0)
    else:
        return 0


def get_disksbd_linux_args(cb_args, **context):
    pdisk_lba = context['pdisk_lba']
    pdisk_label = context['pdisk_label']
    drv_args = 'pdisk_lba={} pdisk_label={}'.format(pdisk_lba, pdisk_label)
    return drv_args


def install_agent_driver(RuntimeCtx, context):
    log_info_msg('[install_agent_driver] v2: enter')

    for driver in g_drivers:
        install_path = context['install_path']
        src_drv_path = context[driver['name']]
        short_name = os.path.basename(src_drv_path)
        dst_drv_path = os.path.join(install_path, short_name)

        command = 'insmod ' + short_name
        if driver['cb_func'] is not None:
            drv_args = eval(driver['cb_func'])(driver['cb_args'], **context)
            command = command + ' ' + drv_args

        log_info_msg('[install_agent_driver] src_drv_path = ' + src_drv_path)
        log_info_msg('[install_agent_driver] dst_drv_path = ' + dst_drv_path)
        log_info_msg('[install_agent_driver] v2: command = ' + command)

        log_info_msg('[install_agent_driver] call write_to_agent')

        ret_val = write_to_agent(RuntimeCtx, src_drv_path, dst_drv_path)
        if ret_val != 0:
            log_error_msg('[install_agent_driver] write_to_agent failed')
            return -1

        log_info_msg('[install_agent_driver] write_to_agent success')

        # crunch: 如果是隧道模式, 先将要执行的cmd, post到客户端保存起来, 到所有完成时再执行
        # 客户端: on_post_execute_cmd->post_cmd.append(command) # command=json_arg
        # on_finish_install->execute_post_cmd->循环执行

        if context['tunnel_mode']:
            json_arg = {
                "cmd": command,
                "dir": install_path,
                "must_success": driver['must_success']
            }
            log_info_msg('[install_agent_driver] tunnel mode, excute post command: json_arg={}'.format(json_arg))
            (ret_val, msg_out, msg_err) = execute_agent_method(RuntimeCtx, 'post_execute_cmd', json_arg)
            if ret_val != 0:
                log_info_msg('[install_agent_driver] tunnel mode, install driver failed: {}'.format(command))
                return -2
            else:
                log_info_msg('[install_agent_driver] tunnel mode, install driver success: {}'.format(command))
                continue

        # crunch: 非隧道模式, 直接执行
        log_info_msg('[install_agent_driver] call execute_agent_cmd')

        # crunch: 对应客户端的executeCommand, 我们客户端的这一步骤处理驱动版本判断的情况.
        (ret_val, msg_out, msg_err) = execute_agent_cmd(RuntimeCtx, command, install_path)
        if ret_val != 0:
            log_error_msg('[install_agent_driver] ret_val = {}'.format(ret_val))
            log_error_msg('[install_agent_driver] msg_out = {}'.format(msg_out))
            log_error_msg('[install_agent_driver] msg_err = {}'.format(msg_err))

            if len(msg_err) == 0:
                log_error_msg('[install_agent_driver] execute_agent_cmd failed, unknown error')
                return -3

            # crunch: 这里处理了驱动已经安装好了的情况
            str_key = msg_err[0].find('File exists')
            if str_key == -1:
                log_error_msg('[install_agent_driver] execute_agent_cmd failed')
                log_install_message(RuntimeCtx, 'error', 'Install driver {} failed: {}'.format(short_name, msg_err))
                return -4
            else:
                log_info_msg('[install_agent_driver] driver is running')

        log_info_msg('[install_agent_driver] finish')

    return 0


# def install_agent_driver(RuntimeCtx, context):
#     log_info_msg('[install_agent_driver] enter')
#
#     install_path = context['install_path']
#     src_drv_path = context['disksbd_linux']
#     short_name = os.path.basename(src_drv_path)
#     dst_drv_path = os.path.join(install_path, short_name)
#
#     pdisk_lba = context['pdisk_lba']
#     pdisk_label = context['pdisk_label']
#     drv_args = 'pdisk_lba={} pdisk_label={}'.format(pdisk_lba, pdisk_label)
#
#     command = 'insmod ' + short_name + ' ' + drv_args
#
#     log_info_msg('[install_agent_driver] src_drv_path = ' + src_drv_path)
#     log_info_msg('[install_agent_driver] dst_drv_path = ' + dst_drv_path)
#     log_info_msg('[install_agent_driver] drv_args = ' + drv_args)
#
#     log_info_msg('[install_agent_driver] call write_to_agent')
#
#     ret_val = write_to_agent(RuntimeCtx, src_drv_path, dst_drv_path)
#     if ret_val != 0:
#         log_error_msg('[install_agent_driver] write_to_agent failed')
#         return -1
#
#     log_info_msg('[install_agent_driver] write_to_agent success')
#
#     if context['tunnel_mode']:
#         json_arg = {
#             "cmd": command,
#             "dir": install_path,
#             "must_success": 0
#         }
#         log_info_msg('[install_agent_driver] tunnel mode, excute post command')
#         (ret_val, msg_out, msg_err) = execute_agent_method(RuntimeCtx, 'post_execute_cmd', json_arg)
#         if ret_val != 0:
#             return -1
#         else:
#             return 0
#
#     log_info_msg('[install_agent_driver] call execute_agent_cmd')
#
#     (ret_val, msg_out, msg_err) = execute_agent_cmd(RuntimeCtx, command, install_path)
#     if ret_val != 0:
#         log_error_msg('[install_agent_driver] ret_val = {}'.format(ret_val))
#         log_error_msg('[install_agent_driver] msg_out = {}'.format(msg_out))
#         log_error_msg('[install_agent_driver] msg_err = {}'.format(msg_err))
#
#         if len(msg_err) == 0:
#             log_error_msg('[install_agent_driver] execute_agent_cmd failed, unknown error')
#             return -1
#
#         str_key = msg_err[0].find('File exists')
#         if str_key == -1:
#             log_error_msg('[install_agent_driver] execute_agent_cmd failed')
#             return -1
#         else:
#             log_info_msg('[install_agent_driver] driver is running')
#
#     log_info_msg('[install_agent_driver] finish')
#
#     return 0


def install_agent_module(RuntimeCtx, context):
    log_info_msg('[install_agent_module] enter')

    install_path = context['install_path']
    target_file = install_path + '/' + 'aio.tar.gz'

    ret_val = install_agent_driver(RuntimeCtx, context)
    if ret_val != 0:
        log_error_msg('[install_agent_module] install_agent_driver failed')
        return ret_val

    if not g_bRemoteInstall:
        return 0

    # crunch->cfq: 本来的想法是自动下载安装包到服务, 自动解压运行, 后来没有这么做

    ret_val = write_to_agent(RuntimeCtx, g_LinuxAgentPacket, target_file)
    if ret_val != 0:
        log_error_msg('[install_agent_module] write_to_agent failed')
        return -1

    ret_val = extract_target_file(RuntimeCtx, target_file)
    if ret_val != 0:
        log_error_msg('[install_agent_module] extract_target_file failed')
        return -1

    json_arg = {
        "curr_dir": install_path + '/aio',
        "AgentService": install_path + '/aio' + '/LinuxAgentService',
    }

    (ret_val, out_msg, err_msg) = execute_agent_method(RuntimeCtx, 'register_service', json_arg)
    if ret_val != 0:
        log_error_msg('[install_agent_module] execute_agent_method failed')
        return -1

    return 0


def backup_grub_file(RuntimeCtx, src, grub_dir):
    log_info_msg('[backup_grub_file] enter')

    index = src.rfind('/')
    grub_short = src[index + 1:]
    backup_name = 'clrd_' + grub_short
    dst = grub_dir + '/' + backup_name

    info = getAgentFileInfo(RuntimeCtx, dst, '')
    if info['md5'] != '':
        log_info_msg('[backup_grub_file] no need to backup ' + str(src))
        return 0

    cmd = 'cp ' + grub_short + ' ' + backup_name
    log_info_msg('[backup_grub_file] cmd = ' + cmd)

    (ret_val, msg_out, msg_err) = execute_agent_cmd(RuntimeCtx, cmd, grub_dir)
    if ret_val != 0:
        log_error_msg('[backup_grub_file] execute_agent_cmd failed, cmd = ' + str(cmd))
        return -1

    log_info_msg('[backup_grub_file] backup grub success name = ' + src)
    return 0


def reconfig_grub_file(RuntimeCtx, context):
    log_info_msg('[reconfig_grub_file] enter...')

    if not g_bReconfigGrub:
        log_info_msg('[reconfig_grub_file] no need reconfig')
        return 0

    grub_file = context['grub_file']
    grub_ver = context['grub_ver']
    tmp_dir = context['tmp_dir']

    index = grub_file.rfind('/')
    grub_short = grub_file[index + 1:]
    grub_dir = grub_file[:index]
    grub_dst = tmp_dir + '/' + grub_short

    grubenv_src = grub_dir + '/grubenv'
    grubenv_dst = tmp_dir + '/' + 'grubenv'

    log_info_msg('grub_file = ' + grub_file)
    log_info_msg('grub_dst = ' + grub_dst)
    log_info_msg('grubenv_src = ' + grubenv_src)
    log_info_msg('grubenv_dst = ' + grubenv_dst)

    ret_val = backup_grub_file(RuntimeCtx, grub_file, grub_dir)
    if ret_val != 0:
        log_error_msg('[reconfig_grub_file] backup_grub_file failed, src = ' + str(grub_file))
        return -1

    log_info_msg('[reconfig_grub_file] backup grub_file success')

    if grub_ver == 2:
        ret_val = backup_grub_file(RuntimeCtx, grubenv_src, grub_dir)
        if ret_val != 0:
            log_error_msg('[reconfig_grub_file] backup_grub_file failed, src = ' + str(grubenv_src))
            return -1
        log_info_msg('[reconfig_grub_file] backup grubenv success')

    ret_val = copy_from_agent(RuntimeCtx, grub_file, grub_dst)
    if ret_val != 0:
        log_error_msg('[reconfig_grub_file] copy_from_agent grub_file failed')
        return -1

    log_info_msg('[reconfig_grub_file] copy_from_agent grub_file finish')

    if grub_ver == 2:
        ret_val = copy_from_agent(RuntimeCtx, grubenv_src, grubenv_dst)
        if ret_val != 0:
            log_error_msg('[reconfig_grub_file] copy_from_agent grubenv_src failed')
            return -1
        log_info_msg('[reconfig_grub_file] copy_from_agent grubenv_src finish')

    clrd_name = context['clrd_name']
    vmlinuz_path = context['vmlinuz_path']

    log_info_msg('[reconfig_grub_file] begin chgrub')

    ret_val = chgrub.chgrub(grub_dst, grub_ver, clrd_name, vmlinuz_path)
    if ret_val != 0:
        log_error_msg('[reconfig_grub_file] chgrub failed')
        return -1

    log_info_msg('[reconfig_grub_file] chgrub success')

    ret_val = write_to_agent(RuntimeCtx, grub_dst, grub_file)
    if ret_val != 0:
        log_error_msg('[reconfig_grub_file] write_to_agent grub_file failed')
        return -1

    log_info_msg('[reconfig_grub_file] write_to_agent grub_file finish')

    if grub_ver == 2:
        ret_val = write_to_agent(RuntimeCtx, grubenv_dst, grubenv_src)
        if ret_val != 0:
            log_error_msg('[reconfig_grub_file] write_to_agent grubenv_src failed')
            return -1
        log_info_msg('[reconfig_grub_file] write_to_agent grubenv_src finish')

    log_info_msg('[reconfig_grub_file] success')

    return 0


str_collect_info = 'Collecting agent information, please wait a minute.'
str_prepare_server = 'Prepare server component, prepare driver.'
str_prepare_agent = 'Prepare agent component, install driver'
str_install_agent = 'Install agent compoment, config initrd'
str_config_agent = 'Configure agent compoment.'
str_regitser_svr = 'Register agent service.'

g_InstallStatus = [str_collect_info,
                   str_prepare_server,
                   str_prepare_agent,
                   str_install_agent,
                   str_config_agent,
                   str_regitser_svr]


def setup_agent_thread(session_name, _g, flag_json):
    log_info_msg("setup_agent_thread start")

    RuntimeCtx = {
        'session': session_name,
        '_g': _g,
    }

    success = -1
    state = 0
    total = len(g_InstallStatus)
    tmp_dir = ''

    session = RuntimeCtx['session']
    _g = RuntimeCtx['_g']

    log_info_msg('total = ' + str(total))

    try:

        log_info_msg("setup_agent_thread prepareInfoOnAgentSetup")
        report_install_status(RuntimeCtx, state, total, g_InstallStatus[state])
        sys_config = _g.getBoxPrx().prepareInfoOnAgentSetup(session, '')
        context = json.loads(sys_config)
        log_info_msg(context)

        if 'version' not in context.keys():
            msg_str = 'You are installing by using an old version on a new version AIO, operation is not allowed.'
            report_install_status(RuntimeCtx, state, total, msg_str)
            return -101

        tmp_dir = make_install_dir()
        context['tmp_dir'] = tmp_dir

        # context['disksbd_linux'] = ''
        for driver in g_drivers:
            context[driver['name']] = ''

        log_info_msg("setup_agent_thread make_agent_driver")
        state += 1
        report_install_status(RuntimeCtx, state, total, g_InstallStatus[state])
        ret_val, msg_str = make_agent_driver(RuntimeCtx, context)
        if ret_val != 0:
            log_error_msg('make_agent_driver failed: {}'.format(msg_str))
            report_install_status(RuntimeCtx, state, total, 'Server Error: ' + msg_str)
            return success

        log_info_msg("setup_agent_thread install_agent_module")
        state += 1
        report_install_status(RuntimeCtx, state, total, g_InstallStatus[state])
        ret_val = install_agent_module(RuntimeCtx, context)
        if ret_val != 0:
            log_error_msg('install_agent_module failed...')
            msg_str = 'Server Error: ' + 'install driver failed: {}'.format(ret_val)
            report_install_status(RuntimeCtx, state, total, msg_str)
            return success

        log_info_msg("setup_agent_thread make_agent_initramfs")
        state += 1
        report_install_status(RuntimeCtx, state, total, g_InstallStatus[state])
        ret_val, msg_str = make_agent_initramfs(RuntimeCtx, context)
        if ret_val != 0:
            log_error_msg('make_agent_initramfs failed...')
            msg_str = 'Server Error: ' + 'config initrd failed: {}'.format(msg_str)
            report_install_status(RuntimeCtx, state, total, msg_str)
            return success

        log_info_msg("setup_agent_thread report_install_status")
        state += 1
        report_install_status(RuntimeCtx, state, total, g_InstallStatus[state])
        ret_val = reconfig_grub_file(RuntimeCtx, context)
        if ret_val != 0:
            return success

        state += 1
        report_install_status(RuntimeCtx, state, total, g_InstallStatus[state])
        log_info_msg("setup_agent_thread install success")
        success = 0

    except Exception as e:
        str_msg = "[setup_agent_thread] except --> {}".format(e)
        log_error_msg(str_msg)
        str_msg = 'Server Except: {}'.format(repr(e))
        report_install_status(RuntimeCtx, state, total, str_msg)

    finally:

        log_info_msg(success)
        log_info_msg("call exitOnAgentSetup...")
        _g.getBoxPrx().exitOnAgentSetup(session, success)

        if g_bRemoveDirectory:
            if tmp_dir:
                log_info_msg("call rmtree...")
                shutil.rmtree(tmp_dir)

        log_info_msg("setup_agent_thread finish")

        return success
