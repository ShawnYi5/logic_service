import fnmatch
import json
import os
import linux_system_locker
import loadIce
import xlogging
import net_common
import sys
import logging
import shutil
import gzip
import argparse
import glob
import copy
try:
    import elf_relink
except ImportError:
    pass


_logger = xlogging.getLogger(__name__)

# 最早的匹配算法：
_CLW_DRIVER_ORG_DB_FILE = r'clerware_linux_drivers.json'

# magic的匹配算法：
_CLW_DRIVER_MAGICS_DB_FILE = 'clerware_linux_driver_magics.json'


# 兼容驱动重链接方法的锁：
_COMPATIBLE_LINUX_DRIVER_LOCKER = r'/run/systemlocker.LogicService.compatible.driver'

# 兼容驱动重新链接的DB
# _CLW_DRIVER_COMPATIBLE_DB_FILE = 'clerware_linux_driver_compatible_vermagic.json'
_CLW_DRIVER_COMPATIBLE_DB_ALL_FILE = 'compatible_*.json'
# 兼容驱动重链接的目标目录：
_COMPATIBLE_DRIVER_PATH = r'/home/ext.aio/compatible.driver/'
# 兼容驱动重链接的符号源文件。
_COMPATIBLE_DRIVER_Module_symvers = "/sbin/aio/logic_service/clerware_linux_Module.symvers/"

# 用户强制匹配的驱动DB
_CLW_DRIVER_USER_COMP_DB_FILE = '/home/clerware_linux_driver_user/clerware_linux_driver_user.json'
# 用户强制匹配的目标目录：
_CLW_DRIVER_USER_COMP_DRIVER_PATH = r'/home/ext.aio/user.compatible.driver/'

g_current_version = r"ver.2.0"

def _get_db_json(json_file):
    if not os.path.isfile(json_file):
        return None
    try:
        with open(json_file) as f:
            return json.load(f)
    except:
        _logger.info(r'drv3: 读取json文件{}异常!'.format(json_file))
        pass

def _write_db_json(json_file, _db):
    with open(json_file, 'w') as file_object:
        file_object.write(json.dumps(_db, ensure_ascii=False, sort_keys=True))

def _get_drv_db(file_name):
    magic_number_json_file = os.path.join(loadIce.current_dir, file_name)
    return _get_db_json(magic_number_json_file)

def _search_in_version_json(db_json, kernel_version, release_version, arch):
    match_entry = None
    match_kernel_entries = list()
    match_release_entries = list()
    # 1. 搜索所有匹配内核版本的条目
    for driver in db_json[r'drivers']:
        if not kernel_version.startswith(driver['kernel_version']) or arch != driver['arch']:
            continue
        match_kernel_entries.append(driver)

    # 2. 如果传入 release_version，优先匹配发行版本
    if release_version:
        release_version_upper = release_version.upper()
        for match_kernel_entry in match_kernel_entries:
            if fnmatch.fnmatch(release_version_upper, match_kernel_entry['release_version'].upper()):
                match_release_entries.append(match_kernel_entry)
    _logger.info('match_release_entries _search_in_version_json{}'.format(len(match_release_entries)))
    if len(match_release_entries) == 0:
        # 如果没有传入 release_version 或 没有匹配上发行版本
        return None

    max_kernel_lenth = 0

    # 3. 匹配最长（精确）的内核版本
    for match_release_entry in match_release_entries:
        if len(match_release_entry['kernel_version']) > max_kernel_lenth:
            max_kernel_lenth = len(match_release_entry['kernel_version'])
    for match_release_entry in match_release_entries:
        if len(match_release_entry['kernel_version']) == max_kernel_lenth:
            match_entry = match_release_entry

    return match_entry


def search_db_json(db_json, kernel_version, release_version, arch):
    if not db_json:
        return None
    return _search_in_version_json(db_json, kernel_version, release_version, arch)


def search_magic_db_json(magic_db_json, version_magic):
    if not magic_db_json:
        return None
    return magic_db_json.get(version_magic, None)


def _search_db_json(db_json, kernel_version, release_version, arch, driver_name):
    if not db_json:
        return None
    return search_db_json(db_json.get(driver_name, None), kernel_version, release_version, arch)


def _search_magic_db_json(magic_db_json, version_magic, driver_name):
    if not magic_db_json:
        return None, None
    driver_real_name = driver_name + '_linux.ko'
    return search_magic_db_json(magic_db_json.get(driver_real_name, None), version_magic), driver_real_name

def get_real_vermagic(ko_file_path):
    if not os.path.isfile(ko_file_path):
        return None
    cmd = 'modinfo "{}"'.format(ko_file_path)
    retval, outs, errinfo = net_common.get_info_from_syscmd(cmd)
    #_logger.info("drv3: runcmd {} return:{} out:{} errorinfo:{}".format(retval, cmd, outs, errinfo))
    if retval != 0:
        str = "runcmd {} return:{} out:{} errorinfo:{}".format(retval, cmd, outs, errinfo)
        raise Exception(str)

    all_lines = outs.split("\n")
    for _l in all_lines:
        if "vermagic:" not in _l:
            continue
        value = _l.replace("vermagic:", " ")
        # 将value前面的空格删除掉。
        for i in range(len(value)):
            if value[i] == ' ':
                continue
            return value[i:]
    return None

def _get_dir_name_from_real_version_magic(real_version_magic):
    return real_version_magic.replace(' ', '.')

import hashlib
def md5Checksum(filePath):
    if os.path.isfile(filePath):
        with open(filePath, 'rb') as fh:
            m = hashlib.md5()
            while True:
                data = fh.read(65536)
                if not data:
                    break
                m.update(data)
            return m.hexdigest()
    return None

def IsSourceFileTheSame(full_ko_file):
    try:
        src_file = full_ko_file + '.src.json'
        src_db = _get_db_json(src_file)
        if src_db is None:
            return False
        if src_db['version'] != g_current_version:
            return False
        _src_file = src_db.get('src_file', None)
        _json_md5 = src_db.get('src_md5', None)
        if _src_file is not None and _json_md5 is not None:
            file_md5 = md5Checksum(_src_file)
            if _json_md5 == file_md5:
                return True
            else:
                _logger.info(r'drv3: 源文件{} md5:{} 不等于 json中的_md5:{}'.format(_src_file, file_md5, _json_md5))
    except:
        pass

    return False

def _get_clerware_compatible_driver(build_drv_path, _real_version_magic, drivers):
    _dir_name = _get_dir_name_from_real_version_magic(_real_version_magic)
    _path_dir = os.path.join(build_drv_path, _dir_name)
    full_ko_file = None
    for drv in drivers:
        full_ko_file = os.path.join(_path_dir, drv['ko_name'])
        if not os.path.isfile(full_ko_file):
            return None
        if not IsSourceFileTheSame(full_ko_file):
            return None
        ko_real_vermagic = get_real_vermagic(full_ko_file)
        if ko_real_vermagic != _real_version_magic:
            return None

    return full_ko_file

def _get_src_driver_from_db(drv_magics_db, srv_vermagic):
    _tmp = drv_magics_db.get("disksbd_linux.ko", None)
    if None is _tmp:
        return None
    return _tmp.get(srv_vermagic, None)

def _make_compatible_driver(src_ko_dir_path, target_ko_dir_path, bd_input, drivers):

    try:
        os.makedirs(target_ko_dir_path)
    except:
        pass
    _elf_relink = elf_relink.ElfRelink(bd_input)
    for drv in drivers:
        _src_ko_file = os.path.join(src_ko_dir_path, drv['ko_name'])
        _full_ko_file = os.path.join(target_ko_dir_path, drv['ko_name'])

        _elf_relink.do_work(_src_ko_file, _full_ko_file)

        src_db = dict()
        src_db['src_file'] = _src_ko_file
        src_db['src_md5'] = md5Checksum(_src_ko_file)
        src_db['version'] = g_current_version
        _write_db_json(_full_ko_file + '.src.json', src_db)

    return

def _safe_clean_dirtree(remove_dir_tree):
    # 不相同，删除目录，并改变之。
    if remove_dir_tree is None:
        return
    if len(remove_dir_tree) < 6:
        return
    try:
        shutil.rmtree(remove_dir_tree)
    except:
        pass
    try:
        os.makedirs(remove_dir_tree)
    except:
        pass
    return

def multi_file_md5Checksum(file_list):
    file_list_md5 = copy.copy(file_list)
    file_list_md5.sort()
    md5_mfile = hashlib.md5()
    for _ in file_list_md5:
        md5 = md5Checksum(_)
        md5_mfile.update(md5.encode())
    return md5_mfile.hexdigest()

def clean_update_cache_file(db_file, cache_dir):

    if cache_dir is None:
        return
    if len(cache_dir) < 10:
        return

    _cache_json_db = os.path.join(cache_dir, 'cache.json')

    md5_now = multi_file_md5Checksum(db_file)
    cache_src = _get_db_json(_cache_json_db)
    if cache_src is not None:
        if md5_now == cache_src.get('src_md5', None) and \
                g_current_version == cache_src.get('version', None):
            # 相同，未有改变。
            return

    _safe_clean_dirtree(cache_dir)

    cache_src = dict()
    cache_src['src_file'] = db_file
    cache_src['src_md5'] = md5_now
    cache_src['version'] = g_current_version
    _write_db_json(_cache_json_db, cache_src)

def print_same_vermagic(base_dict, add_dict, file_name):
    for _key, _v in add_dict.items():
        if _key in base_dict:
            _logger.info(r'drv3: warning: 文件:{}中与别的文件有重复的vermagic({})'.format(file_name, _key))
            continue

def _get_clerware_driver_compatible_vermagic(drv_magics_db, build, real_version_magic, drivers, vmfile):
    db_file_list = build["DbFile"]
    build_drv_path = build["BuildDir"]
    clean_update_cache_file(db_file_list, build_drv_path)
    compatible_db = dict()
    for _one in db_file_list:
        _new = _get_db_json(_one)
        if _new is not None:
            print_same_vermagic(compatible_db, _new, _one)
            compatible_db.update(_new)

    if len(compatible_db) <= 0:
        _logger.info(r'drv3: 没有json文件:{}，忽略，使用空内容!'.format(db_file_list))

    # 这里加锁是因为要建立文件，并且之后一直用这个文件。
    with linux_system_locker.LinuxSystemLocker(_COMPATIBLE_LINUX_DRIVER_LOCKER):
        ko_file_path = _get_clerware_compatible_driver(build_drv_path, real_version_magic, drivers)
        if ko_file_path is not None:
            # 之前已经存了文件。
            _logger.info(r'drv3: 找到兼容驱动({}),vermagic({})'.format(ko_file_path, real_version_magic))
            return ko_file_path

        _target_vermagic = compatible_db.get(real_version_magic, None)
        if _target_vermagic is None:
            _logger.info(r'drv3: 从文件:({})中没有找到({})的兼容项，尝试加入ClerwareBuildOrgDriver'
                         r''.format(db_file_list, real_version_magic))
            _target_vermagic = dict()
            _target_vermagic['src_vermagic'] = real_version_magic + 'ClerwareBuildOrgDriver01234567890123456789'
        else:
            _logger.info(r'drv3: 从文件:({})中找到的兼容项:({})'.format(db_file_list, _target_vermagic))

        if 'src_vermagic' not in _target_vermagic:
            _logger.info(r'drv3: 兼容项({})中不包含关键字:"src_vermagic"'.format(_target_vermagic))
            return None

        _src_drv_dir_name = _get_src_driver_from_db(drv_magics_db, _target_vermagic['src_vermagic'])
        if _src_drv_dir_name is None:
            _logger.info(r'drv3: clerware_linux_driver_magics.json文件中没有找到vermagic({}) from '.format(
                _target_vermagic['src_vermagic']))
            return None

        _src_ko_dir = os.path.join(loadIce.current_dir, 'clerware_linux_drivers', _src_drv_dir_name)

        bd_input = dict()
        bd_input['vermagic'] = real_version_magic
        if 'sym_file' in _target_vermagic:
            bd_input['sym_file'] = os.path.join(_COMPATIBLE_DRIVER_Module_symvers, _target_vermagic['sym_file'])

        if vmfile is not None:
            bd_input['vm_file'] = vmfile

        if 'sym_file' not in bd_input and 'vm_file' not in bd_input:
            # sym_file 和 vmfile 都没有的时候，就不能产生新的ko
            _logger.info(r'drv3:  没有sym_file或vm_file({})'.format(bd_input))
            return None

        _target_ko_dir_path = os.path.join(build_drv_path, _get_dir_name_from_real_version_magic(real_version_magic))

        try:
            _make_compatible_driver(_src_ko_dir, _target_ko_dir_path, bd_input, drivers)
        except Exception as e:
            _logger.info(r'drv3: 编译兼容驱动失败:({})'.format(e))

        ko_file_path = _get_clerware_compatible_driver(build_drv_path, real_version_magic, drivers)
        if ko_file_path is not None:
            # 之前已经存了文件。
            return ko_file_path
    return None

def get_disksbd_ko(kernel_version, release_version, arch, version_magic, drivers, real_version_magic, vmfile):
    """
    得到  disksbd.ko 的绝对路径
    :param kernel_version: linux 内核版本
    :param release_version: linux 发行版本
    :param arch: "32" "64" "32_PAE"  x86 or x86_64 or x86_PAE
    :param version_magic: linux 魔数
    :return: 成功返回路径，失败抛出异常
    """


    if version_magic and len(version_magic) >= 3:
        relative_path, real_driver_name = _search_magic_db_json(_get_drv_db(_CLW_DRIVER_MAGICS_DB_FILE),
                                                                version_magic, r'disksbd')
        if relative_path:
            return os.path.join(loadIce.current_dir, 'clerware_linux_drivers', relative_path, real_driver_name)
        else:
            _logger.info(r'drv3: 不能从clerware_linux_driver_magics.json找到编译的驱动version_magic : {} from '.format(
                version_magic))

    if real_version_magic and len(real_version_magic) >= 3:
        # 看能不能生成一个。
        list_compatible_file = glob.glob(os.path.join(_COMPATIBLE_DRIVER_Module_symvers,_CLW_DRIVER_COMPATIBLE_DB_ALL_FILE))

        list_user_file = [_CLW_DRIVER_USER_COMP_DB_FILE]

        clw_build = {"DbFile": list_compatible_file,
                        "BuildDir": _COMPATIBLE_DRIVER_PATH}
        usr_build = {"DbFile":list_user_file,
                        "BuildDir":_CLW_DRIVER_USER_COMP_DRIVER_PATH}
        _drv_compatible_db_file = [clw_build, usr_build]
        for _build in _drv_compatible_db_file:
            try:
                relative_driver_file = _get_clerware_driver_compatible_vermagic(_get_drv_db(_CLW_DRIVER_MAGICS_DB_FILE),
                                                                                _build,
                                                                                real_version_magic, drivers, vmfile)
                if relative_driver_file:
                    _logger.info(r'drv3: 用({})编译兼容驱动成功:({})'.format(_build["DbFile"], relative_driver_file))
                    return relative_driver_file

                _logger.info(r'drv3: 用({})编译兼容驱动失败!'.format(_build["DbFile"]))
            except Exception as ex:
                _logger.info(r'drv3: 用({})编译兼容驱动失败异常:{}'.format(_build["DbFile"], ex))

            continue
    else:
        _logger.info(r'drv3: 客户端没有上报real_version_magic:{}'.format(real_version_magic))

    #

    xlogging.raise_system_error(r'drv3: 不支持的Linux内核：{}'.format(kernel_version),
                                    r'drv3: get_disksbd_ko failed : {} {}'.format(kernel_version, release_version), 1)
    return


def make_compatible_drv_from_dir(_input_str):

    modules_dir = sym_dir = _input_str['dir']
    _tmp = sym_dir.split(r"/")
    sym_pre_name = _tmp[len(_tmp) - 1]

    ko_dir_list = list()
    for _one in os.listdir(modules_dir):
        if os.path.isfile(os.path.join(modules_dir, _one)):
            continue
        ko_dir_list.append(_one)

    _all_comp_drv = dict()
    _len_of_sym = len(sym_pre_name)
    for _one_file in os.listdir(sym_dir):

        if not os.path.isfile(os.path.join(sym_dir, _one_file)):
            continue
        if len(_one_file) < _len_of_sym:
            continue
        if _one_file[0:_len_of_sym] != sym_pre_name:
            continue

        # _logger.info(r'file:{}'.format(_one_file))
        kernel_name = _one_file.replace(sym_pre_name, '')
        kernel_name = kernel_name.replace(".gz", '')
        kernel_name = kernel_name.strip().strip(' ')

        floopy_ko = os.path.join(modules_dir, kernel_name, "kernel/drivers/block/floppy.ko" )
        ko_real_vermagic = get_real_vermagic(floopy_ko)
        if ko_real_vermagic is None:
            floopy_ko = os.path.join(modules_dir, kernel_name, "floppy.ko")
            ko_real_vermagic = get_real_vermagic(floopy_ko)
            if ko_real_vermagic is None:
                _logger.info(r'no kofile:{}'.format(floopy_ko))
                return
        if kernel_name not in ko_dir_list:
            _logger.info(r'kernel:{} no modules'.format(kernel_name))

        ko_dir_list.remove(kernel_name)

        _one_ver = dict()
        _one_ver['src_vermagic'] = ko_real_vermagic + "ClerwareBuildOrgDriver01234567890123456789"
        _one_ver['sym_file'] = _one_file

        #_logger.info(r'vermagic:{}: {} '.format(ko_real_vermagic, _one_ver))

        _all_comp_drv[ko_real_vermagic] = _one_ver

    if len(ko_dir_list) > 0:
        _logger.info(r'error {} need sym: {}'.format(sym_pre_name, ko_dir_list))
        return

    json_file_path = "/home/compatible_{}.json".format(sym_pre_name)
    _write_db_json(json_file_path, _all_comp_drv)
    print("ok")

if __name__ == '__main__':

    _logger.addHandler(logging.StreamHandler(sys.stdout))

    import Initramfs
    '''
    print(get_disksbd_ko('3.10.0',
                         '3.19.0-25-generic SMP mod_unload modversions 686 |mockbuild@c6b9.bsys.dev.centos.org',
                         '32',
                         '3.19.0-25-generic SMP mod_unload modversions 686',
                         Initramfs.get_sbd_driver_config(),
                         '3.19.0-25-generic SMP mod_unload modversions 686 ',
                         "/mnt/vmlinuz-3.19.0-25-generic"
                         ))
    '''
    if True:
        print(get_disksbd_ko('3.10.0',
                         '4.1.0-1.nk.12.x86_64 SMP mod_unload  |mockbuild@c6b9.bsys.dev.centos.org',
                         '64',
                         '3.12.11-201.nk.1.i686.PAE SMP mod_unload 686',
                         Initramfs.get_sbd_driver_config(),
                         '3.10.0-123.13.2.el7.x86_64 SMP mod_unload modversions ', #4.4.0-24-generic SMP mod_unload modversions ',
                         "/mnt/vmlinuz-3.12.11-201.nk.1.i686.PAE"
                         ))

    # 获取命令行参数
    def get_cmd_args():
        args_parser = argparse.ArgumentParser(
            description="python clerware_linux_driver.py -boot_dir /xxx/ -modules_dir /xxx/ -sym_name abi")
        args_parser.add_argument("-dir", metavar='modules_dir', required=True, help="modules and boot DIR")
        cmd_args = args_parser.parse_args()
        return cmd_args

    args = get_cmd_args()
    _input = dict()
    _input['dir'] = args.dir

    _logger.info("drv3: start  input:{}".format(_input))

    '''  -modules_dir  /home/zy/ubuntu/Ubuntu/ubuntu-10.04-x64 -sym_name ubuntu-10.04.x-x64- -sym_dir /home/zy/ubuntu/Ubuntu/ubuntu-10.04-x64 
    '''
    make_compatible_drv_from_dir(_input)
