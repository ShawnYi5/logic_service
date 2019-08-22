# coding:utf-8
import os
import sys
import platform
import re
import json
import bootent
import crutil
import initlib

_logger = crutil.get_logger('crunch:initfn')

initrd_name_conf = [{'initrd': 'initrd-{knlver}.img',
                     'vmlinuz': 'vmlinuz-{knlver}',
                     'efi_dir': 'efi/EFI',
                     'release': ['cetnos', 'redhat']
                     },

                    {'initrd': 'initramfs-{knlver}.img',
                     'vmlinuz': 'vmlinuz-{knlver}',
                     'efi_dir': 'efi/EFI',
                     'release': ['cetnos', 'redhat']
                     },

                    {'initrd': 'ultrapath-{knlver}.img',
                     'vmlinuz': 'vmlinuz-{knlver}',
                     'efi_dir': 'efi/EFI',
                     'release': ['cetnos', 'redhat']
                     },

                    {'initrd': 'initrd.img-{knlver}',
                     'vmlinuz': 'vmlinuz-{knlver}',
                     'efi_dir': 'efi/efi',
                     'release': ['ubuntu']},

                    {'initrd': 'ultrapath.img-{knlver}',
                     'vmlinuz': 'vmlinuz-{knlver}',
                     'efi_dir': 'efi/efi',
                     'release': ['ubuntu']},

                    {'initrd': 'initrd-{knlver}',
                     'vmlinuz': 'vmlinuz-{knlver}',
                     'efi_dir': 'efi/efi',
                     'release': ['SuSE']},

                    {'initrd': 'ultrapath-{knlver}',
                     'vmlinuz': 'vmlinuz-{knlver}',
                     'efi_dir': 'efi/efi',
                     'release': ['SuSE']}
                    ]


def get_def_init_fns_by_find(root_dir, knl_ver='', use_efi_first=True):
    _logger.debug('get_def_init_fns begin')
    _logger.debug('1 check input params')
    if os.path.isdir(root_dir) is False:
        _logger.error('1.1 check root_dir failed: root_dir={rd}'.format(rd=root_dir))
        return -11, []

    if knl_ver == '':
        tmp_res, knl_ver = crutil.wrap_getstatusoutput('uname -r')
    if len(knl_ver) == 0:
        _logger.debug('1.2 get knl_ver failed: knl_ver={kv}'.format(kv=knl_ver))
        return -12, []

    for i, names in enumerate(initrd_name_conf):

        boot_dir = initlib.get_boot_dir(root_dir)
        initrd_name = names['initrd'].format(knlver=knl_ver)
        vmlinuz_name = names['vmlinuz'].format(knlver=knl_ver)
        efi_dir = names['efi_dir']
        releases_list = names['release']

        _logger.info('boot_dir: {b}, efi_dir: {e}, release: {r}, initrd: {i}, vmlinuz: {v}'.format(
            b=boot_dir, e=efi_dir, r=releases_list, i=initrd_name, v=vmlinuz_name))

        if use_efi_first:
            for release in releases_list:
                efi_bios_initrd_name = os.path.join(boot_dir, efi_dir, release, initrd_name)
                efi_bios_vmlinuz_name = os.path.join(boot_dir, efi_dir, release, vmlinuz_name)

                _logger.info('use_efi_first: try find {fn}'.format(fn=efi_bios_initrd_name))
                if os.path.isfile(efi_bios_initrd_name):
                    _logger.info('find {fn}, {fn1} exist'.format(fn=efi_bios_initrd_name, fn1=efi_bios_vmlinuz_name))
                    return 0, [efi_bios_vmlinuz_name, efi_bios_initrd_name]

        # 如果非efi版本, efi路径肯定搜索不到, 此时,应该用非efi版本
        leg_bios_initrd_name = os.path.join(boot_dir, initrd_name)
        leg_bios_vmlinuz_name = os.path.join(boot_dir, vmlinuz_name)

        if os.path.isfile(leg_bios_initrd_name):
            _logger.info('find {fn}, {fn1} exist'.format(fn=leg_bios_initrd_name, fn1=leg_bios_vmlinuz_name))
            return 0, [leg_bios_vmlinuz_name, leg_bios_initrd_name]

    _logger.error('get_def_init_fns failed end')
    return -1, []


def get_def_init_fns_by_grub(root_dir):
    _logger.debug('crunch: get_def_init_fns begin')

    _logger.debug('1 get grub ver and fn')
    grub_ver, grub_fn = initlib.get_grub_info(root_dir)
    _logger.debug('grub_ver = {ver}, grub_fn = {fn}'.format(ver=grub_ver, fn=grub_fn))
    if grub_ver not in range(1, 2 + 1) or os.path.isfile(grub_fn) is False:
        _logger.debug('1 get grub ver and fn failed: ver={arg1}, fn={arg2}'.format(arg1=grub_ver, arg2=grub_fn))
        return -10, []

    _logger.debug('2 check grubenv')
    if grub_ver == 2:
        grubenv_fn = os.path.join(os.path.dirname(grub_fn), 'grubenv')
        if os.path.exists(grubenv_fn) is False:
            _logger.debug('2 check grubenv failed: fn={arg1} not exist'.format(arg1=grubenv_fn))
            return -12, []

    _logger.debug('3 get grub def entry group and seq')

    def_entry_seq, entry_group = bootent.get_grub_def_entry_ex(grub_fn, grub_ver)
    _logger.debug('def_grub_entry_seq={seq}, grub_entry={ent}'.format(seq=def_entry_seq, ent=entry_group))
    if def_entry_seq < 0 or entry_group is None:
        _logger.debug('2 get grub def entry group and seq failed: error={arg1}'.format(arg1=def_entry_seq))
        return -20, []
    assert len(entry_group) >= 4 and entry_group[3] is True

    _logger.debug('4 get init fns by re')
    ret_fns = list()
    str_list = entry_group[1:3]
    # entry_group返回来的是一个tuple, 是有序的: 前面个是vmlinuz, 后面个是initrd文件
    for i, line in enumerate(str_list):
        reg_exp = bootent.grub_re(grub_ver, i + 1)
        match = re.search(reg_exp, line, re.I)
        if match:
            init_fn = match.group(0)
            if len(init_fn) == 0:
                _logger.debug('4 get init fns by re failed: re={arg1}, line={arg2}'.format(arg1=reg_exp, arg2=line))
                return -40, []
            init_fn = os.path.join(initlib.get_boot_dir(root_dir), os.path.basename(init_fn))
            _logger.debug('find init file: {fn}'.format(fn=init_fn))
            ret_fns.append(init_fn)
        else:
            _logger.debug('4 get init fns by re failed: re={arg1}, line={arg2}'.format(arg1=reg_exp, arg2=line))
            return -41, []

    _logger.debug('crunch: get_def_init_fns end')
    return 0, ret_fns


def get_init_fns_by_json(json_fn):

    if os.path.exists(json_fn):
        _logger.debug("User configed initrd_file: {}".format(json_fn))

        with open(json_fn, 'r') as fd:
            try:
                init_fns = json.load(fd)
                if len(init_fns) != 2 or os.path.exists(init_fns[0]) is False or os.path.exists(init_fns[1]) is False:
                    _logger.error('init_fns.json format error, must be ["full_path_vmlinuz", "full_path_initrd_fn"]')
                    return -1, []
                return 0, init_fns

            except Exception as ex:
                _logger.error('init_fns.json format error, must be ["full_path_vmlinuz", "full_path_initrd_fn"]')
                return -1, []
    else:
        _logger.debug("No user configed initrd_file")
        return -2, []


def get_def_init_fns_type(root_dir, knl_ver=''):

    status, init_fn_def = get_init_fns_by_json('./init_fns.json')
    if status == 0:
        return status, init_fn_def, "by_json"

    knl_ver = knl_ver == '' and platform.release() or knl_ver
    status, init_fn_def = get_def_init_fns_by_grub(root_dir)
    if status == 0 and len(init_fn_def) >= 2:
        for fn in init_fn_def:
            if fn.find(knl_ver) == -1:      # 严重警告
                _logger.warning('Serious Warning: uname={ver} not in {fn1}'.format(ver=knl_ver, fn1=fn))
        _logger.debug('Use default init fns: {}'.format(init_fn_def))
        return 0, init_fn_def, "by_grub"

    _logger.debug("get_def_init_fns_by_grub not find, use get_def_init_fns_by_find")
    status, init_fn_def = get_def_init_fns_by_find(root_dir, knl_ver)
    if status != 0:
        _logger.error("get_def_init_fns_by_find failed, please config ./init_fns.json")
        _logger.debug('./init_fns.json format as ["full_path_vmlinuz", "full_path_initrd_fn"]')
    return status, init_fn_def, "by_enum"


# added at 2019-01-11, for save_clrd_initrd: 原来的get_def_init_fns改为get_def_init_fns_type
def get_def_init_fns(root_dir, knl_ver=''):
    status, init_fn_def, got_type = get_def_init_fns_type(root_dir, knl_ver)
    return status, init_fn_def


# def get_clrd_init_fns(clrd_initrd_json_dir):
#     _logger.info("save_clrd_initrd: get_clrd_init_fns entered: {}".format(clrd_initrd_json_dir))
#
#     init_fn_clrd = list()
#     try:
#         with open(os.path.join(clrd_initrd_json_dir, "clrd_initrd.json"), 'r') as fd:
#             json_obj = json.load(fd)
#         if json_obj is None:
#             raise 'load json obj from {} failed. load return json obj is None'.format(clrd_initrd_json_dir)
#
#         init_fn_clrd.append(json_obj["vmlinuz_path_clrd"])
#         init_fn_clrd.append(json_obj["initrdfs_path_clrd"])
#         saved_md5sum = json_obj["initrdfs_clrd_md5sum"]
#
#         cmd = "md5sum {}".format(json_obj["initrdfs_path_clrd"]) + "|awk '{print $1}'"
#         ret_val, msg_out = crutil.exec_shell_cmd_dir(cmd, os.getcwd())
#         if ret_val != 0:
#             raise "cmd: {} failed: {}".format(cmd, msg_out)
#
#         if saved_md5sum != msg_out[0]:
#             raise "md5sum check failed: saved_md5sum={} cur_md5sum={}".format(saved_md5sum, msg_out[0])
#
#         _logger.info("save_clrd_initrd: get_clrd_init_fns: md5sum check success")
#         return 0, init_fn_clrd
#
#     except Exception as ex:
#         _logger.error("save_clrd_initrd: get_clrd_init_fns failed: {}".format(str(ex)))
#         return -1, init_fn_clrd


if __name__ == "__main__":
    _logger.debug('test initfn entered')

    _status, _clrd_initrd_fns = get_clrd_init_fns(os.getcwd())
    if _status != 0:
        print("get_clrd_init_fns failed")
    print("vmlinuz={}, initrd={}".format(_clrd_initrd_fns[0], _clrd_initrd_fns[1]))

    cur_test_linux = 'centos5'
    _root_dir = '/home/bootrd-dbg/ultra-path/centos72-hw/'
    if platform.system() == 'Windows':  # only for debug on Windows
        _root_dir = os.path.join(r'E:\temp\initramfs-op', cur_test_linux)

    res_int, res_fns = get_def_init_fns(_root_dir)
    print('res_int={arg1}, res_fns={arg2}'.format(arg1=res_int, arg2=res_fns))

    _logger.debug('test initfn exited')
    sys.exit()
