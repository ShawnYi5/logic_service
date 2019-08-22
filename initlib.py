# coding:utf-8
import os
import sys
import pdb
import platform
import crutil
import re

_logger = crutil.get_logger('initlib')


def get_boot_dir(root_dir):
    return os.path.join(root_dir, 'boot')


def join_link_path(root_dir, link_path):
    """
    only for server combine the link path
    :param root_dir: the server mounted rootpath, if localhost, the rootdir is '/'
    :param link_path: readlink returned ln
    :return: combined dir
    """
    match = re.search('/[a-z]]', link_path, re.I)
    if match:
        return os.path.join(root_dir, link_path[match.span()[0]:])
    return os.path.join(root_dir, link_path.replace(r'../', '').replace(r'./', ''))


# 这个函数在当时的了解下写出来, 应该是不准确的, 但不准确没关系, 及时这里失败了, 我们可以通过配置文件来找到
# 配置文件有内部配置文件: initfn.initrd_name_conf, 也可以通过外部json文件直接指定.

def get_grub_info_new(root_dir):
    """
    get grub info: type - grub or grub2, conf file path
    :return: tuple(type[1, 2], fn), error:(-1, '')
    """
    _logger.debug("get_grub_info_new enter: {}".format(root_dir))

    grub_ver_cmd = ["grub-install -v",              # legacy grub, ver 0.97
                    "grub-install -V",              # ubuntu always use this
                    "grub2-install -V",             # grub2
                    "grub-install.unsupported -v"   # SuSE take over by YaST
                    ]
    grub_ver_cmd_grep = ["|grep '[0]\.'", "|grep '[1-9]\.'"]

    grub_ver = -1
    for cmd in grub_ver_cmd:
        for i, grep in enumerate(grub_ver_cmd_grep):
            res, out = crutil.wrap_getstatusoutput(cmd + grep)
            if res == 0:
                grub_ver = i + 1
                break
        if grub_ver != -1:
            break

    _logger.debug("crunch: get_grub_info find grub_ver={}".format(grub_ver))

    # 这个列表是有顺序的, 首先从grub, 再到efi进行枚举.
    # 而且早期版本, 通常menu.lst->./grub.conf, centos5.x, oracle linux 5.x

    grub_files = [(1, "boot/grub/grub.conf"),
                  (2, "boot/grub/grub.cfg"),    # ubuntu, grub2, dir name is grub
                  (2, "boot/grub2/grub.conf"),
                  (2, "boot/grub2/grub.cfg"),
                  (1, "boot/grub/menu.lst"),
                  (1, "boot/grub2/menu.lst"),
                  (2, "boot/efi/EFI/centos/grub.cfg"),
                  (2, "boot/efi/EFI/redhat/grub.cfg"),
                  (1, "boot/efi/EFI/SuSE/elilo.conf"),  # suse 11
                  (1, "boot/efi/EFI/sles/grub.cfg"),  # sles 12, 这个确实是正在的grub, 但source /grub2/grub.cfg
                  (1, "boot/efi/EFI/ubuntu/grub.cfg"),
                  (1, "etc/grub.conf"),
                  (2, "etc/grub2.cfg"),
                  (2, "etc/grub.cfg")
                  ]

    _logger.debug("crunch: get_grub_info find grub file from: {}".format(grub_files))

    grub_fn = ""
    for (ver, file) in grub_files:
        abs_file = os.path.join(root_dir, file)
        if os.path.exists(abs_file):
            grub_ver = ver if grub_ver == -1 else grub_ver
            grub_fn = abs_file
            if os.path.islink(grub_fn):
                grub_fn = os.path.join(os.path.dirname(abs_file), os.readlink(abs_file))
            break

    _logger.debug("get_grub_info_new leaved: {} {}".format(grub_ver, grub_fn))
    return grub_ver, grub_fn


def get_grub_info(root_dir):
    """
    get grub info: type - grub or grub2, conf file path
    :return: tuple(type[1, 2], fn), error:(-1, '')
    """

    _logger.debug('crunch: get_grub_info begin')

    _logger.debug('crunch: get_grub_info root_dir=' + root_dir)

    ver = -1
    conf_fn = ''

    for i in range(0, 1):
        rtdir_boot = get_boot_dir(root_dir)
        conf_fn = os.path.join(rtdir_boot, 'grub2', 'grub.cfg')
        if os.path.isfile(conf_fn):
            ver = 2
            break

        # ubuntu 16.04
        conf_fn = os.path.join(rtdir_boot, 'grub', 'grub.cfg')
        if os.path.isfile(conf_fn):
            ver = 2
            break

        conf_fn = os.path.join(rtdir_boot, 'grub', 'grub.conf')
        if os.path.isfile(conf_fn):
            ver = 1
            break

        conf_fn = os.path.join(rtdir_boot, 'grub', 'menu.lst')
        if os.path.isfile(conf_fn):
            ver = 1
            break

        conf_fn = os.path.join(rtdir_boot, 'efi', 'EFI', 'centos', 'grub.cfg')
        if os.path.isfile(conf_fn):
            ver = 2
            break

        conf_fn = os.path.join(rtdir_boot, 'efi', 'EFI', 'redhat', 'grub.cfg')
        if os.path.isfile(conf_fn):
            ver = 2
            break

        etc_link = os.path.join(root_dir, r'/etc/grub.conf')
        if os.path.exists(etc_link) and os.path.islink(etc_link):
            # the readlink return maybe ../boot/grub2.conf or ./boot/grub2.conf
            conf_fn = join_link_path(root_dir, os.readlink(etc_link))
            if os.path.isfile(conf_fn):
                ver = 1
                break

        etc_link = os.path.join(root_dir, r'/etc/grub2.cfg')
        if os.path.exists(etc_link) and os.path.islink(etc_link):
            conf_fn = join_link_path(root_dir, os.readlink(etc_link))
            if os.path.isfile(conf_fn):
                ver = 2
                break

        # the grub2 link in /etc is grub2.cfg, link to /boot/grub2/grub.cfg
        cmd = r"find {etc} |grep -E '(grub2\.cfg|grub\.conf)'".format(etc=os.path.join(root_dir, '/etc'))
        tmp_res, out_str = crutil.wrap_getstatusoutput(cmd)
        if tmp_res != 0 or os.path.isfile(out_str) is False:   # the find result is absolute path, do not join
            break
        conf_fn = join_link_path(root_dir, os.readlink(out_str))
        if os.path.isfile(os.path.join(root_dir, conf_fn)) is False:
            break
        if conf_fn.find('grub2.cfg') != -1:
            ver = 2
            break
        else:
            ver = 1
            break

    if ver == -1:
        ver, conf_fn = get_grub_info_new(root_dir)
        _logger.debug("use get_grub_info_new: {}, {}".format(ver, conf_fn))

    _logger.debug('get_grub_info:ver={arg1},fn={arg2}'.format(arg1=ver, arg2=os.path.join(root_dir, conf_fn)))
    _logger.debug('crunch: get_grub_info succ end')
    return ver, conf_fn


def get_grub2_def_entry(grub2_conf_fn):
    """
    grep grubenv to get default menuentry
    the function use grub2 abspath to get grubenv fn, same dir the grub2.cfg and grubenv
    important note: the grep result maybe has left blank and right \n
    :param grub2_conf_fn: grub2.cfg abspath
    :return: str: number or text title, or '' if failed
    """
    assert os.path.isfile(grub2_conf_fn)

    grub_dir = os.path.dirname(grub2_conf_fn)
    grubenv_fn = os.path.join(grub_dir, 'grubenv')
    cmd = "grep -Ei '(^[[:blank:]][[:blank:]]*saved_entry|^saved_entry)[[:blank:]]*=' {arg1} ".format(arg1=grubenv_fn)
    cmd += "|cut -d '=' -f2"
    tmp_res, tmp_lines = crutil.exec_shell_cmd_status(cmd)
    if platform.system() == 'Windows':
        tmp_lines = read_grep_result_on_windows(grub2_conf_fn, 'grepres_env.txt')
        assert len(tmp_lines) > 0
        return tmp_lines[0].lstrip(' ').rstrip('\n').rstrip(' ')
    else:
        if len(tmp_lines) > 0:
            return tmp_lines[0].lstrip(' ').rstrip('\n').rstrip(' ')
        else:
            return '0'


def get_grub1_def_entry(grub1_conf_fn):
    assert os.path.isfile(grub1_conf_fn)
    cmd = r"grep -Ei '(^[[:blank:]][[:blank:]]*default|^default)[[:blank:]]*=[[:blank:]]*[0-9]'"
    cmd += " {arg1}|cut -d '=' -f2".format(arg1=grub1_conf_fn)
    tmp_res, tmp_lines = crutil.exec_shell_cmd_status(cmd)
    if platform.system() == 'Windows':
        tmp_lines = read_grep_result_on_windows(grub1_conf_fn, 'grepres_def.txt')
        assert len(tmp_lines) > 0
        return tmp_lines[0].lstrip(' ').rstrip('\n').rstrip(' ')
    else:
        if len(tmp_lines) > 0:
            return tmp_lines[0].lstrip(' ').rstrip('\n').rstrip(' ')
        else:
            return '0'


def get_grub_def_entry(grub_ver, grub_fn):
    assert grub_ver == 1 or grub_ver == 2
    def_entry_tmp = ''
    def_entry_seq = -1
    def_entry_text = ''
    def_entry_type = 'number'
    if grub_ver == 1:
        def_entry_tmp = get_grub1_def_entry(grub_fn)
        if def_entry_tmp.isdigit() is True:
            def_entry_seq = int(def_entry_tmp)
        else:
            def_entry_seq = 0   # if the fuck format: default=1xxx
    else:
        def_entry_tmp = get_grub2_def_entry(grub_fn)
        if def_entry_tmp.isdigit() is True:
            def_entry_seq = int(def_entry_tmp)
        else:
            def_entry_text = def_entry_tmp
            def_entry_type = 'text'

    _logger.debug('def_entry: type={arg1}, seq_text={arg2}'.format(arg1=def_entry_type, arg2=def_entry_tmp))

    return def_entry_type, def_entry_seq, def_entry_text


def get_def_initramfs_fn(root_dir):
    """
    这个函数没有用了, 现在用的是initfn.get_def_init_fns
    parse the grub.conf[grub.cfg] to determine the initrd/initramfs fn
    :return: absolute path if success, or ''
    """
    _logger.debug('crunch: get_def_initramfs_fn begin')

    _logger.debug('1 get grub ver and fn')

    grub_ver, conf_fn = get_grub_info(root_dir)
    if grub_ver == -1 or len(conf_fn) == 0:
        _logger.debug('1 get grub ver and fn failed: no grub.conf|grub2.cfg found')
        return ''

    _logger.debug('2 get default boot entry')

    menuen_str = grub_ver == 1 and 'title' or 'menuentry'
    initrd_str = 'initrd'   # format cmd need not initrd16's 16, reg exp will match[0-9]
    boot_entry_type, boot_entry_seq, boot_entry_title = get_grub_def_entry(grub_ver, conf_fn)

    # only for log
    if boot_entry_type == 'number':
        dbg_tmp = 'find by number={arg1}'.format(arg1=boot_entry_seq)
    else:
        dbg_tmp = 'find by text={arg1}'.format(arg1=boot_entry_title)
    _logger.debug('2 get default boot entry: {}, flag={},{}'.format(dbg_tmp, menuen_str, initrd_str))

    _logger.debug('3 grep to get menuentry and initrd')

    # reg_exp: [:blank:]{0, >0}menuentry|menuentry begin and [:blank:]{0, >0} not[_]
    # "cat /boot/grub2/grub.cfg |grep -E
    # '(^[[:blank:]][[:blank:]]*menuentry|^menuentry)[[:blank:]]*[^_]|
    # (^[[:blank:]][[:blank:]]*initrd|^initrd)[0-9 ].*img'"

    cmd = 'cat {arg1} |grep -E '.format(arg1=conf_fn)
    cmd += "'(^[[:blank:]][[:blank:]]*{arg2}|^{arg3})[[:blank:]]*[^_]|".format(arg2=menuen_str, arg3=menuen_str)
    cmd += "(^[[:blank:]][[:blank:]]*{arg4}|^{arg5})[0-9 ].*img'".format(arg4=initrd_str, arg5=initrd_str)
    tmp_res, tmp_lines = crutil.exec_shell_cmd_status(cmd)
    if len(tmp_lines) == 0 and platform.system() != 'Windows':     # nothing greped
        _logger.debug('3 grep to get menuentry and initrd, greped nothing, cmd={arg1}'.format(arg1=cmd))
        return ''

    if platform.system() == 'Windows':  # only for debug on windows
        tmp_lines = read_grep_result_on_windows(conf_fn, 'grepres.txt')
        assert len(tmp_lines) > 0

    found_seq = 0
    initramfs_fn = ''
    for i in range(len(tmp_lines)):
        if tmp_lines[i].find(menuen_str) != -1:
            bcond_seq = boot_entry_type == 'number' and found_seq == boot_entry_seq
            found_seq += 1
            # can't direct str.find(title), add 'title':
            # if entry1 include entry2, but we want entry2, then we will get entry1's initrd[16]
            # if entry1_title == entry2_title, we get the first one has no wrong
            bcond_txt = boot_entry_type == 'text' and tmp_lines[i].find(r"'{}'".format(boot_entry_title)) != -1
            if bcond_seq or bcond_txt:
                if i == len(tmp_lines) - 1:
                    break
                if tmp_lines[i + 1].find(initrd_str) != -1:
                        # match = re.search(r'/((\S)+).img', tmp_lines[i + 1], re.I)
                        match = re.search(r'(?<=/)([\S]+){1}', tmp_lines[i + 1], re.I)
                        if match:
                            initramfs_fn = os.path.join(get_boot_dir(root_dir), os.path.basename(match.group(0)))
                            break

    if len(initramfs_fn) > 0 and os.path.isfile(initramfs_fn):
        _logger.debug(r'crunch: get_def_initramfs_fn succed end: {}'.format(initramfs_fn))
    else:
        _logger.debug(r'crunch: get_def_initramfs_fn failed end: {}'.format(initramfs_fn))

    return initramfs_fn


def read_grep_result_on_windows(grub_fn, grepres_fn):
    fn = os.path.join(os.path.dirname(grub_fn), grepres_fn)
    with open(fn, 'r') as fd:
        return fd.readlines()


#======================================================================================================================
# test main
#======================================================================================================================


if __name__ == "__main__":

    import logging.config
    logging.config.fileConfig(crutil.stdout_fn())
    _logger.debug('crunch: test initlib entered')

    cur_test_linux = 'centos5'
    g_root_dir = '/home/bootrd-dbg/ultra-path/centos72-hw/'
    if platform.system() == 'Windows': # only for debug on Windows
        g_root_dir = os.path.join(r'E:\temp\initramfs-op', cur_test_linux)

    g_initramfs_fn = get_def_initramfs_fn(g_root_dir)
    _logger.debug('get_def_initramfs_fn: {}'.format(g_initramfs_fn))
    crutil.dbg_break()

    _logger.debug('crunch: test initlib exited')
    sys.exit(0)