# coding:utf-8
import os
import sys
import pdb
import platform
import crutil
import initlib

# if have clerware flag, do not change, and same check with vmlinuz and initramfs

# known defect: we don't handle the senario:
#   the clerware rd is running --> the user changed the default grub menuentry and not restart -->
#   we backuped changed grub --> recovery this state --> then grub's default menuentry is not clerware

_logger = crutil.get_logger('bootent')


def grub_cs(v, s):
    assert v in range(1, 3) and s in range(0, 3)
    grub_str = [['title', 'kernel', 'initrd'], ['menuentry', 'linux', 'initrd']]
    return grub_str[v-1][s]


def grub_re(v, s):
    assert v in range(1, 3) and s in range(0, 3)
    # title_entry diff and kernel_linux, initrd_16 same between grub1 and grub2
    #reg_exp = [[r"[^(title)(\s{1})](.*)", r'(?<=/)([\S]+){1}', r'(?<=/)\S+.img'],
    #           [r"(?<=').*?(?=')",  r'(?<=/)([\S]+){1}', r'(?<=/)\S+.img']]
    reg_exp = [[r"[^(title)(\s{1})](.*)", r'(?<=/)([\S]+){1}', r'(?<=/)([\S]+){1}'],
               [r"(?<=').*?(?=')",  r'(?<=/)([\S]+){1}', r'(?<=/)([\S]+){1}']]
    return reg_exp[v-1][s]


def get_grub_def_entry_ex(grub_fn, grub_ver):
    """
    1 grep menuentry/title, linux16/kernel, initrd16/initrd on grub.conf/grub.cfg with line-no on
    2 group by (menuentry/title, linux16/kernel, initrd16/initrd)
    3 find the defualt, bypass filter and fix the error default menuentry/seq setting
    Note important: if grub2, ensure the grubenv exist and at the same dir
    The callee must self ensure the initramfs and vmlinuz_fn is a valid linux file name
    :param grub_fn: grub.conf/grub.cfg file name - abspath, use get_grub_info to get it
    :param grub_ver: grub version, use get_grub_info to get it
    :return: return tuple(default boot_seq, default (menuentry/title, linux16/kernel, initrd16/initrd))
    """

    _logger.debug('crunch: get_boot_entry begin')

    _logger.debug('1 check in-args')

    if os.path.exists(grub_fn) is False:
        _logger.debug('1.1 check in-args failed: grub_fn={arg1} not exist'.format(arg1=grub_fn))
        return -10, None

    if grub_ver != 1 and grub_ver != 2:
        _logger.debug('1.2 check in-args failed: grub_ver={arg1} invalid'.format(arg1=grub_ver))
        return -11, None

    if grub_ver == 2:
        grubenv_fn = os.path.join(os.path.dirname(grub_fn), 'grubenv')
        if os.path.exists(grubenv_fn) is False:
            _logger.debug('1.2 check in-args failed: grubenv={arg1} not exist'.format(arg1=grubenv_fn))
            return -12, None

    _logger.debug('2 match grub spec-strs')

    # use regualar exp match menuentry/titil, kernel/linux16, initrd/initrd16

    v = grub_ver
    cmd = "grep -nE "
    cmd += '"(^[[:blank:]][[:blank:]]*{arg1}|^{arg2})[[:blank:]]*[^_]|'.format(arg1=grub_cs(v, 0), arg2=grub_cs(v, 0))
    cmd += '(^[[:blank:]][[:blank:]]*{arg1}|^{arg2})[[:blank:]]*[^_]|'.format(arg1=grub_cs(v, 1), arg2=grub_cs(v, 1))
    cmd += '(^[[:blank:]][[:blank:]]*{arg1}|^{arg2})[[:blank:]]*[^_]"'.format(arg1=grub_cs(v, 2), arg2=grub_cs(v, 2))
    cmd += ' {arg1}'.format(arg1=grub_fn)
    if platform.system() == 'Windows':
        tmp_lines = initlib.read_grep_result_on_windows(grub_fn, 'grepres_n.txt')
        assert len(tmp_lines) > 0
    else:
        tmp_int, tmp_lines = crutil.exec_shell_cmd_status(cmd)
        if tmp_int != 0 or len(tmp_lines) == 0:
            _logger.debug('2.1 match grub spec-strs failed: res={}, lines={}'.format(tmp_int, tmp_lines))
            return -20, None

    entry_list = list()
    tmp_int = len(tmp_lines)
    valid_entries = 0
    for i in range(0, tmp_int):
        # can't compare togethor, as menuentry exist, we shall treat it as a seq
        kernel_linux = initrd_16 = ''
        sub_count = 0
        if tmp_lines[i].find(grub_cs(v, 0)) != -1:
            entry_title = tmp_lines[i]
            if ((i + 1) < tmp_int) and (tmp_lines[i + 1].find(grub_cs(v, 1)) != -1):
                kernel_linux = tmp_lines[i + 1]
                sub_count += 1
            if ((i + 2) < tmp_int) and (tmp_lines[i + 2].find(grub_cs(v, 2)) != -1):
                initrd_16 = tmp_lines[i + 2]
                sub_count += 1
            if sub_count == 2:
                entry_list.append((entry_title, kernel_linux, initrd_16, True))
                valid_entries += 1
            else:
                entry_list.append((entry_title, kernel_linux, initrd_16, False))

    if 0 == len(entry_list) or 0 == valid_entries:
        _logger.debug('2.1 match grub spec-strs failed: entry_list={arg1}'.format(arg1=entry_list))
        return -21, None

    _logger.debug('3 get default entry')

    def_entry_type, def_entry_seq, def_entry_text = initlib.get_grub_def_entry(grub_ver, grub_fn)

    _logger.debug('4 match default entry line no')

    if def_entry_type == 'number':
        if def_entry_seq in range(0, len(entry_list)):
            if entry_list[def_entry_seq][3] is False:
                _logger.debug('4 match default entry line no failed, matched entry has error, detail:')
                _logger.debug('4 seq={arg1},entry={arg1}'.format(arg1=def_entry_seq, arg2=entry_list[def_entry_seq]))
                return -40, None
        else:
            if entry_list[0][3]:
                def_entry_seq = 0
            else:
                _logger.debug('4 match default entry line no failed, no matched seq but 0 item has error, detail:')
                _logger.debug('4 seq={arg1},entry={arg1}'.format(arg1=0, arg2=entry_list[0]))
                return -41, None
    else:
        assert def_entry_type == 'text' and len(def_entry_text) > 0
        def_entry_seq = -1
        for i in range(0, len(entry_list)):
            if entry_list[i][0].find(def_entry_text) != -1:
                if entry_list[i][3]:
                    def_entry_seq = i
                    break
        if def_entry_seq == -1:
            if entry_list[0][3]:
                def_entry_seq = 0
            else:
                _logger.debug('4 match default entry line no failed, no matched text but 0 item has error, detail:')
                _logger.debug('4 seq={arg1},entry={arg1}'.format(arg1=0, arg2=entry_list[0]))
                return -42, None

    _logger.debug('^-^: get_boot_entry succ end, detail')
    _logger.debug('def_seq={arg1}, def_entry={arg2}'.format(arg1=def_entry_seq, arg2=entry_list[def_entry_seq]))

    # _logger.debug('5 copy and new entry')
    # assert entry_list[def_entry_seq][3]
    # line = entry_list[def_entry_seq][0]
    # begin_lnno = int(line[0:line.find(':')])
    # line = entry_list[def_entry_seq][2]
    # end_lnno = int(line[0:line.find(':')])

    _logger.debug('crunch: get_boot_entry succ end')
    return def_entry_seq, entry_list[def_entry_seq]


# ======================================================================================================================
# test main
# ======================================================================================================================


if __name__ == "__main__":

    _logger.debug('test chgrub entered')
    cur_test_osver = 7
    g_os_name = ['centos5', 'centos6', 'centos7']
    g_root_dir = r'/'
    if platform.system() == 'Windows':  # only for debug on Windows
        g_root_dir = os.path.join(r'E:\temp\initramfs-op', g_os_name[cur_test_osver - 5])

    g_grub_ver, g_grub_fn = initlib.get_grub_info(g_root_dir)
    get_grub_def_entry_ex(g_grub_fn, g_grub_ver)

    crutil.dbg_break()

    _logger.debug('test chgrub exited')
    sys.exit(0)