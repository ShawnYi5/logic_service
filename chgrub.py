# coding:utf-8
import os
import sys
import pdb
import platform
import chconf
import crutil
import re
import initlib
import bootent


_logger = crutil.get_logger('chgrub')


# if have clerware flag, do not change, and same check with vmlinuz and initramfs
# known defect: we don't handle the senario:
#   the clerware rd is running --> the user changed the default grub menuentry and not restart -->
#   we backuped changed grub --> recovery this state --> then grub's default menuentry is not clerware

CLRD_GRUB_ENTRY_FLAG = 'ClerwareRD'
CLRD_GRUB_ENTRY_TEXT = ' (' + CLRD_GRUB_ENTRY_FLAG + ')'


def add_flag(entry_fld):    # can't not change the reference addr
    assert len(entry_fld) > 0
    if entry_fld.find(CLRD_GRUB_ENTRY_FLAG) != -1:
        reg_exp = '((?<=\()\s?{arg1}-?\d*\s?(?=\)))'.format(arg1=CLRD_GRUB_ENTRY_FLAG)
        mres = re.search(reg_exp, entry_fld, re.I)
        if mres:
            flag_str = mres.group(0)
            flag_str = str(flag_str).strip(' ')
            list_str = flag_str.split('-')
            if len(list_str) > 1 and list_str[1].isdigit():
                list_str[1] = '{num}'.format(num=int(list_str[1])+1)
                flag_str = list_str[0] + '-' + list_str[1]
            else:
                flag_str += '-1'
            entry_fld = re.sub(reg_exp, flag_str, entry_fld)
            return entry_fld
    entry_fld += CLRD_GRUB_ENTRY_TEXT
    return entry_fld


def chgrub(grub_fn, grub_ver, initramfs_fn, vmlinuz_fn):
    """
    1 Copy the default menuentry and replace the vmlinuz and initramfs/initrd to build new entry
    2 Add the new entry before the exist default menuentry
    3 Set the added new entry as default
    Note important: ==>
    1 if grub2, ensure the grubenv exist and at the same dir
    2 The callee must self ensure the initramfs and vmlinuz_fn is a valid linux file name
    3 if already exists, do not handle at this function, and use probe_grub
    :param grub_fn: grub.conf/grub.cfg file name - abspath, use get_grub_info to get it
    :param grub_ver: grub version, use get_grub_info to get it
    :param initramfs_fn: initramfs file name, only basename
    :param vmlinuz_fn: vmlinuz file name, only basename
    :return: return the menuentry seq what the added item, failied return < 0
    """

    _logger.debug('crunch: chgrub begin: 1:{} 2:{} 3:{} 4:{}'.format(grub_fn, grub_ver, initramfs_fn, vmlinuz_fn))

    _logger.debug('1 check in-args')

    if os.path.exists(grub_fn) is False:
        _logger.debug('1.1 check in-args failed: grub_fn={arg1} not exist'.format(arg1=grub_fn))
        return -10

    if grub_ver != 1 and grub_ver != 2:
        _logger.debug('1.2 check in-args failed: grub_ver={arg1} invalid'.format(arg1=grub_ver))
        return -11

    grubenv_fn = ''
    if grub_ver == 2:
        grubenv_fn = os.path.join(os.path.dirname(grub_fn), 'grubenv')
        if os.path.exists(grubenv_fn) is False:
            _logger.debug('1.2 check in-args failed: grubenv={arg1} not exist'.format(arg1=grubenv_fn))
            return -12

    _logger.debug('2 get grub def entry group and seq')

    def_entry_seq, entry_group = bootent.get_grub_def_entry_ex(grub_fn, grub_ver)
    if def_entry_seq < 0 or entry_group is None:
        _logger.debug('2 get grub def entry group and seq failed: error={arg1}'.format(arg1=def_entry_seq))
        return -20
    assert len(entry_group) >= 4 and entry_group[3] is True
    pos1 = entry_group[0].find(':')
    pos2 = entry_group[2].find(':')
    if pos1 == -1 or pos2 == -1:
        _logger.debug('2 get grub def entry group and seq error: without (no:): {arg1}'.format(arg1=entry_group))
        return -21

    # if entry_group[0].find(CLRD_GRUB_ENTRY_FLAG): # already exists, do not handle at here
    _logger.debug('3 copy and new entry')

    _logger.debug('3.1 copy and new entry - get copy range')

    begin_lnno = int(entry_group[0][0:pos1])
    end_lnno = int(entry_group[2][0:pos2])

    _logger.debug('3.2 copy and new entry - copy')

    old_entry_lines = list()
    with open(grub_fn) as fd:
        lines = fd.readlines()
        for i in range(0, len(lines)):
            if i in range(begin_lnno - 1, end_lnno):
                old_entry_lines.append(lines[i])

    if len(old_entry_lines) < 3:
        _logger.debug('3.2 copy and new entry - copy failed: read lines < 3 : {arg1}'.format(arg1=old_entry_lines))
        return -32

    _logger.debug('3.3 copy and new entry - new')

    new_entry_lines = list()
    for line in old_entry_lines:
        replace_text = ''
        if line.find(bootent.grub_cs(grub_ver, 0)) != -1:
            reg_exp_s = 0
        elif line.find(bootent.grub_cs(grub_ver, 1)) != -1:
            reg_exp_s = 1
            replace_text = vmlinuz_fn
        elif line.find(bootent.grub_cs(grub_ver, 2)) != -1:
            reg_exp_s = 2
            replace_text = initramfs_fn
        else:
            new_line = line[:]
            new_entry_lines.append(new_line)
            continue

        reg_exp = bootent.grub_re(grub_ver, reg_exp_s)
        _logger.debug('3.3 copy and new entry - new: re={arg1}, line={arg2}'.format(arg1=reg_exp, arg2=line))
        match = re.search(reg_exp, line, re.I)
        if match:
            _logger.debug('grub_line_bef_ch: {}'.format(line))
            new_line = line[:match.span()[0]]
            if len(replace_text) == 0:
                new_line += add_flag(line[match.span()[0]:match.span()[1]])
            else:
                # reserve the orgignal dir, centos 5: /boot, 6, 7: /
                tmp_str = os.path.dirname(line[match.span()[0]:match.span()[1]])
                tmp_str = os.path.join(tmp_str, os.path.basename(replace_text))
                if platform.system() == 'Windows':  # only for debug on windows
                    tmp_str = str(tmp_str).replace('\\', r'/')
                new_line += tmp_str
            new_line += line[match.span()[1]:]
            _logger.debug('grub_line_aft_ch: {}'.format(new_line))
            new_entry_lines.append(new_line)
        else:
            return -330

    if len(old_entry_lines) != len(new_entry_lines):
        _logger.debug('3.3 copy and new entry - new error of reg_exp match, detail:')
        _logger.debug('old_entry={arg1}, new_entry={arg2}'.format(arg1=old_entry_lines, arg2=new_entry_lines))
        return -331

    if grub_ver == 2 and new_entry_lines[-1].find('}') == -1:
        new_entry_lines.append('}\n')

    _logger.debug('4 insert before line {arg1}'.format(arg1=begin_lnno))

    # print('crunch_chgrub_dump lines before change')
    # _logger.debug('crunch_chgrub_dump lines before change')
    # with open(grub_fn) as fd:
    #     lines = fd.readlines()
    #     for line in lines:
    #         print(line)
    #         _logger.debug(line)

    # print('crunch_chgrub_dump lines new entry lines')
    # _logger.debug('crunch_chgrub_dump lines new entry lines')
    # for line in new_entry_lines:
    #     print(line)
    #     _logger.debug(line)

    # for line in new_entry_lines:
    #     if line.find(r'#!/bin/nash') != -1:
    #         pdb.set_trace()

    with chconf.ChConf(grub_fn) as chc:
        chc.add_lines_atno(new_entry_lines, begin_lnno - 1)
        if grub_ver == 2:
            _logger.debug('4.1 grub2evn change to {arg1}'.format(arg1=def_entry_seq))
            with chconf.ChConf(grubenv_fn) as env_chc:
                rlines = ['saved_entry={arg1}'.format(arg1=def_entry_seq)]   # saved_entry=1 must has no [:blank:]
                env_chc.rep_line_re(rlines, r'^((\s)*(saved_entry))(\s)*=.*')

    # print('crunch_chgrub_dump lines added grub')
    # _logger.debug('crunch_chgrub_dump lines added grub')
    # with open(grub_fn) as fd:
    #     lines = fd.readlines()
    #     for line in lines:
    #         print(line)
    #         _logger.debug(line)
    #         if line.find(r'#!/bin/nash') != -1:
    #             pdb.set_trace()

    _logger.debug('crunch: chgrub end ')
    return 0


# ======================================================================================================================
# test main
# ======================================================================================================================


if __name__ == "__main__":

    _logger.debug('test chgrub entered')

    _logger.debug('test chgrub entered')
    cur_test_osver = 7
    os_name = [['centos5', 'initrd-2.6.18-8.el5-clrd.img', 'vmlinuz-2.6.18-8.el5'],
               ['centos6', 'initramfs-2.6.32-279.el6.i686-clrd.img', 'vmlinuz-2.6.32-279.el6.i686'],
               ['centos7', 'initramfs-3.10.0-327.el7.x86_64-clrd.img', 'vmlinuz-3.10.0-327.el7.x86_64-clrd']]
    root_dir = r'/'
    if platform.system() == 'Windows':  # only for debug on Windows
        root_dir = os.path.join(r'E:\temp\initramfs-op', os_name[cur_test_osver-5][0])

    crutil.dbg_break()

    g_grub_fn = r'/boot/grub2/grub.cfg'
    g_grub_ver = 2
    g_initramfs_name = 'initramfs-3.10.0-229.el7.x86_64.clrd.img'
    g_vmlinuz_name = 'vmlinuz-3.10.0-229.el7.x86_64'

    g_grub_ver, g_grub_fn = initlib.get_grub_info(root_dir)
    chgrub(g_grub_fn, g_grub_ver, os_name[cur_test_osver-5][1], os_name[cur_test_osver-5][2])

    crutil.dbg_break()

    _logger.debug('test chgrub exited')
    sys.exit(0)
