# coding:utf-8
import json
import os
import platform
import subprocess
import sys
import traceback
import uuid
import warnings

import chconf
import chkfile
import crutil

_logger = crutil.DynamicLogger("Initramfs")

sbd_driver_config = [{'name': 'disksbd_linux',
                      'ko_name': 'disksbd_linux.ko',
                      'cb_func': 'get_disksbd_linux_args',
                      'cb_args': None,
                      'to_initrd': True,
                      'must_success': 1},
                     {'name': 'sbd_fun_linux',
                      'ko_name': 'sbd_fun_linux.ko',
                      'cb_func': None,
                      'cb_args': None,
                      'to_initrd': True,
                      'must_success': 1}]


def get_sbd_driver_config():
    return sbd_driver_config


# ======================================================================================================================
# Initramfs
# ======================================================================================================================


def cal_add_lnno(fn, cstr, ward, istr, cstr_pos='starts', start_lnno=0):
    with open(fn) as fd:
        out_lines = fd.readlines()
        max_line = len(out_lines)
        cstr_lnno = -1
        for i, line in enumerate(out_lines):
            if i < start_lnno:
                continue
            # tmp_str = re.sub("(^\s*)|(\s*$)", '', line, re.I)
            tmp_str = line.strip('\n').strip(' ').strip('\t')
            if tmp_str.startswith('#'):
                continue
            if cstr_pos == 'starts':
                if tmp_str.startswith(cstr):
                    cstr_lnno = i
                    break
            elif cstr_pos == 'ends':
                if tmp_str.endswith(cstr):
                    cstr_lnno = i
                    break
            else:
                if tmp_str.find(cstr) != -1:
                    cstr_lnno = i
                    break
        if cstr_lnno == -1:
            return -1, 'not found cstr'

        if ward == 'b':
            if cstr_lnno == 0:
                return 0, 'ok'
            for k in range(cstr_lnno - 1, -1, -1):
                line = out_lines[k].strip('\n').strip(' ').strip('\t')
                if len(line) == 0 or line.find('#') == 0 or line.find(istr) != -1:
                    if k == 0:
                        return 0, 'ok'
                    else:
                        continue
                else:
                    return k + 1, 'ok'
        elif ward == 'a':
            start_line = cstr_lnno + 1
            cstr_lnno = start_line + 1

            _logger.debug('[cal_add_lnno] start_line={}'.format(start_line))
            _logger.debug('[cal_add_lnno] cstr_lnno={}'.format(cstr_lnno))
            _logger.debug('[cal_add_lnno] max_line={}'.format(max_line))

            for k in range(start_line, max_line, 1):
                line = out_lines[k].strip('\n').strip(' ').strip('\t')
                if len(line) == 0 or line.find('#') == 0 or line.find(istr) != -1:
                    if k == max_line - 1:
                        return max_line, 'ok'
                    else:
                        continue
                else:
                    return k + 1, 'ok'
        else:
            return -1, 'ward invalid'

    return -1, 'logic error'


# add sleep after second mkblkdevs
# ('/init', # file
#  {'cstr': 'mkblkdevs', 'ward': 'a', 'istr': ''}, # first mkblkdevs
#  {'cstr': 'mkblkdevs', 'ward': 'a', 'istr': ''}) # second mkblkdevs

def add_wait_after_mkblkdevs(conf_args_tupl, **host_args_dict):
    try:
        _logger.debug('add_wait_after_mkblkdevs entered')
        initramfs = host_args_dict['initramfs']
        img_xdir = host_args_dict['img_xdir']
        add_dict = host_args_dict['add_dict']
        chg_fn = conf_args_tupl[0]
        sh_fn = initramfs.join_rep_knlver(img_xdir, chg_fn)

        cstr = conf_args_tupl[1]['cstr']
        ward = conf_args_tupl[1]['ward']
        istr = conf_args_tupl[1]['istr']
        lnno, out_str = cal_add_lnno(sh_fn, cstr, ward, istr)
        if lnno == -1:
            _logger.warning('8.15 not find first mkblkdevs: {}, set lnno 55 to continue'.format(out_str))
            lnno = 50  # if calc failed, search from 55 lines

        lnno += 1  # backward 5 lines
        cstr = conf_args_tupl[2]['cstr']
        ward = conf_args_tupl[2]['ward']
        istr = conf_args_tupl[2]['istr']
        lnno, out_str = cal_add_lnno(sh_fn, cstr, ward, istr, 'starts', lnno)
        if lnno == -1:
            _logger.error('8.16 cal_add_lnno wait_sh lnno error: {}, add file '.format(out_str))
            return -816

        sh_lines = ['echo "begin Waiting for ip initialize - Clerware"\n',
                    'echo "begin Waiting for ip initialize - Clerware" > /proc/filter_proc\n',
                    'sleep 30\n',
                    'echo "Waiting for ip initialize complete - Clerware"\n',
                    'echo "Waiting for ip initialize complete - Clerware" > /proc/filter_proc\n']
        with chconf.ChConf(sh_fn) as chc:
            chc.add_lines_atno(sh_lines, lnno)
        # save the insert lines and file into json
        chfile = {'fn': chg_fn, 'lines': sh_lines}
        Initramfs.put_add(add_dict, chfile, 'chfiles')

    except Exception as ex:
        _logger.error('crunch: add_wait_after_mkblkdevs exception: {}'.format(traceback.print_exc()))
        return -1, repr(ex)

    return 0, 'ok'


def sysd_srvc_gen_sbd(conf_args_tupl, **host_args_dict):
    try:
        initramfs = host_args_dict['initramfs']
        img_xdir = host_args_dict['img_xdir']
        srvc_fn = initramfs.join_rep_knlver(img_xdir, conf_args_tupl[0])
        wants_dir = initramfs.join_rep_knlver(img_xdir, conf_args_tupl[1])
        shell_fn = initramfs.only_rep_knlver(conf_args_tupl[2])
        srvc_ctnt = ['#  This file is part of systemd.\n',
                     '\n',
                     '[Unit]\n',
                     'Description=Crunch Added Print on Start\n',
                     'DefaultDependencies=no\n',
                     'Conflicts=shutdown.target\n',
                     'After=systemd-udevd-control.socket systemd-udevd-kernel.socket\n',
                     'Before=sysinit.target systemd-modules-load.service systemd-udevd.service\n',
                     '\n',
                     '[Service]\n',
                     'Type=oneshot\n',
                     'RemainAfterExit=yes\n']
        srvc_ctnt_dyline = 'ExecStart={fn}'.format(fn=shell_fn)
        srvc_ctnt.append(srvc_ctnt_dyline)

        with open(srvc_fn, 'w') as fd:
            fd.writelines(srvc_ctnt)
        if os.path.exists(srvc_fn) is False:
            return -2, 'write {} failed, unknown error'.format(srvc_fn)

        # create soft link for service
        link_src = initramfs.join_rep_knlver('../', os.path.basename(srvc_fn))
        sym_name = initramfs.join_rep_knlver(wants_dir, os.path.basename(srvc_fn))
        cmd = 'ln -sf {} {}'.format(link_src, sym_name)
        tmp_res, out_str = crutil.exec_shell_cmd_status(cmd)
        if tmp_res != 0 or os.path.exists(sym_name) is False:
            _logger.error('crunch: create softlink failed: cmd = {}, out = {}'.format(cmd, out_str))
            return -3, out_str

    except Exception as ex:
        _logger.error('crunch: sysd_srvc_gen_sbd exception: {}'.format(traceback.print_exc()))
        return -1, repr(ex)

    return 0, 'ok'


def sysd_srvc_gen_other(conf_args_tupl, **host_args_dict):
    try:
        initramfs = host_args_dict['initramfs']
        img_xdir = host_args_dict['img_xdir']
        srvc_fn = initramfs.join_rep_knlver(img_xdir, conf_args_tupl[3])
        wants_dir = initramfs.join_rep_knlver(img_xdir, conf_args_tupl[4])
        shell_fn = initramfs.only_rep_knlver(conf_args_tupl[5])
        srvc_ctnt = ['#  This file is part of systemd.\n',
                     '\n',
                     '[Unit]\n',
                     'Description=Crunch Load other driver\n',
                     'DefaultDependencies=no\n',
                     'Conflicts=shutdown.target\n',
                     'After=systemd-udevd.service\n',
                     'Wants=systemd-udevd.service\n',
                     'Before=initrd.target dracut-pre-mount.service\n',
                     '\n',
                     '[Service]\n',
                     'Type=oneshot\n',
                     'RemainAfterExit=yes\n']
        srvc_ctnt_dyline = 'ExecStart={fn}'.format(fn=shell_fn)
        srvc_ctnt.append(srvc_ctnt_dyline)

        with open(srvc_fn, 'w') as fd:
            fd.writelines(srvc_ctnt)
        if os.path.exists(srvc_fn) is False:
            return -2, 'write {} failed, unknown error'.format(srvc_fn)

        # create soft link for service
        link_src = initramfs.join_rep_knlver('../', os.path.basename(srvc_fn))
        sym_name = initramfs.join_rep_knlver(wants_dir, os.path.basename(srvc_fn))
        cmd = 'ln -sf {} {}'.format(link_src, sym_name)
        tmp_res, out_str = crutil.exec_shell_cmd_status(cmd)
        if tmp_res != 0 or os.path.exists(sym_name) is False:
            _logger.error('crunch: create softlink failed: cmd = {}, out = {}'.format(cmd, out_str))
            return -3, out_str

    except Exception as ex:
        _logger.error('crunch: sysd_srvc_gen_other exception: {}'.format(traceback.print_exc()))
        return -1, repr(ex)

    return 0, 'ok'


def sysd_srvc_gen(conf_args_tupl, **host_args_dict):
    ret_val, out_str = sysd_srvc_gen_sbd(conf_args_tupl, **host_args_dict)
    if ret_val != 0:
        _logger.error("crunch: sysd_srvc_gen_sbd error: {}, {}".format(ret_val, out_str))
        return ret_val, out_str

    # 这里要判断shell_fn是否存在, 如果不存在, 就不写: 只有在还原时才存在

    initramfs = host_args_dict['initramfs']
    img_xdir = host_args_dict['img_xdir']
    shell_fn = initramfs.only_rep_knlver(conf_args_tupl[5])
    shell_fn_aio = initramfs.join_rep_knlver(img_xdir, shell_fn)
    if os.path.exists(shell_fn_aio) is False:
        _logger.info('crunch: no {}, not gen clrdother service'.format(os.path.basename(shell_fn_aio)))
        return 0, 'OK'

    ret_val, out_str = sysd_srvc_gen_other(conf_args_tupl, **host_args_dict)
    if ret_val != 0:
        _logger.error("crunch: sysd_srvc_gen_other error: {}, {}".format(ret_val, out_str))
        return ret_val, out_str

    return 0, 'OK'


def add_lines_to_file(conf_args_tupl, **host_args_dict):
    _logger.debug('crunch: run_clrdinit_sh begin')
    try:
        _logger.debug('1 get input params')
        initramfs = host_args_dict['initramfs']
        img_xdir = host_args_dict['img_xdir']
        add_dict = host_args_dict['add_dict']
        # '/scripts/init-top/ORDER',
        # {'cstr': 'all_generic_ide', 'ward': 'b', 'istr': 'echo'},
        # '/scripts/init-top/00_clrdinit.sh'
        chf_tarfn = conf_args_tupl[0]
        chf_lnloc = conf_args_tupl[1]
        cstr = chf_lnloc['cstr']
        ward = chf_lnloc['ward']
        istr = chf_lnloc['istr']
        chf_alines = conf_args_tupl[2][:]

        _logger.debug('2 calc add lnno')
        chf_tarfn_abs = initramfs.join_rep_knlver(img_xdir, chf_tarfn)
        lnno, out_str = cal_add_lnno(chf_tarfn_abs, cstr, ward, istr, 'in')
        if lnno == -1:
            _logger.error('7.5 cal_add_lnno error: {}'.format(out_str))
            return -54

        _logger.debug('3 do all line at: {}:{} {}'.format(chf_tarfn_abs, lnno, chf_alines))
        with chconf.ChConf(chf_tarfn_abs) as chc:
            chc.add_lines_atno(chf_alines, lnno)

        chfile = {'fn': chf_tarfn, 'lines': chf_alines}
        _logger.debug('3 save chg to json: {}'.format(chkfile))
        Initramfs.put_add(add_dict, chfile, 'chfiles')

    except Exception as e:
        _logger.error('run_clrdinit_sh except: e={}'.format(e))
        return -1, str(e)

    return 0, 'ok'


def add_lines_to_file_suse11(conf_args_tupl, **host_args_dict):
    _logger.debug('crunch: add_lines_to_file_suse11 begin')
    try:
        _logger.debug('1 get input params')
        initramfs = host_args_dict['initramfs']
        img_xdir = host_args_dict['img_xdir']
        add_dict = host_args_dict['add_dict']

        chf_tarfn = conf_args_tupl[0]
        chf_tarfn_abs = initramfs.join_rep_knlver(img_xdir, chf_tarfn)

        for add_conf in conf_args_tupl[1]:
            cstr = add_conf['cstr']
            ward = add_conf['ward']
            istr = add_conf['istr']
            chf_alines = add_conf['add_lines']

            _logger.debug('2 calc add lnno {}'.format(add_conf))

            lnno, out_str = cal_add_lnno(chf_tarfn_abs, cstr, ward, istr, 'in')
            if lnno == -1:
                _logger.error('7.5 cal_add_lnno error: {}'.format(out_str))
                return -54

            _logger.debug('3 do all line at: {}:{} {}'.format(chf_tarfn_abs, lnno, chf_alines))
            with chconf.ChConf(chf_tarfn_abs) as chc:
                chc.add_lines_atno(chf_alines, lnno)

            chfile = {'fn': chf_tarfn, 'lines': chf_alines}
            _logger.debug('3 save chg to json: {}'.format(chkfile))
            Initramfs.put_add(add_dict, chfile, 'chfiles')

        # patch 00_clrdinit.sh

        patch_conf = conf_args_tupl[2]
        patch_file = patch_conf['patch_file']
        patch_file = initramfs.join_rep_knlver(img_xdir, patch_file)
        patch_lines = patch_conf['patch_lines']

        with chconf.ChConf(patch_file) as chc:
            chc.add_lines_atno(patch_lines, 1)  # 加在#!/sbin/sh后面,  insmod disksbd的前面

    except Exception as e:
        _logger.error('add_lines_to_file_suse11 except: e={}'.format(e))
        return -1, str(e)

    return 0, 'ok'


def get_find_fns(fdir):
    cmd = 'find {path}'.format(path=fdir)
    if platform.system().lower() == 'windows':
        cmd = r'c:\cygwin64\bin\find.exe {path}'.format(path=fdir)
    # fuck, crutil.exec_shell_cmd_dir('find .') will dead
    tmp_res, out_lines = crutil.exec_shell_cmd_status(cmd)
    if tmp_res != 0:
        _logger.error('exec {fn} failed, out={out}'.format(fn=cmd, out=out_lines))
        return -1, None
    fdir_len = len(fdir)
    ret_lines = []
    for line in out_lines:
        if len(line) > fdir_len:
            ret_lines.append(line[fdir_len:])
    return 0, ret_lines


def get_add_fns(after_list, bef_list):
    if len(after_list) <= len(bef_list):
        return []
    fn_dict = {}
    for fn in bef_list:
        fn_dict[fn] = 1
    ret_list = list()
    for fn in after_list:
        if fn_dict.get(fn) is not None:
            del fn_dict[fn]
        else:
            ret_list.append(fn)
    return ret_list


# noinspection SpellCheckingInspection
class Initramfs:
    def __init__(self, in_ffn, out_ffn, tmp_dir, distrib_ver, knl_ver):
        self.__FN_SKIPCPIO = 'needskipcpio'
        self.__XIMG = 'img'
        self.__FTNP_FN = r'/etc/clrdftnp.json'
        self.__EXTR_FN = r'extr.json'

        self.__in_ffn = in_ffn
        self.__out_ffn = out_ffn
        self.__tmp_dir = tmp_dir
        self.__distrib_ver = distrib_ver
        self.__knl_ver = knl_ver

        _logger.debug('[__init__]: in_ffn={}'.format(in_ffn))
        _logger.debug('[__init__]: out_ffn={}'.format(out_ffn))
        _logger.debug('[__init__]: tmp_dir={}'.format(tmp_dir))
        _logger.debug('[__init__]: distrib_ver={}'.format(distrib_ver))
        _logger.debug('[__init__]: knl_ver={}'.format(knl_ver))

    def save_extract_info(self, xdir, pack_cmd, skipcpio):
        _logger.debug('save_extract_info enter: {} {} {}'.format(xdir, pack_cmd, skipcpio))
        jobj = {'skipio': skipcpio, 'pack_cmd': pack_cmd}
        json_fn = os.path.join(xdir, self.__EXTR_FN)
        with open(json_fn, 'w') as fd:
            json.dump(jobj, fd)
        if os.path.exists(json_fn) is False:
            _logger.error('save {} failed.'.format(json_fn))
            return -1
        return 0

    def get_extract_info(self, xdir_img):
        _logger.debug('[get_extract_info] xdir_img={}'.format(xdir_img))
        xdir = os.path.dirname(xdir_img)
        json_fn = os.path.join(xdir, self.__EXTR_FN)
        _logger.debug('[get_extract_info] extr_info_path={}'.format(json_fn))
        if os.path.isfile(json_fn) is False:
            _logger.error('json_fn: {} is not a file'.format(json_fn))
            return -1, '', False

        with open(json_fn, 'r') as fd:
            jobj = json.load(fd)
        if jobj is None:
            _logger.error('load {} from {} failed.'.format(json_fn, json_fn))
            return -2, '', False

        _logger.debug('[get_extract_info] jobj={}'.format(jobj))
        return 0, jobj['pack_cmd'], jobj['skipio']

    @property
    def get_zip_alg(self):
        return [{'alg_name': 'gzip', 'extr_cmd': 'gunzip -c', 'pack_cmd': 'gzip -6 '},
                {'alg_name': 'XZ', 'extr_cmd': 'xz -dc', 'pack_cmd': 'xz -z0 '}]

    @staticmethod
    def check_cpio_out(out_lines):
        _logger.debug('check_cpio_out entered: {}'.format(out_lines))

        if len(out_lines) == 0:
            return -1

        # not xz compressing file format
        cstr = 'File format not recognized'
        tmp_b, _ = crutil.find_in_lines(out_lines, cstr)
        if tmp_b is True:
            _logger.info('find {}'.format(cstr))
            return 1

        # not gzip compressing file format
        cstr = 'not in gzip format'
        tmp_b, _ = crutil.find_in_lines(out_lines, cstr)
        if tmp_b is True:
            _logger.info('find {}'.format(cstr))
            return 2

        words = out_lines[-1].split(' ')
        for i, w in enumerate(words):
            if w.isdigit():
                _logger.info('find number: {} at word position {}'.format(w, i))
                return 0

        _logger.error('out of check condition. outline={}'.format(out_lines))
        return -2

    def determine_cmd(self):
        assert os.path.isfile(self.__in_ffn)

        chkf = chkfile.ChkFile(self.__in_ffn)
        for conf in self.get_zip_alg:
            if chkf.file(conf['alg_name']):
                return [conf]

        _logger.warning('determine failed, will try all cmd')
        return self.get_zip_alg

    def strip_skipcpio(self):
        _logger.debug("strip_skipcpio entered")

        is_skipcpio = False
        initrd_file = self.__in_ffn
        # skipcpio.c也是以找TRAILER!!!特征码栏判断skipcpio的
        cmd = 'strings {} | grep "TRAILER\!\!\!"|wc -l'.format(initrd_file)
        _logger.debug("cmd: {}".format(cmd))
        res, out = crutil.wrap_getstatusoutput(cmd)
        if res != 0:
            _logger.error("find skipcpio charactor code: TRAILER!!! error: {}".format(res))
            return 1, is_skipcpio

        skipcpio_count = int(out)
        _logger.debug("skipcpio count: {}".format(skipcpio_count))
        if skipcpio_count > 0:
            is_skipcpio = True

        for i in range(int(out)):
            skipcpio_initrd = os.path.join(self.__tmp_dir, '{}.skipcpio{}'.format(self.__in_ffn, i))
            cmd = '/usr/lib/dracut/skipcpio {} > {}'.format(initrd_file, skipcpio_initrd)
            _logger.debug("cmd: {}".format(cmd))
            res, out = crutil.wrap_getstatusoutput(cmd)
            if res != 0:
                _logger.error("strip skipcpio error: {}".format(res))
                return 2 + i, is_skipcpio
            os.rename(skipcpio_initrd, self.__in_ffn)

        _logger.debug("strip_skipcpio leaved success")
        return 0, is_skipcpio

    def extract(self):
        """
        extract the initrd/initramfs img file
        :return: return True, ExtractedDir if successful, or False, ''
        """
        _logger.debug(r'crunch: extract begin')
        _logger.debug(r'1 verify in_ffn exist and is file')

        if (os.path.exists(self.__in_ffn) is False) or (os.path.isfile(self.__in_ffn) is False):
            _logger.error('in_ffn not exist or not a file: {}'.format(self.__in_ffn))
            return False, ''

        _logger.debug(r'2 verify tmp_dir exits')

        if os.path.exists(self.__tmp_dir) is False:
            crutil.wrap_getstatusoutput(r'mkdir -p ' + self.__tmp_dir)
        os.chmod(self.__tmp_dir, 777)

        res, skipcpio = self.strip_skipcpio()
        if res != 0:
            _logger.error("strip_skipcpio failed: {}".format(res))
            return False, ''

        conf_list = self.determine_cmd()
        for conf in conf_list:
            zip_cmd = conf['extr_cmd']
            # every try to make new uuid_dir
            _logger.debug(r'3 prepare extr-img/uuid')
            xdir = os.path.join(self.__tmp_dir, str(uuid.uuid4().hex))
            if os.path.exists(xdir) is True:
                crutil.wrap_getstatusoutput('rm -rf ' + xdir)
            xdir_img = os.path.join(xdir, self.__XIMG)
            crutil.wrap_getstatusoutput('mkdir -p ' + xdir_img)
            assert os.path.exists(xdir_img)
            _logger.debug('3 extr-img dir={}'.format(xdir_img))

            _logger.debug(r'5 do extract')
            _logger.debug(r'5.1 do {} | cpio'.format(zip_cmd))

            cmd = '{} {} |cpio -imd'.format(zip_cmd, os.path.abspath(self.__in_ffn))
            tmp_res, out_lines = crutil.exec_shell_cmd_dir(cmd, xdir_img)
            _logger.debug('[extract] 1stry: cmd={}, out_lines={}'.format(cmd, out_lines))
            chk_res = Initramfs.check_cpio_out(out_lines)

            if tmp_res == 0 and chk_res == 0:
                pack_cmd = conf['pack_cmd']
                cmd = "xz -lv {}".format(self.__in_ffn) + "|awk '{print $2}'" + '|grep -i "CRC32"'
                tmp_res, out_str = crutil.wrap_getstatusoutput(cmd)
                _logger.debug("[extract] check XZ CRC32: cmd={}, res={}, out={}".format(cmd, tmp_res, out_str))
                if tmp_res == 0 and out_str.find("CRC32") != -1:
                    pack_cmd += '-Ccrc32 '

                self.save_extract_info(xdir, pack_cmd, skipcpio)
                _logger.debug(r'[extract] succ end xdir_img={}'.format(xdir_img))
                return True, xdir_img

            _logger.warning(r'use {} failed: {}, retry'.format(cmd, out_lines))

        _logger.debug(r'crunch: all alg try failed and exist')
        return False, ''

    def extract_gzip(self):
        """
        extract the initrd/initramfs img file
        :return: return True, ExtractedDir if successful, or False, ''
        """
        warnings.warn("The 'extract_gzip' method is deprecated, "
                      "use 'extract' instead", DeprecationWarning, 2)

        _logger.debug(r'crunch: extract begin')

        # first, adjust the format of img, can't use file img to adjust
        # file img always: img_name: ASCII cpio archive (SVR4 with no CRC)
        # RHEL,centos 5, 6 is zip file , 7 is dracut format
        # the right method is gzip file. the dracut format can't gzip
        # gunzip -c ../initramfs-3.10.0.img |cpio -imd
        # if not gzip file, output: not in gzip format

        _logger.debug(r'1 verify in_ffn exist and is file')

        if (os.path.exists(self.__in_ffn) is False) or (os.path.isfile(self.__in_ffn) is False):
            return False, ''

        # 2 verify the tmp_dir exists, if not mkdir

        _logger.debug(r'2 verify tmp_dir exits')

        if os.path.exists(self.__tmp_dir) is False:
            crutil.wrap_getstatusoutput(r'mkdir -p ' + self.__tmp_dir)

        os.chmod(self.__tmp_dir, 777)

        # pdb.set_trace()

        _logger.debug(r'3 prepare extr-img/uuid')

        xdir = os.path.join(self.__tmp_dir, str(uuid.uuid4().hex))
        if os.path.exists(xdir) is True:
            crutil.wrap_getstatusoutput('rm -rf ' + xdir)

        _logger.debug(r'4 prepare extr-img/uuid/img')

        xdir_img = os.path.join(xdir, self.__XIMG)
        crutil.wrap_getstatusoutput('mkdir -p ' + xdir_img)
        assert os.path.exists(xdir_img)
        # issue: cause the other module bug, use popen(cur_dir)
        # os.chdir(xdir_img)  # extr-img/uuid/img

        _logger.debug(r'5 do extract')

        _logger.debug(r'5.1 do gunzip | cpio')

        cmd = 'gunzip -c ' + os.path.abspath(self.__in_ffn) + ' | cpio -imd'
        tmp_res, out_lines = crutil.exec_shell_cmd_dir(cmd, xdir_img)
        find_res, _ = crutil.find_in_lines(out_lines, 'not in gzip format')
        if find_res is True:
            _logger.debug('5.1.1 do skipcpio | gunzip | cpio')

            cmd = r'/usr/lib/dracut/skipcpio ' + os.path.abspath(self.__in_ffn) + ' | gunzip -c | cpio -imd'
            tmp_res, out_lines = crutil.exec_shell_cmd_dir(cmd, xdir_img)
            if tmp_res != 0:
                _logger.debug('5.1.1 do skipcpio | gunzip | cpio failed: cmd={}, out={}'.format(cmd, out_lines))
                return False, ''

            _logger.debug(r'5.1.2 cat extr-img/uuid/needskipcpio ')

            skp_ffn = os.path.join(xdir, self.__FN_SKIPCPIO)
            cmd = r'cat /dev/null > ' + skp_ffn
            tmp_res, cat_lines = crutil.exec_shell_cmd_status(cmd)
            if os.path.exists(skp_ffn) is False:
                _logger.debug(r'5.1.2 cat extr-img/uuid/needskipcpio failed: {arg1}'.format(arg1=cat_lines))
                return False, ''

        _logger.debug(r'5.2 verify extract out_lines')

        # can't find the charactor string, if Chinese or non English, no blocks
        # find_res, find_line = crutil.find_in_lines(out_lines, 'blocks')
        if os.path.exists(os.path.join(xdir_img, 'init')) is False:
            _logger.debug(r'5.2 verify extract out_lines failed: {arg1}'.format(arg1=out_lines))
            return False, ''

        _logger.debug(r'crunch: extract succ end')

        return True, xdir_img

    def pack(self, img_xdir):
        """
        pack the extracted initrd/initramfs dir to an img file
        :param img_xdir: the extracted img file temp dir
        :return: the True is return if success, or False if failed
        """
        _logger.debug('[pack]: img_xdir={}'.format(img_xdir))

        _logger.debug(r'crunch: pack begin')

        dbg_msg = '[pack] stopping: xdir_img={}, out_ffn={}'.format(img_xdir, self.__out_ffn)
        crutil.dbg_stop(r'/tmp/pack.crunch.stop', 5, _logger, dbg_msg)

        _logger.debug(r'1 verify arguments')

        _logger.debug(r'1.1 verify dirname(out_ffn) isdir')

        dir_out = os.path.dirname(self.__out_ffn)
        out = dir_out
        tmp_res = os.path.isdir(out)
        if tmp_res is False:
            _logger.debug(r'1.1 verify dirname(out_ffn) isdir failed: {arg1}'.format(arg1=self.__out_ffn))
            return False

        _logger.debug(r'1.2 verify xdir_img isdir')

        # pdb.set_trace()

        xdir_img = os.path.abspath(img_xdir)
        tmp_res = os.path.isdir(xdir_img)
        if tmp_res is False:
            _logger.debug(r'1.2 verify xdir_img isdir failed: {arg1}'.format(arg1=xdir_img))
            return False

        _logger.debug(r'1.3 verify xdir_img/../ isdir')

        xdir_img_up = os.path.dirname(xdir_img)
        tmp_res = os.path.isdir(xdir_img_up)
        if tmp_res is False:
            _logger.debug(r'1.3 verify xdir_img/../ isdir failed: {arg1}'.format(arg1=xdir_img_up))
            return False

        _logger.debug(r'2 do pack')

        _logger.debug(r'2.1 get pack alg')

        tmp_res, pack_cmd, skipcpio = self.get_extract_info(xdir_img)
        if tmp_res != 0:
            _logger.error('get_extract_info failed, res: {}'.format(tmp_res))
            return False

        _logger.debug(r'2.2 do pack use find | cpio | gzip')

        # ** can't use abstract path, must use relative path, the path will be pack into img
        # ** so, the pack cmd is fixed

        # pdb.set_trace()
        # os.chdir(xdir_img)
        # assert str(xdir_img).__eq__(os.getcwd())
        cmd = 'find . | cpio -o -H newc | {} > {}'.format(pack_cmd, self.__out_ffn)

        # popen maybe execute async, the outlines is []
        # tmp_res, out_lines = crutil.exec_shell_cmd_status(cmd)

        # pdb.set_trace()
        tmp_res, out_lines = crutil.exec_shell_cmd_dir(cmd, xdir_img)
        _logger.debug('[pack] exec_pack_cmd: cmd={}, out={}'.format(cmd, out_lines))
        # find_res, _ = crutil.find_in_lines(out_lines, 'blocks')
        if 0 != tmp_res or os.path.exists(self.__out_ffn) is False:
            _logger.debug(r'2.2 do pack use find | cpio | gzip failed: {arg1}'.format(arg1=out_lines))
            return False

        _logger.debug(r'crunch: pack succ end')

        return True

    def join_rep_knlver(self, base_dir, conf_fn):
        """
        why not use os.join path:
        the conf_fn only can be the sub dir, can't be a base dir
        :param base_dir:
        :param conf_fn:
        :return:
        """
        crutil.unrefer_arg(self)
        if conf_fn is None or len(conf_fn) == 0:
            raise ValueError('join_rep_knlver: conf_fn must a valid str')

        conf_fn = self.only_rep_knlver(conf_fn)
        if platform.system().lower() == 'windows':
            return os.path.join(base_dir, conf_fn.replace('/', '\\').lstrip('\\'))
        else:
            return os.path.join(base_dir, conf_fn.lstrip('/'))

    def only_rep_knlver(self, conf_fn):
        assert isinstance(conf_fn, str)
        if platform.system().lower() == 'windows':
            conf_fn = conf_fn.replace('/', '\\')
        if conf_fn.find('{knlver}') != -1:
            return conf_fn.format(knlver=self.__knl_ver)
        else:
            return conf_fn

    # noinspection PyUnreachableCode
    def get_mod_load_cmd(self, xdir_img):
        dir_bin = '/bin'
        dir_sbin = '/sbin'
        insmod_bfn = 'insmod'
        modprobe_bfn = 'modprobe'
        kmod_bfn = 'kmod'

        _logger.debug('1 try to find insmod')
        cmd_path = os.path.join(dir_bin, insmod_bfn)
        rximg_path = self.join_rep_knlver(xdir_img, cmd_path)
        if os.path.exists(rximg_path):
            _logger.debug('1 found {} succ end'.format(cmd_path))
            return 0, cmd_path

        cmd_path = os.path.join(dir_sbin, insmod_bfn)
        rximg_path = self.join_rep_knlver(xdir_img, cmd_path)
        if os.path.exists(rximg_path):
            _logger.debug('1 found {} succ end'.format(cmd_path))
            return 0, cmd_path

        _logger.debug('2 no insmod and continue find kmod')
        rximg_path_bin = self.join_rep_knlver(xdir_img, os.path.join(dir_bin, kmod_bfn))
        rximg_path_sbin = self.join_rep_knlver(xdir_img, os.path.join(dir_sbin, kmod_bfn))
        tar_bin = ''
        if os.path.exists(rximg_path_bin):
            tar_bin = dir_bin
        elif os.path.exists(rximg_path_sbin):
            tar_bin = dir_sbin
        else:
            pass
        if len(tar_bin) > 0:
            _logger.debug('2.1 found kmod and create insmod by link kmod')
            cmd_path = os.path.join(dir_sbin, insmod_bfn)
            link_name = self.join_rep_knlver(xdir_img, cmd_path)
            tar_name = os.path.join('..', tar_bin.lstrip('/'), kmod_bfn)
            tmp_res, out_str = crutil.s_link(tar_name, link_name)
            if tmp_res == 0:
                _logger.debug('2.1 create {} by link kmod succ end'.format(cmd_path))
                return 0, cmd_path
            else:
                return -2, '2.1 create insmod by link kmod failed end: res = {}, out = {}'.format(tmp_res, out_str)

        _logger.info('3 no kmod and continue find modprobe')
        cmd_path = os.path.join(dir_bin, modprobe_bfn)
        rximg_path_bin = self.join_rep_knlver(xdir_img, cmd_path)
        if os.path.exists(rximg_path_bin) and os.path.islink(rximg_path_bin) is False:
            _logger.debug('3 found {} succ end'.format(cmd_path))
            return 0, cmd_path

        cmd_path = os.path.join(dir_sbin, modprobe_bfn)
        rximg_path_sbin = self.join_rep_knlver(xdir_img, cmd_path)
        if os.path.exists(rximg_path_sbin) and os.path.islink(rximg_path_sbin) is False:
            _logger.debug('3 found {} succ end'.format(cmd_path))
            return 0, cmd_path

        return -1, 'not found insmod > kmod > modprobe, failed end'

    @staticmethod
    def find_mod_load_dump(xdir_img):
        _logger.debug('dump find insmod/kmod/modprobe')
        cmd = "find {dir} |grep -E '(insmod)$|(kmod)$|(modprobe)$'".format(dir=xdir_img)
        tmp_res, out_lines = crutil.exec_shell_cmd_status(cmd)
        if tmp_res == 0:
            for line in out_lines:
                if os.path.islink(line):
                    _logger.debug('{} {}'.format(line, os.readlink(line)))
                else:
                    _logger.debug('{}'.format(line))
        else:
            _logger.error('find insmod/kmod/modprobe failed: res = {}, out = {}'.format(tmp_res, out_lines))

    def check_fstr_dict(self, img_xdir, fstr_dict):
        assert isinstance(fstr_dict, dict)
        fn = fstr_dict.get('fn')
        fstr = fstr_dict.get('fstr')
        cstr = fstr_dict.get('cstr')
        assert fn is not None or len(fn) > 0

        fn = self.join_rep_knlver(img_xdir, fn)
        fn_exist = False
        if fn.find('*') == -1:
            if os.path.exists(fn):
                fn_exist = True
        else:
            ls = platform.system() == 'Windows' and 'dir' or 'ls'
            cmd = '{} {}'.format(ls, fn)
            tmp_res, out_str = crutil.exec_shell_cmd_status(cmd)
            if tmp_res == 0 and len(out_str) > 0:
                fn_exist = True

        if fn_exist is False:
            return False

        cf = chkfile.ChkFile(fn)

        if fstr is not None and len(fstr) > 0:
            tmp_res, _ = cf.file_ln(fstr)
            if tmp_res is False:
                return False

        if cstr is not None and len(cstr) > 0:
            if cf.grep(cstr) is False:
                return False

        return True

    def __save_add(self, xdir_img, dict_obj):
        _logger.debug('__save_add content={}'.format(dict_obj))
        if dict_obj is not None and len(dict_obj) > 0:
            fn = self.join_rep_knlver(xdir_img, self.__FTNP_FN)
            with open(fn, 'w') as fd:
                json.dump(dict_obj, fd)
            if os.path.exists(fn) is False:
                return -1, 'wrtie json failed, unknown error'
            else:
                return 0, 'successed'

    def __del_json(self, xdir_img):
        fn = self.join_rep_knlver(xdir_img, self.__FTNP_FN)
        if os.path.exists(fn):
            os.remove(fn)
            if os.path.exists(fn):
                _logger.error('[__del_json] failed: fn={}'.format(fn))
                return -1
        return 0

    def __load_add(self, xdir_img):
        fn = self.join_rep_knlver(xdir_img, self.__FTNP_FN)
        if os.path.exists(fn):
            with open(fn, 'r') as fd:
                jobj = json.load(fd)
                if jobj is None:
                    _logger.error('[__load_add] exist but json.load failed: fn={}'.format(fn))
                    return -1, None
                else:
                    return 0, jobj

        return 0, None

    @staticmethod
    def put_add(add_dict, add_data, add_key):
        if add_dict.get(add_key) is None:
            add_dict[add_key] = []
        add_dict[add_key].append(add_data)

    def get_added_files(self, xdir_img):

        dbg_msg = '[get_added_files] stopping: xdir_img={}'.format(xdir_img)
        crutil.dbg_stop(r'/tmp/get_added_files.crunch.stop', 5, _logger, dbg_msg)

        _, dict_obj = self.__load_add(xdir_img)
        if dict_obj is not None:
            _logger.debug('[get_added_files] ftnp_list={}'.format(dict_obj.get('ftnp_list')))
            return dict_obj.get('ftnp_list')

        _logger.warning('[get_added_files] load ftnp failed: xdir_img={}'.format(xdir_img))
        return None

    def del_files(self, xdir_img):
        try:
            tmp_res, add_dict = self.__load_add(xdir_img)
            if tmp_res != 0:
                _logger.error('load json failed, unknown error')
                return -1

            if add_dict is None or len(add_dict) == 0:
                _logger.warning('load json ret None[no err], will not del anything')
                return 0

            tmp_list = add_dict.get('file')
            if tmp_list is not None:
                for fn in tmp_list:
                    try:
                        fn = self.join_rep_knlver(xdir_img, fn)
                        os.remove(fn)
                        _logger.debug('[del_files] removed file: {}'.format(fn))
                    except Exception as e:
                        _logger.warning('remove file:{} failed, e={} contiue'.format(fn, e))

            tmp_list = add_dict.get('dir')
            if tmp_list is not None:
                for fn in tmp_list:
                    try:
                        fn = self.join_rep_knlver(xdir_img, fn)
                        os.removedirs(fn)
                        _logger.debug('[del_files] removed dir: {}'.format(fn))
                    except Exception as e:
                        _logger.warning('remove dir:{} failed, e={} contiue'.format(fn, e))

            tmp_list = add_dict.get('chfiles')
            if tmp_list is not None:
                for chf in tmp_list:
                    fn = self.join_rep_knlver(xdir_img, chf['fn'])
                    _logger.debug('[del_files] del_line file: {}'.format(fn))
                    lines = chf['lines']
                    with chconf.ChConf(fn) as ch:
                        for line in lines:
                            ch.del_line(line)
                            _logger.debug('[del_files] del line: {}'.format(line))

            tmp_res = self.__del_json(xdir_img)
            if tmp_res != 0:
                return -2

        except Exception as e:
            _logger.warning('loop add_dict do del file or dir failed: {}'.format(e))
            return -10

        _logger.debug('[del_files] success end')
        return 0

    @property
    def config(self):

        # dist: distribute manufature id, match one of
        # rules: add file rules
        # distver: ex: centos 7, only for rule editor manual distinguish the rules
        # axidstr: identify the extracted img to distinguish, if the condition matched, use it's rule
        #       fn: relateive(xdir_img) filename
        #       fstr: shell cmd 'file filename' output charactor string, no key then not shellexec 'file'
        #       cstr: content charactor string for line find, no key not open file to find
        # addfile: cp the file to target dir, sub
        # bdepmod: if file exists, one of do depmod condition satisfied
        # shell: descript how to handle our shell cmd, insmod, load app
        #       fn: load app file or insmod driver name
        #       add: add method, tail is add to tail.
        #       cstr: find charactor string, lstrip and begin by cstr
        #           cstr: charactor string
        #           ward: add before or after
        #           istr: lstrip and begin and ignore: default # and lstrip.begin(istr)

        return [{'distver': 'radhat/centos 7, suse 12/13',
                 'axidstr': [{'fn': '/init', 'fstr': 'ELF', 'cstr': ''},
                             {'fn': '/bin/kmod'},
                             {'fn': '/bin/sh'},
                             {'fn': '/usr/lib/systemd/system/sysinit.target'},
                             {'fn': '/usr/lib/systemd/system/sysinit.target.wants'},
                             {'fn': '/usr/lib/systemd/system/systemd-modules-load.service'},
                             {'fn': '/usr/lib/systemd/system/sysinit.target.wants/systemd-modules-load.service'}],
                 'addfile': {'appdir': '/usr/bin',
                             'dvrdir': '/lib/modules/{knlver}/kernel/drivers/clrd'},
                 'bdepmod': {'depfile': '/lib/modules/{knlver}/modules.dep'},
                 'shell': {'fn': '/usr/lib/systemd/00_clrdinit.sh;/usr/lib/systemd/99_clrdinit.sh',
                           'add': 'new',
                           'cstr': {},
                           'waitmthd': 'initwait'},
                 'other': [{'func': 'sysd_srvc_gen',
                            'args': ('/usr/lib/systemd/system/systemd-clrdinit-load.service',
                                     '/usr/lib/systemd/system/sysinit.target.wants',
                                     '/usr/lib/systemd/00_clrdinit.sh',
                                     '/usr/lib/systemd/system/systemd-clrdother-load.service',
                                     '/usr/lib/systemd/system/initrd.target.wants',
                                     '/usr/lib/systemd/99_clrdinit.sh')}]},
                {'distver': 'redhat/centos 6',
                 'axidstr': [{'fn': '/init', 'fstr': 'shell script', 'cstr': 'source_all cmdline'},
                             {'fn': '/sbin/modprobe'},
                             {'fn': '/bin/sh'},
                             {'fn': '/cmdline'},
                             {'fn': '/cmdline/01parse-kernel.sh'}],
                 'addfile': {'appdir': '/usr/bin',
                             'dvrdir': '/lib/modules/{knlver}/kernel/drivers/clrd'},
                 'bdepmod': {'depfile': '/lib/modules/{knlver}/modules.dep'},
                 'shell': {'fn': '/cmdline/00_clrdinit.sh;/pre-mount/99_clrdinit1.sh',
                           'add': 'new',
                           'cstr': {},
                           'waitmthd': 'initwait'},
                 'other': []},
                {'distver': 'fedora 15/16',
                 'axidstr': [{'fn': '/init', 'fstr': 'shell script', 'cstr': 'source_hook cmdline'},
                             {'fn': '/sbin/modprobe'},
                             {'fn': '/bin/sh'},
                             {'fn': '/lib/dracut/hooks/cmdline'},
                             {'fn': '/lib/dracut/hooks/cmdline/01parse-kernel.sh'}],
                 'addfile': {'appdir': '/usr/bin',
                             'dvrdir': '/lib/modules/{knlver}/kernel/drivers/clrd'},
                 'bdepmod': {'depfile': '/lib/modules/{knlver}/modules.dep'},
                 'shell': {'fn': '/lib/dracut/hooks/cmdline/00_clrdinit.sh;/lib/dracut/hooks/pre-mount/99_clrdinit1.sh',
                           'add': 'new',
                           'cstr': {},
                           'waitmthd': 'initwait'},
                 'other': []},
                {'distver': 'redhat/centos 5',
                 'axidstr': [{'fn': '/init', 'fstr': 'nash script', 'cstr': 'insmod'},
                             {'fn': '/sbin/insmod'},
                             {'fn': '/bin/nash'},
                             {'fn': '/lib/*.ko'}],
                 'addfile': {'appdir': '/bin',
                             'dvrdir': '/lib'},
                 'bdepmod': {'depfile': '/lib/modules/{knlver}/modules.dep'},
                 'shell': {'fn': '/init;/init',
                           'add': 'insert',
                           'cstr': {'cstr': 'insmod', 'ward': 'b', 'istr': 'echo'},
                           'cstr1': {'cstr': 'mkrootdev', 'ward': 'b', 'istr': 'echo'},
                           'waitmthd': 'initwait'},
                 'other': []},
                {'distver': 'fedora 11',
                 'axidstr': [{'fn': '/init', 'fstr': 'nash script', 'cstr': 'modprobe'},
                             {'fn': '/sbin/modprobe'},
                             {'fn': '/bin/nash'},
                             {'fn': '/lib/modules/{knlver}/*.ko'}],
                 'addfile': {'appdir': '/bin',
                             'dvrdir': '/lib/modules/{knlver}/clrd'},
                 'bdepmod': {'depfile': '/lib/modules/{knlver}/modules.dep'},
                 'shell': {'fn': '/init;/init',
                           'add': 'insert',
                           'cstr': {'cstr': 'modprobe', 'ward': 'b', 'istr': 'echo'},
                           'cstr1': {'cstr': 'mkrootdev', 'ward': 'b', 'istr': 'echo'},
                           'waitmthd': 'initwait'},
                 'other': []},
                {'distver': 'ubuntu',
                 'axidstr': [{'fn': '/init', 'cstr': 'run_scripts /scripts/init-top'},
                             {'fn': '/scripts/init-top/ORDER'},
                             {'fn': '/bin/sh'}],
                 'addfile': {'appdir': '/bin',
                             'dvrdir': '/lib/modules/{knlver}/kernel/drivers/clrd'},
                 'bdepmod': {'depfile': '/lib/modules/{knlver}/modules.dep'},
                 'shell': {'fn': '/scripts/init-top/00_clrdinit.sh',
                           'add': 'new',
                           'cstr': {},
                           'waitmthd': 'initwait'},
                 'other': [{'func': 'add_lines_to_file',
                            'args': ('/scripts/init-top/ORDER',
                                     {'cstr': 'udev', 'ward': 'a', 'istr': 'param.conf'},
                                     ['/scripts/init-top/00_clrdinit.sh\n'])}]},
                {'distver': 'suse 10',
                 'axidstr': [{'fn': '/init', 'fstr': 'shell script', 'cstr': '/sbin/udevd --daemon'},
                             {'fn': '/init', 'fstr': 'shell script', 'cstr': 'udev_discover_root()'},
                             {'fn': '/init', 'fstr': 'shell script', 'cstr': 'if ! udev_discover_root ; then'},
                             {'fn': '/init', 'fstr': 'shell script', 'cstr': 'udev_discover_resume'},
                             {'fn': '/init', 'fstr': 'shell script', 'cstr': 'rootfstype'},
                             {'fn': '/bin/bash'},
                             {'fn': '/bin/fsck'},
                             {'fn': '/lib/modules/{knlver}/kernel/drivers/'}],
                 'addfile': {'appdir': '/bin',
                             'dvrdir': '/lib/modules/{knlver}/kernel/drivers/clrd'},
                 'bdepmod': {'depfile': '/lib/modules/{knlver}/modules.dep'},
                 'shell': {'fn': '/init;/init',
                           'add': 'insert',
                           'cstr': {'cstr': '/sbin/udevd --daemon', 'ward': 'a', 'istr': 'echo'},
                           'cstr1': {'cstr': 'if ! udev_discover_root ; then', 'ward': 'b', 'istr': 'echo'},
                           'waitmthd': 'initwait'},
                 'other': []},
                {'distver': 'suse 10.3/11',
                 'axidstr': [{'fn': '/init', 'fstr': 'shell script', 'cstr': 'source run_all.sh'},
                             {'fn': '/init', 'fstr': 'shell script', 'cstr': 'source $file'},
                             {'fn': '/bin/sh'},
                             {'fn': '/run_all.sh'},
                             {'fn': '/boot/*.sh'},
                             {'fn': '/lib/modules/{knlver}/kernel/drivers/'}],
                 'addfile': {'appdir': '/bin',
                             'dvrdir': '/lib/modules/{knlver}/kernel/drivers/clrd'},
                 'bdepmod': {'depfile': '/lib/modules/{knlver}/modules.dep'},
                 'shell': {'fn': '/boot/00-clrdinit.sh;/boot/12-clrdother.sh',
                           'add': 'new',
                           'cstr': {},
                           'waitmthd': 'initwait'},
                 'other': [{'func': 'add_lines_to_file_suse11',
                            'args': ('/run_all.sh',
                                     [{'cstr': 'source boot/01-devfunctions.sh', 'ward': 'b', 'istr': 'echo',
                                       'add_lines': ['echo "running clrdinit"\n',
                                                     'source boot/00-clrdinit.sh\n']},
                                      {'cstr': 'source boot/21-devinit_done.sh', 'ward': 'b', 'istr': 'echo',
                                       'add_lines': ['echo "running clrdother"\n',
                                                     'source boot/12-clrdother.sh\n']
                                       }],
                                     {'patch_file': '/boot/00-clrdinit.sh',
                                      'patch_lines': ['echo "clrd mounting proc filesystem"\n',
                                                      'mount -t proc  proc  /proc']}
                                     )}]}
                ]

    # noinspection PyMethodMayBeStatic
    def wait_sh(self, wait_secs):

        wait_sh_path = '/sbin/aio/logic_service/wait.sh'
        ret_lines = list()

        if os.path.exists(wait_sh_path) is True:
            with open(wait_sh_path, 'r') as fp:
                for line in fp.readlines():
                    if str(line).startswith('dr_wait_fnsh'):
                        ret_lines.append('dr_wait_fnsh={secs}\n'.format(secs=wait_secs))
                    elif str(line).startswith('#!/bin'):
                        ret_lines.append('\n\n')
                    else:
                        ret_lines.append(line)
        else:
            ret_lines.append('echo "wait_sh replaced by initwait"\n')

        return ret_lines

    def get_cur_rule(self, xdir_img):
        cur_rule = None
        for rule in self.config:
            id_dict = rule['axidstr']
            chk_succ_counts = 0
            for fstr_dict in id_dict:
                if self.check_fstr_dict(xdir_img, fstr_dict):
                    chk_succ_counts += 1
                else:
                    _logger.debug('[get_cur_rule] break by distver={} fstr_dict={}'.format(rule['distver'], fstr_dict))
                    break
            if chk_succ_counts == len(id_dict):
                cur_rule = rule
                break

        _logger.debug('[get_cur_rule] use rule = {}'.format(cur_rule['distver']))
        return cur_rule

    def need_initwait_app(self, img_xdir):
        _logger.debug(r'4 get cur_rule')
        cur_rule = self.get_cur_rule(img_xdir)
        if cur_rule is None:
            _logger.error(r'2.1 no valid rule: config = {}'.format(self.config))
            return True  # mismatch: add

        if cur_rule['shell']['waitmthd'] == 'initwait':
            return True
        else:
            return False

    # noinspection PyMethodMayBeStatic
    def write_sh(self, sh_fn, sh_lines):
        """
        写shell文件的封装, 原来在add_file里面, 因多处用到相同代码, 提出来
        :param sh_fn: 文件名
        :param sh_lines: 写的行, 一个list
        :return: 这里返回值沿用的add_file的错误号, 否则以前的代码返回的错误号就查不到了.
        """
        _logger.debug(r'[write_sh]: file={} content={}'.format(sh_fn, sh_lines))

        sh_dir = os.path.dirname(sh_fn)
        if os.path.exists(sh_dir) is False:
            tmp_res, out_str = crutil.mkdir_p(sh_dir)
            if tmp_res is False:
                _logger.error('mkdir -p {} failed, write_sh {} failed'.format(sh_dir, sh_fn))
                return -75

        with open(sh_fn, 'w') as fd:
            fd.writelines(sh_lines)
        if os.path.exists(sh_fn) is False:
            _logger.error('write_sh: shell write unkown error: fn = {}'.format(sh_fn))
            return -73
        # _logger.debug(r'write_sh: chmod of new shell file: {}'.format(sh_fn))
        tmp_res, out_str = crutil.exec_chmod(sh_fn, 777)
        if tmp_res is False:
            _logger.error('write_sh: chmod {} 777 failed: out_str = {}'.format(sh_fn, out_str))
            return -74
        return 0

    # noinspection PyMethodMayBeStatic
    def find_sbd_driver_version(self, driver_path):
        if driver_path is None or len(driver_path) == 0:
            return -1, None
        cmd = 'strings {file}'.format(file=driver_path) + r'|grep "sbd_driver_version:[[:digit:]]\{4\}"'
        status, output = crutil.wrap_getstatusoutput(cmd)
        return status, output

    # noinspection PyMethodMayBeStatic
    def split_sh_lines_two(self, sh_lines, driver_clw_count, add_sh_head=True):
        """
        为了写为两个文件, 切割sh_lines为两个, 第一个是我们是我们的驱动, 后面的是其他驱动
        :rtype: 返回切分的list
        """
        if len(sh_lines) % 2 != 0:
            raise ValueError('fixed sh_lines must be [echo, redirect, cmd] 3 lines aligned: {}'.format(sh_lines))

        new_sh_lines_array = list()
        sh_head = '#!/bin/sh\n\n'

        if len(sh_lines) <= 2 * driver_clw_count:
            if add_sh_head:
                sh_lines.insert(0, sh_head)
            new_sh_lines_array.append(sh_lines)
            return new_sh_lines_array

        first_sh_lines = list()
        if add_sh_head:
            first_sh_lines.append(sh_head)
        for i in range(0, 2 * driver_clw_count):
            first_sh_lines.append(sh_lines[i])
        new_sh_lines_array.append(first_sh_lines)

        second_sh_lines = list()
        if add_sh_head:
            second_sh_lines.append(sh_head)
        for i in range(2 * driver_clw_count, len(sh_lines)):
            second_sh_lines.append(sh_lines[i])
        new_sh_lines_array.append(second_sh_lines)

        return new_sh_lines_array

    # noinspection PyMethodMayBeStatic
    def split_sh_lines_by_initwait(self, sh_lines):
        """
        为了写为两个文件, 切割sh_lines为两个, 第一个是我们是我们的驱动, 后面的是其他驱动
        :rtype: 返回切分的list
        """
        if len(sh_lines) % 2 != 0:
            raise ValueError('fixed sh_lines must be [echo, cmd] 2 lines aligned: {}'.format(sh_lines))

        new_sh_lines_array = list()
        first_sh_lines = list()
        initwait_sh_lines = list()

        for line in sh_lines:
            if line.find('initwait') != -1:
                initwait_sh_lines.append(line)
            else:
                first_sh_lines.append(line)

        new_sh_lines_array.append(first_sh_lines)
        new_sh_lines_array.append(initwait_sh_lines)
        return new_sh_lines_array

    def add_files(self, img_xdir, ftnp_list, is_ha=0):
        """
        the method will do depmod automatically:
        if the init need depmod, and if the list include one or more driver
        :param is_ha: is hot backup, high avaliable
        :param img_xdir: extracted img dir
        :param ftnp_list: list[tuple(file_type, src_name, tar_name, params_str)]
               --file_type = string - 'app', 'driver'
               --src_name = full filename, absolute path
               --tar_name = cp to target name: ex. cp src_name tar_name
               --params_str like param1=3 param2="disk1", method will write without any handling
               --mod_name = driver's mod_name, use modinfo view the loaded mod to get
        :return: 0 - success, < 0 - failed
        """
        _logger.debug(r'crunch: add_files begin')

        _logger.debug('[add_files] img_xdir ={}'.format(img_xdir))
        _logger.debug('[add_files] ftnp_list={}'.format(ftnp_list))
        _logger.debug('[add_files] is_ha    ={}'.format(is_ha))

        dbg_msg = 'img_xdir={}, ftnp_list={}, is_ha={}'.format(img_xdir, ftnp_list, is_ha)
        crutil.dbg_stop('/tmp/add_files.crunch.stop', 5, _logger, dbg_msg)

        _logger.debug(r'1 verify arguments')

        assert isinstance(ftnp_list, list)

        if os.path.exists(img_xdir) is False:
            _logger.error(r'1.0 img_xdir = {} not exist'.format(img_xdir))
            return -10

        for ftnp in ftnp_list:
            if len(ftnp) < 4:
                _logger.error('1.2 input argument of len(ftnp) < 4: ftnp = {}'.format(ftnp))
                return -12
            if ftnp[0] not in ['app', 'driver', 'cmd']:
                _logger.error('1.3 input argument ftype invalid: ftnp = {}'.format(ftnp))
                return -13

        try:
            _logger.debug('2 del file first')
            tmp_res = self.del_files(img_xdir)
            if tmp_res != 0:
                _logger.error('del added file failed, unknown error')
                return -20

            if len(ftnp_list) == 0:
                _logger.debug('len(ftnp_list) is 0, clear last added files.')
                return 0

            wait_secs = 30 if is_ha == 0 else 100 * 365 * 24 * 3600
            _logger.debug('2 is_ha={}, wait_secs={}'.format(is_ha, wait_secs))

            add_dict = {}
            _logger.debug('3 find files befor add')

            tmp_res, bef_list = get_find_fns(img_xdir)
            if tmp_res != 0:
                _logger.error(r'get_find_fns for add before failed: {}'.format(bef_list))
                return -31

            _logger.debug(r'4 get cur_rule')
            cur_rule = self.get_cur_rule(img_xdir)
            if cur_rule is None:
                _logger.error(r'2.1 no valid rule: config = {}'.format(self.config))
                return -41

            _logger.debug(r'5 get addfile_dirs')

            _logger.debug(r'5.1 get addfile-appdir/dvrdir')

            app_dir = self.join_rep_knlver(img_xdir, cur_rule['addfile']['appdir'])
            dvr_dir = self.join_rep_knlver(img_xdir, cur_rule['addfile']['dvrdir'])

            _logger.debug(r'5.2 mkdir_p app_dir/dvr_dir')

            tmp_b, out_str = crutil.mkdir_p(app_dir)
            if tmp_b is False:
                _logger.error('5.2 mkdir_p {}-{} for cp failed'.format(app_dir, out_str))
                return -52
            tmp_b, out_str = crutil.mkdir_p(dvr_dir)
            if tmp_b is False:
                _logger.error('5.3 mkdir_p {}-{} for cp failed'.format(dvr_dir, out_str))
                return -53

            _logger.debug(r'6 copy file and gen shell')

            app_dir_clt = self.only_rep_knlver(cur_rule['addfile']['appdir'])
            dvr_dir_clt = self.only_rep_knlver(cur_rule['addfile']['dvrdir'])

            # make determine to get module load cmd, insmod or modprobe
            # if both cmd not exist, use kmod and ln insmod -> ../bin/kmod
            tmp_res, mod_load_cmd = self.get_mod_load_cmd(img_xdir)
            if tmp_res != 0:
                _logger.error('6.0 get_mod_load_cmd failed: res = {} out = {}'.format(tmp_res, mod_load_cmd))
                Initramfs.find_mod_load_dump(img_xdir)
                return -60
            _logger.debug('[add_files] mod_load_cmd={}'.format(mod_load_cmd))
            mod_load_cmd_shtn = os.path.basename(mod_load_cmd)

            driver_count = 0
            sh_lines = list()
            driver_count_clw = 0
            for i, ftnp in enumerate(ftnp_list):

                _logger.debug('6.1 join cp path')
                file_type = ftnp[0]
                src_fn = ftnp[1]
                tar_fn = tar_fn_clt = os.path.basename(ftnp[2])
                if file_type == 'driver':
                    tar_fn = self.join_rep_knlver(dvr_dir, tar_fn)
                elif file_type == 'app':
                    tar_fn = self.join_rep_knlver(app_dir, tar_fn)
                elif file_type == 'cmd':
                    tar_fn = ''
                else:
                    _logger.error('fntp file_type = {} error'.format(file_type))
                    assert False

                _logger.debug("6.11 join cp path: src_fn={}, tar_fn={}".format(src_fn, tar_fn))
                if (src_fn is None or len(src_fn) == 0 or len(tar_fn) == 0) and file_type != 'cmd':
                    continue

                if file_type == 'driver':
                    find_res, sbd_ver = self.find_sbd_driver_version(src_fn)
                    if find_res == 0 or i == 0:
                        driver_count_clw += 1
                        _logger.debug("6.12 find clw driver: file={} sbd_ver={}".format(src_fn, sbd_ver))
                    else:
                        _logger.debug("6.12 find 3rd driver: file={}".format(src_fn))

                _logger.debug('6.2 cp file')

                tmp_b, out_str = crutil.cp_f(src_fn, tar_fn)
                if tmp_b is False and file_type != 'cmd':
                    _logger.error('6.2 cp_f({}, {}) failed: out_str = {}'.format(src_fn, tar_fn, out_str))
                    return -62
                else:
                    _logger.debug("6.2 cp_f({}, {}) success".format(src_fn, tar_fn))

                _logger.debug('6.3 chmod if app')

                if file_type == 'app':
                    tmp_res, out_str = crutil.exec_chmod(tar_fn, 777)
                    if tmp_res is False:
                        _logger.error('6.3 chmod {} 777 failed: out_str = {}'.format(tar_fn, out_str))
                        return -63
                    else:
                        _logger.debug("6.3 chmod {} 777 success".format(tar_fn))

                _logger.debug('6.4 gen sh_line')

                params = '' if ftnp[3] is None else ftnp[3]

                if file_type == 'driver':

                    tar_fn_clt = self.join_rep_knlver(dvr_dir_clt, tar_fn_clt)
                    tar_fn_mod = mod_load_cmd_shtn == 'modprobe' and ftnp[4] or tar_fn_clt
                    sh_line = '{mcmd} {fn} {params}\n'.format(mcmd=mod_load_cmd, fn=tar_fn_mod, params=params)

                elif file_type == 'app':
                    tar_fn_clt = self.join_rep_knlver(app_dir_clt, tar_fn_clt)
                    params = params if src_fn.find('initwait') == -1 else '5 {} 300'.format(wait_secs)
                    sh_line = '{fn} {params}\n'.format(fn=tar_fn_clt, params=params)

                elif file_type == 'cmd':
                    tar_fn_clt = params.split(' ')[0]
                    sh_line = '{params}\n'.format(params=params)

                else:
                    assert False

                echo_line = 'echo "Loading ClerwareRD {} {}"'.format(os.path.basename(tar_fn_clt), file_type)
                # 如果这里注释掉redirect_line, 那么后面的 split_sh_lines_two 中的计算行数要改为2
                # redirect_line = '{} > /proc/filter_proc\n'.format(echo_line)
                echo_line = '{}\n'.format(echo_line)

                sh_lines.append(echo_line)
                # sh_lines.append(redirect_line)
                sh_lines.append(sh_line)

                driver_count = (driver_count + 1) if file_type == 'driver' else driver_count

                mod_name = '' if len(ftnp) < 5 else ftnp[4]
                add_data = [ftnp[0], ftnp[1], ftnp[2], ftnp[3], mod_name, tar_fn_clt.lstrip('/')]
                Initramfs.put_add(add_dict, add_data, 'ftnp_list')
                # end for ftnp_list for

            # driver of clerware there are at least one
            driver_count_clw = 1 if driver_count_clw == 0 else driver_count_clw
            _logger.debug("6 driver_clw_count={}".format(driver_count_clw))

            _logger.debug("6 copy file and gen shell end, sh_lines=\n")
            _logger.debug("{}".format(sh_lines))

            _logger.debug(r'7 add shell')
            _logger.debug(r'7.1 fetch config')

            # 2017-03-09 强行将['shell']['fn']用【;】分割，以能够处理在CentOS 6中，能够支持将
            # 添加的驱动增加到另外一个sh中去， 这个sh放pre-trigger目录， 以支持按不同加载顺序
            # 这只是一个临时更改方案，这种更改方案打破了原来的处理假设（假设全部驱动都放到一个文件中）

            sh_fn_str = cur_rule['shell']['fn']
            sh_fn_array = sh_fn_str.split(';')
            add_mthd = cur_rule['shell']['add']
            crutil.dbg_break()
            _logger.debug(r'7.2 do add shell')

            if add_mthd == 'new':

                if len(sh_fn_array) == 1:  # 所有添加的文件, 写大1个sh文件中

                    sh_fn = self.join_rep_knlver(img_xdir, sh_fn_array[0])
                    tmp_split = os.path.splitext(os.path.basename(sh_fn))
                    if tmp_split[1] != '.sh':
                        _logger.error("config['shell']['fn']={} error, should be *.sh".format(sh_fn))
                        return -72

                    # in some linux: like suse 11, not set PATH for /sbin or /bin
                    sh_head = '#!/bin/sh\n\n'
                    sh_lines.insert(0, sh_head)
                    sh_lines.extend(self.wait_sh(wait_secs))
                    _logger.debug(r'7.3 do add new shell file={} content={}'.format(sh_fn, sh_lines))
                    tmp_res = self.write_sh(sh_fn, sh_lines)
                    if tmp_res != 0:
                        _logger.error(r'7.3 do add new shell file={} failed, res={}'.format(sh_fn, tmp_res))
                        return -730

                elif len(sh_fn_array) == 2:  # 所有添加的文件, 写到2个sh文件中

                    _logger.debug("7.2.2 handle config['shell']['fn']={} with two file".format(sh_fn_str))
                    for fn in sh_fn_array:
                        tmp_split = os.path.splitext(os.path.basename(fn))
                        if tmp_split[1] != '.sh':
                            _logger.error("config['shell']['fn']={} error, should be *.sh".format(sh_fn_str))
                            return -72

                    new_sh_lines_array = self.split_sh_lines_two(sh_lines, driver_count_clw, add_sh_head=True)
                    _logger.debug('7.3 do add new shell file={} sh_lines={}'.format(sh_fn_array, new_sh_lines_array))

                    # 这里len(new_sh_lines_array)肯定小于等于len(sh_fn_array)
                    # 当只有disksbd_linux驱动时, 是没有pre-trigger/00_clrdinit1.sh的
                    for i, tmp_lines in enumerate(new_sh_lines_array):
                        sh_fn = self.join_rep_knlver(img_xdir, sh_fn_array[i])
                        if len(new_sh_lines_array) >= 2 and i == 1:  # 如果有两个, wait_sh加在第二个shell上
                            tmp_lines.extend(self.wait_sh(wait_secs))
                        tmp_res = self.write_sh(sh_fn, tmp_lines)
                        if tmp_res != 0:
                            _logger.error(r'7.3 do add new shell file={} failed, res={}'.format(sh_fn, tmp_res))
                            return -731

                else:  # 所有添加的文件, 写到!(1|2)个sh文件中, 错误
                    _logger.error("7.2.3 config['shell']['fn']={} error".format(sh_fn_str))
                    return -724

            elif add_mthd == 'insert':

                new_sh_lines_array = self.split_sh_lines_by_initwait(sh_lines)
                _logger.debug('7.3 do insert shell file={} sh_lines={}'.format(sh_fn_array, new_sh_lines_array))

                for i, split_sh_lines in enumerate(new_sh_lines_array):
                    if i > len(sh_fn_array):
                        break

                    sh_fn = self.join_rep_knlver(img_xdir, sh_fn_array[i])

                    _logger.debug(r'7.3 do chg old shell file')
                    if os.path.exists(sh_fn) is False:
                        _logger.error('7.3 old shell file not exist: fn = {}'.format(sh_fn))
                        return -73

                    _logger.debug(r'7.4 fetch chg old shell conf')
                    # for compated old config format
                    cstr_key = 'cstr' if i == 0 else 'cstr' + str(i)
                    cstr = cur_rule['shell'][cstr_key]['cstr']
                    ward = cur_rule['shell'][cstr_key]['ward']
                    istr = cur_rule['shell'][cstr_key]['istr']

                    _logger.debug(r'7.5 calc chg line no')
                    lnno, out_str = cal_add_lnno(sh_fn, cstr, ward, istr)
                    if lnno == -1:
                        _logger.error('7.5 cal_add_lnno erro: {}'.format(out_str))
                        return -54

                    _logger.debug(r'7.6 do chg at line: file  ={}'.format(sh_fn))
                    _logger.debug(r'7.6 do chg at line: lnno  ={}'.format(lnno))
                    _logger.debug(r'7.6 do chg at line: lines ={}'.format(split_sh_lines))

                    with chconf.ChConf(sh_fn) as chc:
                        chc.add_lines_atno(split_sh_lines, lnno)
                    # save the insert lines and file into json
                    chfile = {'fn': sh_fn_array[i], 'lines': split_sh_lines}
                    Initramfs.put_add(add_dict, chfile, 'chfiles')

            _logger.debug(r'8 handle other')

            other = cur_rule['other']
            for cb in other:
                cb_func = cb['func']
                cb_args = cb['args']
                if len(cb_func) > 0:
                    fath_args = {'img_xdir': img_xdir,
                                 'ftnp_list': ftnp_list,
                                 'initramfs': self,
                                 'add_dict': add_dict,
                                 'is_ha': is_ha}
                    tmp_res, out_str = eval(cb_func)(cb_args, **fath_args)
                    if tmp_res != 0:
                        _logger.error('8.1 {}({}, {}) failed: {}'.format(cb_func, cb_args, fath_args, out_str))
                        return -81
                else:
                    _logger.warning('8.2 func invalid: other = {}'.format(other))
                    return -82

            mod_dep_fn = self.join_rep_knlver(img_xdir, cur_rule['bdepmod']['depfile'])
            _logger.debug('9 do module if need: {}, {}'.format(mod_dep_fn, mod_load_cmd))
            if os.path.isfile(mod_dep_fn) and mod_load_cmd_shtn == 'modprobe':
                _logger.debug('9.1 do module is need')
                tmp_b, out_str = self.do_depmod(img_xdir)
                if tmp_b is False:
                    _logger.error('do depmod fialed, out_str: {} '.format(out_str))
                    return -90
            else:
                _logger.debug('9.1 do module not need')

            _logger.debug(r'10 write add_dict to json')
            tmp_res, aft_list = get_find_fns(img_xdir)
            if tmp_res != 0:
                _logger.error(r'10.1 get_find_fns for add before failed: {}'.format(bef_list))
                return -101
            add_list = get_add_fns(aft_list, bef_list)
            for fn in add_list:
                tmp_fn = os.path.join(img_xdir, fn.lstrip('/'))
                if os.path.isdir(tmp_fn):
                    Initramfs.put_add(add_dict, fn, 'dir')
                else:
                    Initramfs.put_add(add_dict, fn, 'file')
            tmp_res, out_str = self.__save_add(img_xdir, add_dict)
            if tmp_res != 0:
                _logger.error('10.2 write add_dict to json failed: {msg}'.format(msg=out_str))
                return -102

        except Exception as e:
            _logger.error(r'add_file exception : {ex}'.format(ex=e), exc_info=True)
            _logger.error(r'add_file exception trace+back: {tr}'.format(tr=traceback.format_exc()))
            return -1

        _logger.debug(r'crunch: add_files end')

        return 0

    def add_driver(self, img_xdir, driver_fn, load_seq, with_depmod):
        """
        add one driver to initrd/initramfs
        :param img_xdir: extracted img dir
        :param driver_fn: driver file name
        :param load_seq:  driver start sequence
        :param with_depmod: add driver with do depmod ?
        :return: the True is return if success, or False if failed
        """

        warnings.warn("The 'add_driver' method is deprecated, "
                      "use 'add_files' instead", DeprecationWarning, 2)

        _logger.debug(r'crunch: add_driver begin')
        _logger.debug(r'load_seq not used: {}'.format(load_seq))
        _logger.debug(r'1 verify arguments')

        _logger.debug(r'1.1 verify xdir_img isdir')

        xdir_img = os.path.abspath(img_xdir)
        tmp_res = os.path.isdir(xdir_img)
        if tmp_res is False:
            _logger.debug(r'1.1 verify xdir_img isdir failed: {arg1}'.format(arg1=xdir_img))
            return False

        _logger.debug(r'1.2 verify xdir_img/../ isdir')

        xdir_img_up = os.path.dirname(xdir_img)
        tmp_res = os.path.isdir(xdir_img_up)
        if tmp_res is False:
            _logger.debug(r'1.2 verify xdir_img/../ isdir failed: {arg1}'.format(arg1=xdir_img_up))
            return False

        _logger.debug(r'1.3 verify xdir_img/lib is dir')

        xdir_img_lib = os.path.join(xdir_img, 'lib')
        tmp_res = os.path.isdir(xdir_img_lib)
        if tmp_res is False:
            _logger.debug(r'1.3 verify xdir_img/lib is dir failed: {arg1}'.format(arg1=xdir_img))
            return False

        _logger.debug(r'1.4 verify driver_fn')
        tmp_res = os.path.isfile(driver_fn)
        if tmp_res is False:
            _logger.debug(r'1.4 verify driver_fn exist failed: {arg1}'.format(arg1=driver_fn))
            return False
        if len(os.path.splitext(os.path.basename(driver_fn))) != 2:
            _logger.debug(r'1.4 verify driver_fn fmt(xxx.ko) failed: {arg1}'.format(arg1=driver_fn))
            return False

        _logger.debug(r'2 determine driver install dir')

        xdir_drv_tar = xdir_img_lib
        assert str(self.__knl_ver).find(r'/') == -1
        krnl_ver = self.__knl_ver  # for debug: can't view class.member
        # only handle two case: ko file in lib/ or /lib/modules/$(uname -r)/kernel/drivers
        xdir_img_lib_mod = os.path.join(xdir_img_lib, 'modules', krnl_ver, 'kernel', 'drivers')
        tmp_res = os.path.isdir(xdir_img_lib_mod)
        if tmp_res is True:
            xdir_drv_tar = os.path.join(xdir_img_lib_mod, 'clrd')
            print(os.getcwd())
            if platform.system() == 'Windows':
                crutil.exec_shell_cmd_status(r'mkdir ' + xdir_drv_tar)
            else:
                crutil.exec_shell_cmd_status(r'mkdir -p ' + xdir_drv_tar)
            assert os.path.isdir(xdir_drv_tar) is True

        _logger.debug(r'2 determine driver install dir: {arg1}'.format(arg1=xdir_drv_tar))

        _logger.debug(r'3 cp -rf driver to install dir')

        assert os.path.isabs(driver_fn)

        if platform.system() == 'Windows':
            cmd = r'cp -rf ' + driver_fn + ' ' + xdir_drv_tar
        else:  # linux use copy without no execption
            cmd = r'\cp -rf ' + driver_fn + ' ' + xdir_drv_tar
        tmp_res, out_str = subprocess.getstatusoutput(cmd)
        if tmp_res != 0:
            _logger.debug(r'3 \cp -rf driver to install dir failed: {arg1}'.format(arg1=cmd))
            return False

        _logger.debug(r'4 change config')

        # 5 - init: a /bin/nash script text executable
        # 6 - init: POSIX shell script text executable
        # 7 - init: symbolic link to `usr/lib/systemd/systemd'
        #           ./usr/lib/systemd/systemd: ELF 64-bit LSB shared object
        # 5 - init: init->insmod
        # 6 - init->source_all cmdline->emuerate comline/*.sh and execute
        # 7 - /usr/lib/systemd/system/systemd-modules-load.service
        #     for load seq research, refer: /tmp/initrd-ex/img/etc/udev/rules.d
        #     /tmp/initrd-ex/img/usr/sbin/initqueue(shell)

        _logger.debug(r'4.1 check init file exist')

        init_fn = os.path.join(xdir_img, 'init')
        if os.path.exists(init_fn) is False:
            _logger.debug(r'4.1 check init file exist failed: {arg1}:'.format(arg1=init_fn))
            return False

        _logger.debug(r'4.2 chconf')

        chkf = chkfile.ChkFile(init_fn)

        # if the driver is installed: ./lib, then add_lines to init directly
        if xdir_drv_tar == xdir_img_lib:  # rhel5/centos5
            # 1 driver file at: xdir_img/lib/xxxx.ko
            # 2 driver load at xdir_img/init: insmod xxxx.ko
            # 3 insert after first 'mkblkdevs'
            assert chkf.grep('insmod /lib/') > 0 and chkf.grep('mkblkdevs') > 0
            driver_fn_base = os.path.basename(driver_fn)  # insmod use driver filename
            driver_fn_new = os.path.join(r'/lib/', driver_fn_base)
            alines = ['\n', 'echo "Loading ' + driver_fn_base + 'module"\n', 'insmod ' + driver_fn_new + '\n']
            pstr = 'mkblkdevs'
            with chconf.ChConf(init_fn) as chc:
                tmp_res = chc.add_lines_oseq(alines, pstr, 'a', 1)
            if tmp_res == 0:
                _logger.debug(r'4.2 chconf failed: fn={arg1}, add_lines={arg2}'.format(arg1=init_fn, arg2=alines))
                return False
        else:
            if chkf.file('script text') and chkf.grep('source_all cmdline') > 0:  # rhel6/centos6
                # 1 driver file at: xdir_img/lib/modules/$(uname -r)/kernel/drivers/clrd/xxxx.ko
                # 2 init is a sh, execute: source_all cmdline/*.sh
                #   driver load: xdir_img/cmd_line/01parse-kernel.sh by for p in (rdloaddriver=):
                # 3 add modprobe xxxx 2>&1 | vinfo before the for in 01parse-kernel.sh
                modprb_sh_dir = os.path.join(xdir_img, 'cmdline')
                modprb_sh_fn = os.path.join(modprb_sh_dir, '01parse-kernel.sh')
                # modprobe use mod name(no file ext), has verified before
                mod_name = os.path.splitext(os.path.basename(driver_fn))[0]
                alines = ['\n', 'modprobe {arg1} 2>&1 | vinfo'.format(arg1=mod_name), '\n']
                pstr = '#!/bin/sh'
                if os.path.isfile(modprb_sh_fn):
                    with chconf.ChConf(modprb_sh_fn) as chc:
                        chc.add_lines_oseq(alines, pstr, 'a', 1)
                else:
                    modprb_sh_fn = os.path.join(modprb_sh_dir, '00parse-clrd.sh')
                    alines = ['#!/bin/sh']
                    alines.extend(alines)
                    with chconf.ChConf(modprb_sh_fn) as chc:
                        chc.add_lines_tail(alines)
            else:  # rhel7/centos7
                # 1 driver file at: xdir_img/lib/modules/$(uname -r)/kernel/drivers/clrd/xxxx.ko
                # 2 init is a exe, load driver refer the xdir_img/sur/lib/systemd/system/systemd-modules-load.service
                #   load driver find driver laod config path: /lib/modules-load.d
                # 3 create xdir_img/lib/modules-load.d dir
                # 4 create xxxx.conf, content:xxxx
                modload_srv_fn = os.path.join(xdir_img, 'usr/lib/systemd/system', 'systemd-modules-load.service')
                if os.path.exists(modload_srv_fn):
                    modload_dir = os.path.join(xdir_img, 'lib', 'modules-load.d')
                    crutil.exec_shell_cmd_status('mkdir -p ' + modload_dir)
                    mod_name = os.path.splitext(os.path.basename(driver_fn))[0]
                    mod_conf_fn = os.path.join(modload_dir, mod_name + '.conf')
                    alines = [mod_name + '\n']
                    with chconf.ChConf(mod_conf_fn) as chc:
                        chc.add_lines_tail(alines)
                else:
                    _logger.debug("can't handle")
                    return False

        _logger.debug(r'4 do depmod')

        if with_depmod is False:
            _logger.debug(r'4 do depmod nothing with_dempod: {arg1}'.format(arg1=with_depmod))
        else:
            if self.be_depmod(xdir_img) is False:
                _logger.debug(r'4 do depmod nothing nothing: no dep file')
            else:
                tmp_res, out_str = self.do_depmod(xdir_img)
                if tmp_res is False:
                    _logger.debug(r'4 do depmod failed: {arg1}'.format(arg1=out_str))
                    return False

        _logger.debug(r'crunch: add_driver succ end')
        return True

    def be_depmod(self, img_xdir):
        """
        determine wheather need to be depmod.
        :param img_xdir: initrd/initramfs extracted dir
        :return: True is need to be, or False
        """
        xdir_img = os.path.abspath(img_xdir)
        krnl_ver = self.__knl_ver
        dep_fn = os.path.join(xdir_img, 'lib', 'modules', krnl_ver, 'modules.dep')
        tmp_res = os.path.exists(dep_fn)
        return tmp_res

    def do_depmod(self, img_xdir):
        """
        call depmod to re-generate the initrd/initramfs modeules.dep et.
        if add more than on driver, you can set add_driver's do_depmod as false
        and at the final to do_depmod
        :param img_xdir: img extracted dir
        :return: the True is return if success, or False if faild
        """
        _logger.debug('do_depmod begin')

        # _logger.debug('check symvers-{}.gz file'.format(self.__knl_ver))
        # symvers_fn = 'symvers-{}'.format(self.__knl_ver)
        # symvers_fn_gz = symvers_fn + '.gz'
        # symvers_fn_gz = os.path.join(os.path.dirname(self.__in_ffn), symvers_fn_gz)
        # chf = chkfile.ChkFile(symvers_fn_gz)
        # tmp_res = chf.file('gzip')
        # if tmp_res is False:
        #     _logger.error('check file={} is gzip file failed'.format(symvers_fn_gz))
        #     return False, 'not exist or not gzip file'
        #
        # _logger.debug('gunzip symvers-{}.gz file'.format(self.__knl_ver))
        # symvers_fn = os.path.join(os.path.dirname(self.__in_ffn), symvers_fn)
        # unzip_cmd = 'gunzip -c {} > {}'.format(symvers_fn_gz, symvers_fn)
        # tmp_res, out_str = crutil.wrap_getstatusoutput(unzip_cmd)
        # if tmp_res != 0 or os.path.isfile(symvers_fn) is False:
        #     _logger.error('gunzip {} to {} failed: {}'.format(symvers_fn_gz, symvers_fn, out_str))
        #     return False, 'gunzip symvers file failed'

        _logger.debug('check System.map-{} file'.format(self.__knl_ver))
        sysmap_fn = 'System.map-{}'.format(self.__knl_ver)
        sysmap_fn = os.path.join(os.path.dirname(self.__in_ffn), sysmap_fn)
        if os.path.isfile(sysmap_fn) is False:
            _logger.error('check file={}')

        _logger.debug('do depmod')
        base_dir = os.path.abspath(img_xdir)

        # 2017-2-28: 为了解决OracleLinux上的depmod将modules.builtin.bin改了导致不能启动的问题
        # 在depmod前, 先备份modules.builtin.bin和modules.builtin, 执行完后, 将其覆盖.
        # 目前看来, 只有oracle Linux才会有次情况, centos 6和7都不会有此情况:
        # Centos 6 没有modules.builtin.bin或modules.builtin,
        # centos7 用的是kmod ln的insmod, 不会进depmod

        mod_path = os.path.join(base_dir, 'lib/modules/', self.__knl_ver)
        bk_path = os.path.dirname(base_dir)

        dir_bef = os.listdir(mod_path)
        bk_list = list()
        for fn in dir_bef:
            if fn in ['modules.builtin', 'modules.builtin.bin']:
                src_fn = os.path.join(mod_path, fn)
                bk_fn = os.path.join(bk_path, fn)
                tmp_b, out_str = crutil.cp_f(src_fn, bk_fn)
                if tmp_b is True:
                    bk_list.append((src_fn, bk_fn))
                else:
                    _logger.warning('do_depmod: backup {} to {} failed'.format(src_fn, bk_fn))

        # cmd = r'depmod -b {} -E {} -F {} -w {}'.format(base_dir, symvers_fn, sysmap_fn, self.__knl_ver)
        # 2017-2-28: 今天重新看man depmod, 发现-E和-F参数是冲突的. -E参数可以不要, -C 指定/etc/modprobe.d配置, 不用host机器的
        # depmod -A -a参数: -a 参数是全部probe, -A参数是probe比modules.dep更新(至于是那个时间[amc]更新, 未知)
        # 这个问题是有xd在外面改的, 在外面每次更新modules.dep的时间到当前, 然后, 延后一秒调用add_files, add_file会拷贝驱动
        # 驱动拷贝后, 所有驱动文件的时间会被更新为当前时间. 也就比modules.dep的时间新了, 用-A参数就可以了.

        cmd = r'depmod -b {} -F {} -A -w {}'.format(base_dir, sysmap_fn, self.__knl_ver)
        tmp_res, out_str = crutil.wrap_getstatusoutput(cmd)
        _logger.info('exec cmd={}, return={}, {}'.format(cmd, tmp_res, out_str))
        # althrough the output has WARNING, tmp_res returned 0, so if == 0 is success
        if tmp_res != 0:
            _logger.error('do depmod failed end: cmd={}, return={}, {}'.format(cmd, tmp_res, out_str))
            return False, 'do depmod failed'

        # delete added files that new generated by depmod
        dir_aft = os.listdir(mod_path)
        add_list = get_add_fns(dir_aft, dir_bef)
        for fn in add_list:
            os.remove(os.path.join(mod_path, fn))
        # restore the modules.builtin and modules.builtin.bin
        for fns in bk_list:
            tmp_b, out_str = crutil.cp_f(fns[1], fns[0])
            if tmp_b is False:
                _logger.warning('do_depmod: recover {} to {} failed'.format(fns[1], fns[0]))

        _logger.info('do depmod succ end')
        return True, ''


# ======================================================================================================================
# test main
# ======================================================================================================================


if __name__ == "__main__":

    # _logger.handlers.clear()
    # _logger.addHandler(logging.StreamHandler())
    import initfn

    if platform.system().lower() == 'linux':

        # 0 类型 1 源文件名 2 拷贝过去的目标文件名 3 参数 4 mod名
        g_ftnp_list = [
            ('driver', r'/home/bootrd-dbg/drive-test/sbd.ko', 'disksbd_linux.ko', 'arg="121"', 'disksbd_linux'),
            ('driver', r'/home/bootrd-dbg/drive-test/fun.ko', 'sbd_fun_linux.ko', None, 'sbd_fun_linux'),
            ('driver', r'/home/bootrd-dbg/drive-test/e1000.ko', 'e1000.ko', '', 'e1000'),
            ('app', r'/home/bootrd-dbg/drive-test/app.sh', 'app.sh', '1'),
            ('cmd', '', '', 'echo "demo to add cmd"', '')
        ]

        g_tmp_dir = r'/home/bootrd-dbg/initrd-tmp'
        if os.path.exists(g_tmp_dir):
            g_tmp_res, g_out_str = crutil.wrap_getstatusoutput('rm -rf {}'.format(g_tmp_dir))
            assert g_tmp_res == 0
        g_tmp_res, g_out_str = crutil.wrap_getstatusoutput('mkdir -p {}'.format(g_tmp_dir))
        assert g_tmp_res == 0

        crutil.dbg_break()
        test_other = True
        g_knl_ver = ''
        g_init_fns = list()
        if test_other:
            g_boot_files_dir = r'/home/bootrd-dbg/cur-test-initrd-files'
            g_init_fns_base = os.listdir(g_boot_files_dir)
            for g_fn in g_init_fns_base:
                if g_fn.find('System.map-') != -1:
                    g_knl_ver = g_fn[len('System.map-'):]
            assert len(g_knl_ver) > 0
            for g_fn in g_init_fns_base:
                g_init_fns.append(os.path.join(g_boot_files_dir, os.path.basename(g_fn)))
        else:
            g_tmp_res, g_knl_ver = crutil.wrap_getstatusoutput('uname -r')
            assert g_tmp_res == 0
            g_tmp_res, g_init_fns = initfn.get_def_init_fns('/')
            assert g_tmp_res == 0
            g_boot_dir = os.path.dirname(g_init_fns[0])
            g_init_fns.append(os.path.join(g_boot_dir, 'symvers-{}.gz'.format(g_knl_ver)))
            g_init_fns.append(os.path.join(g_boot_dir, 'System.map-{}'.format(g_knl_ver)))

        assert len(g_init_fns) > 0
        g_in_dir = g_tmp_dir[:]

        crutil.dbg_break()
        g_in_ffn = ''
        for g_fn in g_init_fns:
            g_cmd = '\cp -f {} {}'.format(g_fn, g_in_dir)
            g_tmp_res, g_out_str = crutil.wrap_getstatusoutput(g_cmd)
            assert g_tmp_res == 0
            if g_fn.find('initrd-' + g_knl_ver) != -1 \
                    or g_fn.find('initramfs-' + g_knl_ver) != -1\
                    or g_fn.find('initrd.img-' + g_knl_ver) != -1:
                g_in_ffn = os.path.join(g_in_dir, os.path.basename(g_fn))
        assert len(g_in_ffn) > 0

        crutil.dbg_break()
        initrd_fn = os.path.basename(g_in_ffn)
        if initrd_fn.find('initrd') != -1:
            g_out_ffn = initrd_fn.replace('initrd', 'initrd.clrd')
        elif initrd_fn.find('initramfs') != -1:
            g_out_ffn = initrd_fn.replace('initramfs', 'initramfs.clrd')
        else:
            assert False
        g_out_ffn = os.path.join(os.path.dirname(g_in_ffn), g_out_ffn)

        g_distrib_ver = crutil.get_distribver(platform.platform())
        crutil.dbg_break()
        g_initramfs = Initramfs(g_in_ffn, g_out_ffn, g_tmp_dir, g_distrib_ver, g_knl_ver)

        crutil.dbg_break()
        g_tmp_b, g_xdir_img = g_initramfs.extract()
        if g_tmp_b is False:
            print('extract failed')
        else:
            print('extract success: xdir_img={}'.format(g_xdir_img))

        linux_info = dict()
        linux_info['bit_opt'] = ''
        g_img_bin_dir = os.path.join(g_xdir_img, 'bin')
        fbn_list = os.listdir(g_img_bin_dir)
        for g_fn in fbn_list:
            g_chkf = chkfile.ChkFile(os.path.join(g_img_bin_dir, g_fn))
            g_tmp_res, _ = g_chkf.file_ln('ELF 64-bit')
            if g_tmp_res:
                linux_info['bit_opt'] = '64'
                break
            g_tmp_res, _ = g_chkf.file_ln('ELF 32-bit')
            if g_tmp_res:
                linux_info['bit_opt'] = '32'
                break
        assert len(linux_info['bit_opt']) > 0

        initwait_name = 'initwait' + linux_info['bit_opt']
        initwait_path = os.path.join(os.getcwd(), r'clerware_linux_apps', initwait_name)
        _logger.info(r'_get_initwait_path : {}'.format(initwait_path))

        need = g_initramfs.need_initwait_app(g_xdir_img)
        _logger.info('initramfs.need_initwait_app need={}'.format(need))
        if need:
            # initwait_path = self._get_initwait_path()
            g_ftnp_list.append(('app', initwait_path, 'initwait', '', ''))

        crutil.dbg_break()
        g_tmp_res = g_initramfs.add_files(g_xdir_img, g_ftnp_list, is_ha=0)
        if g_tmp_res != 0:
            print('add file failed')
        else:
            print('add_file success')

        need = g_initramfs.need_initwait_app(g_xdir_img)
        print('need_initwait_app: {nd}'.format(nd=need))

        crutil.dbg_break()
        g_ftnp_list = g_initramfs.get_added_files(g_xdir_img)
        if g_ftnp_list is not None:
            print('get_added_files: {list}'.format(list=g_ftnp_list), )
        else:
            print('get_added_files error')

        crutil.dbg_break()
        g_tmp_b = g_initramfs.pack(g_xdir_img)
        if g_tmp_b is False:
            print('pack failed')
        else:
            print('pack success')

        crutil.dbg_break()
        print('crunch: linux test end')
        sys.exit(0)

    else:
        _initramfs_op_basedir = r'e:\temp\initramfs-op'
        _initramfs_extr_basedir = os.path.join(_initramfs_op_basedir, 'extr')
        _initramfs_imgs_basedir = os.path.join(_initramfs_op_basedir, 'imgs')
        _logger.debug('# initramfs operator start')
        # show_and_exe_cmd_line_and_get_ret('cmd.exe /c start notepad.exe')

        linux_rh = [
            ('Linux-2.6.18-8.el5-x86_64-with-redhat-5-Final',
             '2.6.18-8.el5',
             'centos5',
             'initrd-'),
            ('Linux-2.6.32-279.el6.i686-i686-with-centos-6.3-Final',
             '2.6.32-279.el6.i686',
             'centos6',
             'initramfs-'),
            ('Linux-3.10.0-327.el7.x86_64-x86_64-with-centos-7.2.1511-Core',
             '3.10.0-327.el7.x86_64',
             'centos7',
             'initramfs-'),
            ('Linux-3.10.0-327.13.1.el7.x86_64-x86_64-with-centos-7.2.1511-Core',
             '3.10.0-327.13.1.el7.x86_64',
             'centos72',
             'initramfs-'),
            ('Linux-2.6.16.21-0.8-default-i686-with-SuSE-10-i586',
             '2.6.16.21-0.8-default',
             'suse10',
             'initrd-')
        ]
        test_osv = 4
        g_img_dir = os.path.join(_initramfs_imgs_basedir, str(uuid.uuid4().hex))
        crutil.exec_shell_cmd_status(r'mkdir -p ' + g_img_dir)

        knl_vstr = linux_rh[test_osv][1]

        # copy src img from /boot

        g_img_fn = linux_rh[test_osv][3] + knl_vstr + '.img'
        g_in_ffn = os.path.join(g_img_dir, g_img_fn)
        g_cmd = r'cp ' + os.path.join(_initramfs_op_basedir, linux_rh[test_osv][3], g_img_fn) + ' ' + g_in_ffn
        g_tmp_res, g_tmp_lines = crutil.exec_shell_cmd_status(g_cmd)
        g_find_res, null = crutil.find_in_lines(g_tmp_lines, 'cp: overwrite')
        assert g_find_res is False

        g_img_fn_out = linux_rh[test_osv][3] + knl_vstr + '.clrd.img'
        g_out_ffn = os.path.join(g_img_dir, g_img_fn_out)

        g_distrib_ver = crutil.get_distribver(linux_rh[test_osv][0])
        g_knl_ver = linux_rh[test_osv][1]
        g_xdir_img_base = 'e:\\temp\\initramfs-op\\'
        g_xdir_img = os.path.join(g_xdir_img_base, linux_rh[test_osv][2], 'img')
        # assert os.path.exists(g_xdir_img)
        g_initramfs = Initramfs(g_in_ffn, g_out_ffn, _initramfs_extr_basedir, g_distrib_ver, g_knl_ver)

        # def add_driver(self, img_xdir, driver_fn, load_seq, with_depmod):
        g_drv_fn = os.path.join(g_xdir_img_base, linux_rh[test_osv][2], 'driver', 'crunchtest.ko')
        assert os.path.exists(g_drv_fn)

        # ftnp_list: list[tuple(file_type, src_name, tar_name, params_str)]

        g_ftnp_list = [
            ('driver', r'E:\temp\initramfs-op\add_files\sbd.ko', 'disksbd_linux.ko', 'arg="121"', 'disksbd_linux'),
            ('driver', r'E:\temp\initramfs-op\add_files\fun.ko', 'sbd_fun_linux.ko', None, 'sbd_fun_linux'),
            ('driver', r'E:\temp\initramfs-op\add_files\e1000.ko', 'e1000.ko', '', 'e1000'),
            ('app', r'E:\temp\initramfs-op\add_files\app.sh', 'testapp.sh', '1'),
            ('cmd', '', '', 'echo "demo to add cmd"', '')
        ]
        g_ret = g_initramfs.add_files(g_xdir_img, g_ftnp_list, 1)
        if g_ret != 0:
            print('add_files error: {}'.format(g_ret))

        g_ftnp_list = g_initramfs.get_added_files(g_xdir_img)
        if g_ftnp_list is not None:
            print('get_added_files: {list}'.format(list=g_ftnp_list), )
        else:
            print('get_added_files error')

        crutil.dbg_break()

        # g_initramfs.add_driver(g_xdir_img, g_drv_fn, 0, True)

        (g_tmp_res, g_newimg_fn) = g_initramfs.extract_gzip()
        # pdb.set_trace()
        if g_tmp_res is True and len(g_newimg_fn) > 0:
            g_initramfs.pack(g_newimg_fn)
        else:
            _logger.debug('# initramfs extract failed')

        _logger.debug('# initramfs operateor end')

        sys.exit(0)
