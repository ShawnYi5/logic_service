import os
import signal
import subprocess
import tempfile
import time
import traceback

import xlogging

_logger = xlogging.getLogger(__name__)

link_para_list = ['kernel_ver', 'bit_opt', 'vermagic', 'src_dir', 'tmp_dir', 'syms_file', 'kconfig_file']


def get_info_from_syscmd(in_cmd_line, timeout=100):
    if len(in_cmd_line) <= 0:
        _logger.error("invalid cmd line")
        return -1, None
    try:
        _logger.debug("start cmd {}".format(in_cmd_line))
        p = subprocess.Popen(in_cmd_line, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        retval = None
        timeout *= 10
        if timeout > 0:
            t = 0
            while t < timeout:
                retval = p.poll()
                if retval is not None:
                    _logger.debug(
                        'cmd {} process ret success,retval {},timer {} {}'.format(in_cmd_line, retval, t, timeout))
                    break
                t += 1
                time.sleep(0.1)
            else:
                retval = p.poll()
                if retval is None:
                    os.kill(p.pid, signal.SIGKILL)
                    _logger.error('cmd {} process killed,timer {} {}'.format(in_cmd_line, t, timeout))

        if retval is None:
            retval = p.wait()
        _logger.debug("run cmd {} ret {}".format(in_cmd_line, retval))
        mstr = p.stdout.read()
        if retval != 0:
            _logger.error("run cmd {} failed,ret str {}".format(in_cmd_line, mstr))
            return -2, mstr
        else:
            _logger.debug("run cmd {} success,ret str {}".format(in_cmd_line, mstr))
            return 0, mstr
    except Exception as e:
        _logger.error("run cmd {} error, {} {}".format(in_cmd_line, e, traceback.format_exc()))
        return -1, None


def read_file(in_file, in_format, pdebug=True):
    if os.path.isfile(in_file):
        try:
            with open(in_file, in_format) as fd:
                mstr = fd.read()
                fd.close()
                if pdebug:
                    _logger.debug("read file {} success,info {}".format(in_file, mstr))
                return 0, mstr
        except Exception as e:
            ret_str = "read file {} failed, {} {}".format(in_file, e, traceback.format_exc())
            _logger.error(ret_str)
    else:
        ret_str = "read file {} failed,file not exist".format(in_file)
        _logger.error(ret_str)
    return -1, ret_str


def write_file(in_file, in_str, in_format):
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
            return 0, ''
    except Exception as e:
        ret_str = "write file {} failed, {} {}".format(in_file, e, traceback.format_exc())
        _logger.error(ret_str)
        return -1, ret_str


def get_kdir(kernel_ver):
    KDIR = os.path.join('/sbin/aio/link-utils/kernel', kernel_ver)
    if os.path.isdir(KDIR):
        return KDIR
    _logger.error('KDIR {} not exist'.format(KDIR))
    return ''


def link_para_check(para_dict):
    global link_para_list
    for value in link_para_list:
        if len(para_dict[value]) <= 0:
            ret_str = 'para {} invalid'.format(value)
            _logger.error(ret_str)
            return -1, ret_str
    KDIR = get_kdir(para_dict['kernel_ver'])
    if KDIR == '':
        ret_str = 'kernel_ver {} invalid'.format(para_dict['kernel_ver'])
        _logger.error(ret_str)
        return -1, ret_str
    if not os.path.isfile(os.path.join(KDIR, 'modpost')):
        ret_str = 'kernel_ver {} invalid,modpost not exist'.format(para_dict['kernel_ver'])
        _logger.error(ret_str)
        return -1, ret_str

    if (para_dict['bit_opt'] != '32') and (para_dict['bit_opt'] != '64') and (para_dict['bit_opt'] != '32_PAE'):
        ret_str = 'bit_opt {} invalid'.format(para_dict['bit_opt'])
        _logger.error(ret_str)
        return -1, ret_str
    for value in link_para_list[3:5]:
        if not os.path.isdir(para_dict[value]):
            ret_str = '{} {} not exist'.format(value, para_dict[value])
            _logger.error(ret_str)
            return -1, ret_str
    for value in link_para_list[5:7]:
        if not os.path.isfile(para_dict[value]):
            ret_str = '{} {} not exist'.format(value, para_dict[value])
            _logger.error(ret_str)
            return -1, ret_str
    return 0, ''


def modify_config(src_config, des_config):
    ret = read_file(src_config, 'r')
    if ret[0] != 0:
        return ret
    des_str = ''
    src_str = ret[1]
    src_list = src_str.splitlines()
    for line in src_list:
        line.strip(' ')
        if line.startswith('CONFIG_'):
            mlist = line.split('=')
            if len(mlist) != 2:
                _logger.error('invalid line {}'.format(line))
            else:
                if mlist[1] == 'y':
                    des_one = '#define ' + mlist[0] + ' 1\n'
                elif mlist[1] == 'm':
                    des_one = '#define ' + mlist[0] + '_MODULE 1\n'
                else:
                    des_one = '#define ' + mlist[0] + ' ' + mlist[1] + '\n'
                des_str += des_one
                # _logger.debug('{}           {}'.format(line,des_one))

    if len(des_str) > 0:
        ret = write_file(des_config, des_str, 'w')
        if ret[0] != 0:
            return ret
    return 0, ''


def get_compile_str(kernel_var, target):
    _logger.debug('kernel_var {},target {}'.format(kernel_var, target))
    if kernel_var == '2.6.18':
        return '$MODPOST -m -a -i $KSYMS -I $DESDIR/{}.symvers -o $DESDIR/{}.symvers $DESDIR/{}.o\n' \
               'gcc -m$BITOPT -Wp,-MD,$DESDIR/.{}.mod.o.d  -nostdinc -isystem $GCCDIR/include ' \
               '-D__KERNEL__ -I$KDIR/include  -include $KDIR/include/linux/autoconf.h -Wall -Wundef ' \
               '-Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Wstrict-prototypes ' \
               '-Wundef -Werror-implicit-function-declaration -Os -pipe -msoft-float -fno-builtin-sprintf ' \
               '-fno-builtin-log2 -fno-builtin-puts -mpreferred-stack-boundary=2 -march=i686 -mtune=generic ' \
               '-mtune=generic -mregparm=3 -ffreestanding -I$KDIR/ -I$KDIR/include ' \
               '-I$KDIR/include/asm-i386/mach-generic -I$KDIR/include/asm-i386/mach-default -fomit-frame-pointer ' \
               '-g  -fno-stack-protector -Wdeclaration-after-statement -Wno-pointer-sign -D"KBUILD_STR(s)=#s" ' \
               '-D"KBUILD_BASENAME=KBUILD_STR({}.mod)" -D"KBUILD_MODNAME=KBUILD_STR({})" -DMODULE ' \
               '-c -o $DESDIR/{}.mod.o $DESDIR/{}.mod.c\n' \
               'ld -m $ELFOPT -r -o $DESDIR/{}.ko $DESDIR/{}.o $DESDIR/{}.mod.o\n'. \
            format(target, target, target, target, target, target, target, target, target, target, target)
    elif kernel_var == '2.6.32':
        return '$MODPOST -m -a -i $KSYMS -I $DESDIR/{}.symvers  -o $DESDIR/{}.symvers -S -w -s $DESDIR/{}.o\n' \
               'gcc -m$BITOPT -Wp,-MD,$DESDIR/.{}.mod.o.d  -nostdinc -isystem $GCCDIR/include ' \
               '-I$KDIR/include  -I$KDIR/arch/x86/include -include $KDIR/include/linux/autoconf.h ' \
               '-D__KERNEL__ -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing ' \
               '-fno-common -Werror-implicit-function-declaration -Wno-format-security ' \
               '-fno-delete-null-pointer-checks -O2 -m32 -msoft-float -mregparm=3 -freg-struct-return ' \
               '-mpreferred-stack-boundary=2 -march=i686 -mtune=generic -Wa,-mtune=generic32 -ffreestanding ' \
               '-fstack-protector -DCONFIG_AS_CFI=1 -DCONFIG_AS_CFI_SIGNAL_FRAME=1 -pipe -Wno-sign-compare ' \
               '-fno-asynchronous-unwind-tables -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -Wframe-larger-than=1024 ' \
               '-fomit-frame-pointer -g -Wdeclaration-after-statement -Wno-pointer-sign -fno-strict-overflow ' \
               '-fno-dwarf2-cfi-asm -fconserve-stack  -D"KBUILD_STR(s)=#s" ' \
               '-D"KBUILD_BASENAME=KBUILD_STR({}.mod)"  -D"KBUILD_MODNAME=KBUILD_STR({})" -D"DEBUG_HASH=62" ' \
               '-D"DEBUG_HASH2=24" -DMODULE -c -o $DESDIR/{}.mod.o $DESDIR/{}.mod.c\n' \
               'ld -r -m $ELFOPT -T $KDIR/scripts/module-common.lds --build-id -o $DESDIR/{}.ko ' \
               '$DESDIR/{}.o $DESDIR/{}.mod.o\n'. \
            format(target, target, target, target, target, target, target, target, target, target, target)
    elif kernel_var == '3.10.0':
        return 'echo "$DESDIR/{}.o" | $MODPOST -m -a -i $KSYMS -I $DESDIR/{}.symvers  -o $DESDIR/{}.symvers  ' \
               '-w -s -T -\n' \
               'gcc -m$BITOPT -Wp,-MD,$DESDIR/.{}.mod.o.d  -nostdinc -isystem $GCCDIR/include ' \
               '-I$KDIR/arch/x86/include -I$KDIR/arch/x86/include/generated  -I$KDIR/include ' \
               '-I$KDIR/arch/x86/include/uapi -I$KDIR/arch/x86/include/generated/uapi ' \
               '-I$KDIR/include/uapi -I$KDIR/include/generated/uapi -include $KDIR/include/linux/kconfig.h ' \
               '-D__KERNEL__ -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing ' \
               '-fno-common -Werror-implicit-function-declaration -Wno-format-security ' \
               '-fno-delete-null-pointer-checks -O2 -mno-sse -mpreferred-stack-boundary=3 ' \
               '-mtune=generic -mno-red-zone -mcmodel=kernel -funit-at-a-time -maccumulate-outgoing-args ' \
               '-Wframe-larger-than=2048 -DCONFIG_AS_CFI=1 -DCONFIG_AS_CFI_SIGNAL_FRAME=1 ' \
               '-DCONFIG_AS_CFI_SECTIONS=1 -DCONFIG_AS_FXSAVEQ=1 -DCONFIG_AS_AVX=1 -DCONFIG_AS_AVX2=1 ' \
               '-pipe -Wno-sign-compare -fno-asynchronous-unwind-tables -mno-sse -mno-mmx -mno-sse2 ' \
               '-mno-3dnow -mno-avx -Wframe-larger-than=2048 -fstack-protector-strong ' \
               '-Wno-unused-but-set-variable -fno-omit-frame-pointer -fno-optimize-sibling-calls ' \
               '-g -pg -mfentry -DCC_USING_FENTRY -fno-inline-functions-called-once ' \
               '-Wdeclaration-after-statement -Wno-pointer-sign -fno-strict-overflow -fconserve-stack ' \
               '-DCC_HAVE_ASM_GOTO  -D"KBUILD_STR(s)=#s" -D"KBUILD_BASENAME=KBUILD_STR({}.mod)"  ' \
               '-D"KBUILD_MODNAME=KBUILD_STR({})" -DMODULE  -c -o $DESDIR/{}.mod.o $DESDIR/{}.mod.c\n' \
               'ld -r -m $ELFOPT -T $KDIR/scripts/module-common.lds --build-id -o $DESDIR/{}.ko ' \
               '$DESDIR/{}.o $DESDIR/{}.mod.o\n'. \
            format(target, target, target, target, target, target, target, target, target, target, target)
    else:
        _logger.error('invalid kernel_ver {}'.format(kernel_var))
        return ''


def generate_compile_sh(para_dict):
    write_sh = 0
    kernel_ver = para_dict['kernel_ver']
    KDIR = get_kdir(kernel_ver)
    modpost = os.path.join(KDIR, 'modpost')
    bit_opt = para_dict['bit_opt']  # '32', '64', '32_PAE'
    GCCDIR = '/usr/lib/gcc/x86_64-redhat-linux/4.8.5'
    src_dir = para_dict['src_dir']
    tmp_dir = para_dict['tmp_dir']
    ksyms = para_dict['syms_file']
    vermagic = '#define VERMAGIC_STRING ' + '\"' + para_dict['vermagic'] + '\"'
    sh_file = os.path.join(tmp_dir, 'ld.sh')

    if bit_opt == '32_PAE':
        bit_opt = '32'
    if bit_opt == '32':
        elf_opt = 'elf_i386'
    else:
        elf_opt = 'elf_x86_64'
    write_sh_str = '#!/bin/sh -e\nKDIR={}\nBITOPT={}\nELFOPT={}\nMODPOST={}\nGCCDIR={}\nKSYMS={}\nDESDIR={}\n'. \
        format(KDIR, bit_opt, elf_opt, modpost, GCCDIR, ksyms, tmp_dir)

    cmdline = 'rm -rf ' + tmp_dir + '/*;' + '\\cp -rf ' + src_dir + '/*.o ' + src_dir + '/*.symvers ' + tmp_dir
    ret = get_info_from_syscmd(cmdline, 5 * 60)
    if ret[0] != 0:
        _logger.error('get_info_from_syscmd failed ret {}'.format(ret))
        return ret
    ret = write_file(os.path.join(KDIR, 'include/linux/vermagic.h'), vermagic, 'w')
    if ret[0] != 0:
        return ret

    ret = modify_config(para_dict['kconfig_file'], os.path.join(KDIR, 'include/linux/autoconf.h'))
    if ret[0] != 0:
        return ret

    for fn in os.listdir(tmp_dir):
        targets = os.path.join(tmp_dir, fn)
        if not os.path.isfile(targets):
            continue
        mstr = fn[len(fn) - 2:]
        if mstr != '.o':
            continue
        mname = fn[:len(fn) - 2]
        mstr = get_compile_str(kernel_ver, mname)
        if mstr == '':
            ret_str = 'invalid target {}'.format(fn)
            _logger.error(ret_str)
            return -1, ret_str
        write_sh_str += mstr
        write_sh = 1
    if write_sh == 1:
        ret = write_file(sh_file, write_sh_str, 'w')
        if ret[0] != 0:
            return ret
        return 0, sh_file
    else:
        return -1, 'no valid .o file'


def modlink(para_dict):
    try:
        ret = link_para_check(para_dict)
        if ret[0] != 0:
            _logger.error('link_para_check failed ret {}'.format(ret))
            return ret
        ret = generate_compile_sh(para_dict)
        if ret[0] != 0:
            _logger.error('generate_compile_sh failed ret {}'.format(ret))
            return ret
        cmdline = 'chmod +x {}'.format(ret[1]) + ';' + ret[1]
        ret = get_info_from_syscmd(cmdline, 5 * 60)
        if ret[0] != 0:
            _logger.error('get_info_from_syscmd failed ret {}'.format(ret))
            return ret
        return 0, ''
    except Exception as e:
        _logger.error("modlink failed,{} {}".format(e, traceback.format_exc()))
        return -1, 'link failed'


# link_para_list = ['kernel_ver', 'bit_opt', 'version_magic', 'src_dir', 'tmp_dir', 'syms_file', 'kconfig_file',
#                   'log_file']
if __name__ == "__main__":
    # para_dict = {
    #     'kernel_ver': '2.6.18',
    #     'bit_opt': '32',
    #     'vermagic': '2.6.18-8.el5 SMP mod_unload 686 REGPARM 4KSTACKS gcc-4.1',
    #     'src_dir': '/mnt/sdb1/pjt/test/link-example/2.6.18-32',
    #     'tmp_dir': '/mnt/sdb1/pjt/test/link-example/2.6.18-32/tmp',
    #     'syms_file': '/mnt/sdb1/pjt/test/link-example/2.6.18-32/KModule.symvers',
    #     'kconfig_file': '/mnt/sdb1/pjt/test/link-example/2.6.18-32/config-2.6.18-8.el5'
    # }
    # para_dict = {
    #     'kernel_ver': '2.6.32',
    #     'bit_opt': '32',
    #     'vermagic': '2.6.32-71.el6.i686 SMP mod_unload modversions 686 ',
    #     'src_dir': '/mnt/sdb1/pjt/test/link-example/2.6.32-32',
    #     'tmp_dir': '/mnt/sdb1/pjt/test/link-example/2.6.32-32/tmp',
    #     'syms_file': '/mnt/sdb1/pjt/test/link-example/2.6.32-32/KModule.symvers',
    #     'kconfig_file': '/mnt/sdb1/pjt/test/link-example/2.6.32-32/config-2.6.32-71.el6.i686'
    # }
    _para_dict = {
        'kernel_ver': '3.10.0',
        'bit_opt': '64',
        'vermagic': '3.10.0-327.el7.x86_64 SMP mod_unload modversions ',
        'src_dir': '/mnt/sdb1/pjt/test/link-example/3.10.0-64',
        'tmp_dir': '/mnt/sdb1/pjt/test/link-example/3.10.0-64/tmp',
        'syms_file': '/mnt/sdb1/pjt/test/link-example/3.10.0-64/KModule.symvers',
        'kconfig_file': '/mnt/sdb1/pjt/test/link-example/3.10.0-64/config-3.10.0-327.el7.x86_64'
    }
    # para_dict = {
    #     'kernel_ver': '3.10.0',
    #     'bit_opt': '64',
    #     'vermagic': '3.10.0-327.el7.x86_64 SMP mod_unload modversions ',
    #     'src_dir': '/mnt/sdb1/pjt/aio/disksbd_linux',
    #     'tmp_dir': '/mnt/sdb1/pjt/aio/disksbd_linux/tmp',
    #     'syms_file': '/mnt/sdb1/pjt/aio/disksbd_linux/KModule.symvers',
    #     'kconfig_file': '/mnt/sdb1/pjt/aio/disksbd_linux/tt-config',
    #     'log_file': 'tt.log'
    # }
    modlink(_para_dict)
