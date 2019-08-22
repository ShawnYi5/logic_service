import os
import copy
import io
import sys
import xlogging
try:
    import elftools.elf.elffile
    import elftools.elf.sections
    import elftools.elf.descriptions
except ImportError:
    pass

import logging
import struct
import ext_vmlinux
import gzip
import types
from net_common import get_info_from_syscmd

_logger = xlogging.getLogger(__name__)


def print_section_info(filename, section, section_name):
    if section:
        _logger.info("drv3: filename:{}, section:{}, sh_addr:{:x}, sh_offset:{:x}, sh_size:{:x}, sh_entsize:{:x}".format(
                     filename, section.name, section['sh_addr'], section['sh_offset'],
                     section['sh_size'], section['sh_entsize']))
    else:
        _logger.error("drv3: filename:{}, 没有section:{}".format(filename, section_name))


class ElfReadCrcTable(object):
    def __init__(self, vm_filename, module_sym_file):
        self.__crc_table = dict()

        if module_sym_file is not None:
            if not os.path.isfile(module_sym_file):
                xlogging.raise_system_error('drv3: file({}) not exist'.format(module_sym_file),
                                            r'drv3: 文件({})不存在'.format(module_sym_file), 10, _logger)
                return
            else:
                self.load_crc32_from_symvers(module_sym_file)
                return

        if vm_filename is not None:
            if not os.path.isfile(vm_filename):
                xlogging.raise_system_error('drv3: file({}) not exist'.format(vm_filename),
                                            'drv3: 文件({})不存在'.format(vm_filename), 9, _logger)
                return
            else:
                self.load_crc_from_elf(vm_filename)
                return

        xlogging.raise_system_error('drv3: no vm_filename module_sym_file', '没有vmlinux或module_sym_file', 101, _logger)
        return

    def load_crc_from_elf(self, elf_filename):
        # 检查文件是不是存在？
        if not os.path.isfile(elf_filename):
            xlogging.raise_system_error('drv3: file({}) not exist'.format(elf_filename),
                                        'drv3: 文件({})不存在'.format(elf_filename), 6,
                                        _logger)

        # elf文件存在。
        try:
            src_bin = ext_vmlinux.get_ext_vmlinux(elf_filename)

            src_elffile = elftools.elf.elffile.ELFFile(src_bin)

            bytes_per_word = src_elffile.elfclass//8

            _ksymtab_section = src_elffile.get_section_by_name(r'__ksymtab')
            _ksymtab_gpl_section = src_elffile.get_section_by_name(r'__ksymtab_gpl')
            _ksymtab_strings_section = src_elffile.get_section_by_name(r'__ksymtab_strings')
            _kcrctab_section = src_elffile.get_section_by_name(r'__kcrctab')
            _kcrctab_gpl_section = src_elffile.get_section_by_name(r'__kcrctab_gpl')

            print_section_info(elf_filename, _ksymtab_section, '_ksymtab_section')
            print_section_info(elf_filename, _ksymtab_gpl_section, '_ksymtab_gpl_section')
            print_section_info(elf_filename, _ksymtab_strings_section, '_ksymtab_strings_section')
            print_section_info(elf_filename, _kcrctab_section, '_kcrctab_section')
            print_section_info(elf_filename, _kcrctab_gpl_section, '_kcrctab_gpl_section')

            if _kcrctab_section:
                # 有的vmlinux 没有开启动crc功能。
                if _kcrctab_section is None or _ksymtab_section is None or _ksymtab_strings_section is None:
                    raise Exception("drv3: 文件({})缺少: __ksymtab或__kcrctab或_ksymtab_strings_section".format(
                        elf_filename))
                self.add_to_crc_table(bytes_per_word, _kcrctab_section, _ksymtab_section, _ksymtab_strings_section)

            if _kcrctab_gpl_section and _ksymtab_gpl_section:
                self.add_to_crc_table(bytes_per_word, _kcrctab_gpl_section, _ksymtab_gpl_section, _ksymtab_strings_section)

        except Exception as e:
            xlogging.raise_system_error('drv3: check elf file({}) failed:{}'.format(elf_filename, e),
                                        '文件({})不存在:{}'.format(elf_filename, e), 9, _logger)

    def add_to_crc_table(self, bytes_per_word, _kcrctab_section, _ksymtab_section, _ksymtab_strings_section):
        _count = len(_kcrctab_section.data())//bytes_per_word
        _ksymtab_strings_start = _ksymtab_strings_section['sh_addr']
        _ksymtab_strings_end = _ksymtab_strings_start + _ksymtab_strings_section['sh_size']
        _ksymtab_strings_data = _ksymtab_strings_section.data()
        for _i in range(_count):
            _post = _i * bytes_per_word
            _crc32_bs = _kcrctab_section.data()[_post:_post+4]
            _post = _i * bytes_per_word * 2
            _name_post_bs = _ksymtab_section.data()[_post + bytes_per_word:_post + 2*bytes_per_word]
            if bytes_per_word == 4:
                _name_post = struct.unpack('<I', _name_post_bs)[0]
            else:
                _name_post = struct.unpack('<Q', _name_post_bs)[0]

            if _ksymtab_strings_start <= _name_post and _name_post <= _ksymtab_strings_end:
                _name_post = _name_post - _ksymtab_strings_start
                _fun_bs = _ksymtab_strings_data[_name_post:_name_post+65]
                _fun_str = _fun_bs.decode().split('\x00')[0]
                # print("{}:0x{:08x}".format(_fun_str, struct.unpack('<I', _crc32_bs)[0]))
                self._insert_crc32_by_name(_fun_str, _crc32_bs)
            else:
                _logger.error("drv3: 内部错误，error crc:0x{:08x}, post:{}".format(
                    struct.unpack('<I', _crc32_bs)[0], _name_post))

    def get_name_and_crc32_for_one_line(self, _line):
        # 0xe1bc05c5      kvm_get_cs_db_l_bits    arch/x86/kvm/kvm        EXPORT_SYMBOL_GPL
        # EXPORT_SYMBOL_GPL vmlinux 0xfe078190    digsig_verify
        # 要匹配一下。
        # 匹配方法：删除EXPORT开头的：
        _all_word = _line.split()

        _find_out = None
        for _ in _all_word:
            if 'vml' in _:
                _find_out = _
                break
        if not _find_out:
            return None, None
        _all_word.remove(_find_out)

        _find_out = None
        for _ in _all_word:
            if 'EXPORT_' in _:
                _find_out = _
                break
        if _find_out:
            _all_word.remove(_find_out)

        _crc32 = None
        for _ in _all_word:
            if '0x' == _[0:2] or '0X' == _[0:2]:
                _crc32 = _
                break
        if _crc32:
            _all_word.remove(_crc32)

        if 1 != len(_all_word):
            return None, None

        _fun_name = _all_word[0]

        return _fun_name, _crc32

    def load_all_sym_to_list(self, f):
        for _line in f.readlines():
            if isinstance(_line, bytes):
                _line = _line.decode()

            _fun_str, _crc32_str = self.get_name_and_crc32_for_one_line(_line)
            if _fun_str is None or _crc32_str is None:
                continue

            _crc32_v = int(_crc32_str, 16)
            _crc32_bs = struct.pack('<I', _crc32_v)
            self._insert_crc32_by_name(_fun_str, _crc32_bs)

    def is_gz_file(self, filename):
        try:
            with open(filename, "rb") as f:
                _file_head = f.read(3)
                if _file_head == B'\037\213\010':
                    return True
        except:
            pass
        return False

    def load_crc32_from_symvers(self, symvers_filename):

        if self.is_gz_file(symvers_filename):
            with gzip.open(symvers_filename, "r") as f:
                self.load_all_sym_to_list(f)
        else:
            with open(symvers_filename, "r") as f:
                self.load_all_sym_to_list(f)
        return

    def get_crc32_from_name(self, fun_name):
        if fun_name in self.__crc_table:
            return self.__crc_table[fun_name]
        else:
            return None

    def _insert_crc32_by_name(self, fun_name, crc32_bs):
        print("{}:0x{:08x}".format(fun_name, struct.unpack('<I', crc32_bs)[0]))
        self.__crc_table[fun_name] = crc32_bs
        return


if __name__ == '__main__':

    # 获取命令行参数
    _logger.addHandler(logging.StreamHandler(sys.stdout))

    # elf_read_crc = ElfReadCrcTable(r'/mnt/vm3')
    # elf_read_crc = ElfReadCrcTable(r'/mnt/vmlinux')
    elf_read_crc = ElfReadCrcTable(None, r"/mnt/Module.symvers.3.10.0-514")

    print("__kmalloc:{}".format(elf_read_crc.get_crc32_from_name("__kmalloc")))
    print("test:{}".format(elf_read_crc.get_crc32_from_name("test")))

    print("end")
