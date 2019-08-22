import json
import logging
import os
import threading
import time
import copy
import io
import sys

try:
    import elftools.elf.elffile
    import elftools.elf.sections
    import elftools.elf.descriptions
except ImportError:
    pass

import argparse
import xlogging
import elf_read_crctab

_CLERWARE_sym_name_list = ['sbd_iofwrapper_init']

_logger = xlogging.getLogger(__name__)


def get_file_BytesIO(file_name):
    with open(file_name, 'rb') as f:
        return io.BytesIO(f.read())


def get_bytes_from_section(file_io, section):
    # file_io = io.BytesIO()
    section_offset = section['sh_offset']
    section_size = section['sh_size']
    file_io.seek(section_offset, io.SEEK_SET)
    return file_io.read(section_size)


def do_write_target(target_bin, offset, io_bytes):
    file_io = target_bin
    # file_io = io.BytesIO(b"abcdef")
    file_io.seek(offset, io.SEEK_SET)
    file_io.write(io_bytes)
    return


'''
def get_modinfo(file_io, modinfo_section, tag):
    # 这个版本不能准确知道位置。
    modinfo_bs = get_bytes_from_section(file_io, modinfo_section)

    modinfo_list = modinfo_bs.split(b'\x00')
    for tag_info in modinfo_list:
        _logger.info(tag_info)
        if tag_info is None or 0 == len(tag_info):
            continue
        tag_name, tag_string = tag_info.decode().split('=')
        if tag_name == tag:
            return tag_string
    return None
'''
'''
for (p = (char *)infosec->sh_addr; p; p = next_string(p, &size)) {
    if (strncmp(p, tag, taglen) == 0 && p[taglen] == '=')
        return p + taglen + 1;
}
'''


def goto_first_zero(bs, post):
    while post < len(bs):
        if bs[post:post+1] == b'\x00':
            return post
        post = post + 1
    return post


def goto_first_nonzero(bs, post):
    while post < len(bs):
        if bs[post:post+1] != b'\x00':
            return post
        post = post + 1
    return post


class ElfModInfo(object):
    def __init__(self, file_name, file_io, section):
        self.__file_name = file_name
        self.__file_io = file_io
        self.__section_offset = section['sh_offset']
        self.__modinfo_bs = get_bytes_from_section(file_io, section)

    def get_mode_info(self, _tag):
        _tag_len = len(_tag)
        i = 0
        _len_of_bs = len(self.__modinfo_bs)
        while i < _len_of_bs:
            i = goto_first_nonzero(self.__modinfo_bs, i)
            if i+_tag_len >= _len_of_bs:
                break
            # 直到不为0的字符串。
            find_out_tag = self.__modinfo_bs[i:i+_tag_len]
            if find_out_tag == _tag:
                # find out.
                i = i + _tag_len
                _ver_magic_start = i
                _ver_magic_end = goto_first_zero(self.__modinfo_bs, i)
                return self.__modinfo_bs[_ver_magic_start:_ver_magic_end], \
                       self.__section_offset + _ver_magic_start, _ver_magic_end - _ver_magic_start

            # skip.
            i = goto_first_zero(self.__modinfo_bs, i)
        xlogging.raise_system_error('drv3: can not found vermagic:{}'.format(self.__file_name),
                                    'drv3: 不能找到vermagic', 4, _logger)


def print_section_info(filename, section):
    _logger.info("drv3: filename:{}, section:{}, sh_addr:{:x}, sh_offset:{:x}, sh_size:{:x}, sh_entsize:{:x}".format(
                 filename, section.name, section['sh_addr'], section['sh_offset'],
                 section['sh_size'], section['sh_entsize']))


'''
#define MAX_PARAM_PREFIX_LEN (64 - sizeof(unsigned long))
struct modversion_info
{
	unsigned long crc;
	char name[MODULE_NAME_LEN];
};
'''

class ElfVersion(object):
    def __init__(self, file_io, section, elfclass):
        self.__all_version = list()
        self.__file_io = file_io
        self.__section_offset = section['sh_offset']
        self.__section_bytes = get_bytes_from_section(file_io, section)
        for _post in range(0, len(self.__section_bytes), 64):
            _one_line = self.__section_bytes[_post:_post+64]
            _crc32 = _one_line[0:4]
            _sym_name = 32
            if elfclass == 32:
                _sym_name = _one_line[4:64]
            elif elfclass == 64:
                _sym_name = _one_line[8:64]
            else:
                pass

            self.__all_version.append([_crc32, _sym_name, _post + self.__section_offset])

    def get_crc32(self, sym_name):
        for _version in self.__all_version:
            if _version[1] == sym_name:
                return _version[0]
        return None

    def get_version(self):
        return self.__all_version


class OneElfInfo(object):
    def __init__(self, file_name):
        self.file_name = file_name
        if not os.path.isfile(self.file_name):
            xlogging.raise_system_error('drv3: file({}) not exist'.format(self.file_name),
                                        '文件不存在'.format(self.file_name), 6,
                                        _logger)
        self.file_bin = get_file_BytesIO(self.file_name)
        self.file_elf = elftools.elf.elffile.ELFFile(self.file_bin)

        _section = self.file_elf.get_section_by_name(r'.modinfo')
        print_section_info(self.file_name, _section)
        self.mod_info = ElfModInfo(self.file_name, self.file_bin, _section)

        _section = self.file_elf.get_section_by_name(r'__versions')
        print_section_info(self.file_name, _section)
        self.src_version = ElfVersion(self.file_bin, _section, self.file_elf.elfclass)


class ElfGroupInfo(object):
    def __init__(self, file_name_list):
        self.__all_inc = list()
        for _ in file_name_list:
            self.__all_inc.append(OneElfInfo(_))

    def get_elfclass(self):
        if len(self.__all_inc) == 0:
            return 0
        first_elf = self.__all_inc[0]
        for _ in self.__all_inc:
            if _.file_elf.elfclass != first_elf.file_elf.elfclass:
                xlogging.raise_system_error('drv3: elfclass({}) != elfclass({})'.format(first_elf.file_name, _.file_name),
                                            '文件类型不一样', 7, _logger)

        return first_elf.file_elf.elfclass

    def get_mode_info(self, _tag):
        if len(self.__all_inc) == 0:
            xlogging.raise_system_error('drv3: no inc.ko', '没有inc.ko文件', 8, _logger)
        return self.__all_inc[0].mod_info.get_mode_info(_tag)

    def get_crc32(self, sym_name):
        if len(self.__all_inc) == 0:
            xlogging.raise_system_error('drv3: no inc.ko', '没有inc.ko文件', 8, _logger)

        all_crc32 = list()
        for _ in self.__all_inc:
            _crc32 = _.src_version.get_crc32(sym_name)
            if _crc32 is None:
                continue
            all_crc32.append(_crc32)

        if len(all_crc32) == 0:
            return None

        _crc32 = all_crc32[0]
        for _ in all_crc32:
            if _crc32 != _:
                xlogging.raise_system_error('drv3: all inc.ko crc32 not eque', '在inc.ko中的crc32文件不相等', 8, _logger)

        return _crc32


'''    
vm_file,sym_file, 2选一，必须有一个, 
      vm_file是指解压后的vmlinux文件, 
      sym_file是编译环境中的Module.symvers(在Kernel-devel包中。)
inc_ko, vermagic, 2选一，必须有一个。
       inc_ko是目标机中对应板块中的任何一个ko文件。
       vermagic是目标机ko文件中的modinfo中的vermagic，
       注意，字符串后面有一个空格。
       注意，字符串后面有一个空格。
       注意，字符串后面有一个空格。
src_ko, 我们编译的，兼容的ko文件路径和名。
target_ko, 要生成的目标ko文件路径和名。
'''


class ElfRelink(object):
    def __init__(self, link_info):

        self.__vm_filename = None
        if 'vm_file' in link_info:
            self.__vm_filename = link_info['vm_file']

        self.__module_sym_file = None
        if 'sym_file' in link_info:
            self.__module_sym_file = link_info['sym_file']

        self.__inc_elf_filename = None
        if 'inc_ko' in link_info:
            self.__inc_elf_filename = link_info['inc_ko']

        self.__target_vermagic = None
        if 'vermagic' in link_info:
            self.__target_vermagic = link_info['vermagic']

        if self.__inc_elf_filename is None and self.__target_vermagic is None:
            xlogging.raise_system_error(r'drv3: no inc.ko or vermagic', '没有inc.ko或vermagic', 11, _logger)

        if self.__vm_filename is None and self.__module_sym_file is None:
            xlogging.raise_system_error(r'drv3: no vm_file or sym_file', '没有vmlinux或sym_file', 11, _logger)

        self.__crc32Table = elf_read_crctab.ElfReadCrcTable(self.__vm_filename, self.__module_sym_file)
        self.__inc_elf_filename_list = [self.__inc_elf_filename]
        self.__inc_ko = None
        self.init_vermagic()

    def check_src_and_include_elf(self, src_ko_file, src_elffile):
        # 1.检测 位数是否相同并且是否支持。。
        if self.__inc_ko is not None:
            _inc_elfclass = self.__inc_ko.get_elfclass()
            if self.__inc_ko.get_elfclass() != src_elffile.elfclass:
                xlogging.raise_system_error(r'drv3: elf class not EQUL(文件类型不相同)',
                                            'drv3: inc class:{}, src elf file:{},class{} '.format(_inc_elfclass,
                                                                                            src_ko_file,
                                                                                            src_elffile.
                                                                                            elfclass), 2, _logger)

        if src_elffile.elfclass == 32:
            _logger.info("drv3: elf32")
        elif src_elffile.elfclass == 64:
            _logger.info("drv3: elf64")
        else:
            xlogging.raise_system_error('drv3: unknow elf file!', '未知elf文件的class:{}'.format(src_elffile.elfclass), 1,
                                        _logger)
            return
        # 2.

    def do_work(self, src_ko_file, target_ko_file):

        # 检查文件是不是存在？
        if not os.path.isfile(src_ko_file):
            xlogging.raise_system_error('drv3: file({}) not exist'.format(src_ko_file),
                                        '文件不存在:{}'.format(src_ko_file), 6,
                                        _logger)
        src_bin = get_file_BytesIO(src_ko_file)
        target_bin = copy.copy(src_bin)

        src_elffile = elftools.elf.elffile.ELFFile(src_bin)

        self.check_src_and_include_elf(src_ko_file, src_elffile)

        _src_modinfo_section = src_elffile.get_section_by_name(r'.modinfo')
        _src_version_section = src_elffile.get_section_by_name(r'__versions')

        print_section_info(src_ko_file, _src_modinfo_section)

        src_mod_info = ElfModInfo(src_ko_file, src_bin, _src_modinfo_section)
        self.copy_ver_magic(target_bin, src_mod_info)

        if _src_version_section:
            src_version = ElfVersion(src_bin, _src_version_section, src_elffile.elfclass)
            self.copy_crc32(target_bin, src_version)

        # 产生新的文件
        self.do_create_target_and_flush(target_bin, target_ko_file)
        return

    def do_create_target_and_flush(self, target_bin, target_ko_file):
        with open(target_ko_file, 'wb') as f:
            target_bin.seek(0, io.SEEK_SET)
            return f.write(target_bin.read())

    def init_vermagic(self):
        self.__inc_ko = None
        if self.__target_vermagic is None:
            # 使用 inc.ko
            self.__inc_ko = ElfGroupInfo(self.__inc_elf_filename_list)

    def get_vermagic(self):
        if self.__target_vermagic is None:
            return self.__inc_ko.get_mode_info(b"vermagic=")
        else:
            b_vermagic = self.__target_vermagic.encode()
            return b_vermagic, 0, len(b_vermagic)

    def copy_ver_magic(self, target_bin, src_elf_mod_info):

        _inc_ver_magic, _inc_start, _inc_len = self.get_vermagic()
        _src_ver_magic, _src_start, _src_len = src_elf_mod_info.get_mode_info(b"vermagic=")
        if _src_len < _inc_len:
            # 空间不足，不能存下，异常！
            xlogging.raise_system_error('drv3: src.ko vermagic:{} < inc.ko vermagic:{}'.format(_src_len, _inc_len),
                                        '内部错误：源ko的vermagic空间太小:', 4, _logger)

        for i in range(_inc_len, _src_len):
            _inc_ver_magic += b'\x00'

        do_write_target(target_bin, _src_start, _inc_ver_magic)

        return

    def copy_crc32(self, target_bin, src_elf_version):
        _dst_version = src_elf_version.get_version()
        _no_sym_list = ''
        _copy_sym_list = ''
        _same_sym_list = ''
        _all_sym_name = 'all sym name:'
        for _version in _dst_version:
            _crc32_src = _version[0]
            _sym_name = _version[1].decode().strip('\x00')
            _offset_src = _version[2]
            _all_sym_name += _sym_name + "\n"

            if _sym_name in _CLERWARE_sym_name_list:
                continue

            _crc32 = self.__crc32Table.get_crc32_from_name(_sym_name)

            if _crc32 is None:
                _no_sym_list += 'no sym:{}\n'.format(_sym_name)
                continue

            # for debug _crc32 = b'\x00\x00\x00\x00'
            if _crc32 != _crc32_src:
                _copy_sym_list += \
                    "copy sym: {} crc32 {:08x} to {:08x}\n".format(_sym_name,
                                                                   int.from_bytes(_crc32_src, byteorder='little'),
                                                                   int.from_bytes(_crc32, byteorder='little'))
                do_write_target(target_bin, _offset_src, _crc32)
            else:
                _same_sym_list += "same sym: {} crc32 {:08x}\n".format(_sym_name,
                                                                       int.from_bytes(_crc32, byteorder='little'))
                pass

        if len(_no_sym_list) != 0:
            _logger.info(_all_sym_name)
            _logger.info(_same_sym_list)
            _logger.info(_copy_sym_list)
            _logger.error(_no_sym_list)
            _no_sym_list = _all_sym_name = _same_sym_list = _copy_sym_list = _version = _dst_version = None
            xlogging.raise_system_error('drv3: no sym in include.ko:{}\n'.format(_no_sym_list),
                                        'drv3: 不能找到sym信息', 3, _logger)
        return

if __name__ == '__main__':

    # 获取命令行参数
    def get_cmd_args():
        args_parser = argparse.ArgumentParser(
            description="python elf_relink.py -vm_file vmlinuz -sym_file Module.symvers -vermagic vermagic -inc inc.ko -src src.ko -new new.ko")
        args_parser.add_argument("-vm_file", metavar='vmlinuz', help="vmlinuz for linux kernel")
        args_parser.add_argument("-sym_file", metavar='Module.symvers', help="Module.symvers file")
        # args_parser.add_argument("-inc", metavar='inc.ko', required=True, action='append', help="xxx.ko from include linux kernel") 多个参数时
        args_parser.add_argument("-inc_ko", metavar='inc.ko', help="sg.ko from include linux kernel")
        args_parser.add_argument("-vermagic", metavar='inc.ko', help="vermagic from linux kernel")
        args_parser.add_argument("-src_ko", metavar='src.ko', required=True, help="src.ko for clerware build")
        args_parser.add_argument("-target_ko", metavar='new.ko', required=True, help="link to target new.ko.")
        cmd_args = args_parser.parse_args()
        return cmd_args

    _logger.addHandler(logging.StreamHandler(sys.stdout))

    args = get_cmd_args()
    _input = dict()
    _input['vm_file'] = args.vm_file
    _input['sym_file'] = args.sym_file
    _input['inc_ko'] = args.inc_ko
    _input['vermagic'] = args.vermagic

    _logger.info("drv3: start link input:{}".format(_input))

    elf_relink = ElfRelink(_input)
    elf_relink.do_work(args.src_ko, args.target_ko)
    print("ok")
