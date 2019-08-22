import os
import argparse
import sys
import subprocess
import operator

bytes_offset_f = operator.itemgetter(1)
sectors_f = operator.itemgetter(2)
is_alter_f = operator.itemgetter(5)


def get_cml():
    arg = argparse.ArgumentParser(description='get pocw file alter')
    arg.add_argument('-file', help='file path')
    return arg.parse_args()


def exe_cmd(cmd):
    with subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True) \
            as p:
        stdout, stderr = p.communicate()
    return p.returncode, stdout, stderr


class GetQcowFileAlterInfo():
    @staticmethod
    def _get_line_info(line):
        """
        input:['[', '0]', '800640/', '148897792', 'sectors', 'not', 'allocated', 'at', 'offset', '0', 'bytes', '(0)']
        output:0 409927680 False
        """
        items = line.split()
        bytes_offset = int(bytes_offset_f(items).rstrip(']'))
        _bytes = int(sectors_f(items).rstrip('/')) * 512
        is_alter = is_alter_f(items) == 'allocated'
        return bytes_offset, _bytes, is_alter

    @staticmethod
    def _get_alter_list(file_path):
        cmd = r'qemu-io -c map {}'.format(file_path)
        info = exe_cmd(cmd)
        if info[0] != 0:
            raise Exception(info[2])
        lines = info[1].splitlines()
        rs = list()
        interrupted = True
        for line in lines:
            offset, _bytes, is_alter = GetQcowFileAlterInfo._get_line_info(line)
            if is_alter:
                if interrupted:
                    rs.append([offset, _bytes])
                    interrupted = False
                else:
                    rs[-1][1] += _bytes
            else:
                interrupted = True
        return rs

    @staticmethod
    def get(file_path):
        """
        :param file_path:
        :return: 磁盘偏移list [[bytes_offset, bytes], [bytes_offset, bytes]]
        """
        if not os.path.isfile(file_path):
            raise Exception('file not exists')
        return GetQcowFileAlterInfo._get_alter_list(file_path)


if __name__ == '__main__':
    cml_arg = get_cml()
    file = cml_arg.file

    sys.exit(GetQcowFileAlterInfo.get(file))
