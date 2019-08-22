# coding:utf-8
import os
import platform
import crutil


class ChkFile:
    def __init__(self, conf_fn):
        self.__conf_fn = conf_fn

    def file_ln(self, chk_str):
        conf_fn = self.__conf_fn
        cmd = 'file {arg1}'.format(arg1=conf_fn)
        tmp_res, out_str = crutil.wrap_getstatusoutput(cmd)
        if tmp_res != 0:
            return False, out_str
        if out_str.find(chk_str) != -1:
            return True, 'ok'

        if out_str.find('symbolic link') == -1:
            return False, 'dismatched'

        ln = os.readlink(conf_fn)
        fn = os.path.isabs(ln) and ln or os.path.join(os.path.dirname(conf_fn), ln)
        cmd = 'file {arg1}'.format(arg1=fn)
        tmp_res, out_str = crutil.wrap_getstatusoutput(cmd)
        if tmp_res != 0:
            return False, out_str
        if out_str.find(chk_str) != -1:
            return True, 'ok'

        return False, 'dismatched'

    def file(self, chk_str):
        """
        linux shell: file filename, check output str
        :param chk_str:
        :return: bool
        """
        cmd = 'file {arg1}'.format(arg1=self.__conf_fn)
        tmp_res, out_str = crutil.wrap_getstatusoutput(cmd)
        if platform.system() == 'Windows':
            ls = chk_str.split(' ')
            for cs in ls:
                if out_str.find(cs) == -1:
                    return False
            return True
        else:
            if out_str.find(chk_str) != -1:
                return True
            else:
                return False

    def grep(self, chk_str):
        """
        linux shell: cat filename grep -c chk_str
        :param chk_str:
        :return:
        """
        cmd = 'cat {fn} | grep -c "{cs}"'.format(fn=self.__conf_fn, cs=chk_str)
        tmp_res, out_str = crutil.wrap_getstatusoutput(cmd)
        if tmp_res != 0:    # if not found or other error, the status is not 0
            return 0
        return int(out_str)


if __name__ == "__main__":
    sf = ChkFile('/tmp/initramfs-op/extr/3e0b1f835e6c424e9a5534746a99a03d/img/init')
    sf.file('source_all')

