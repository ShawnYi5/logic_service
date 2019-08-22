# coding:utf-8
import os
import re
import sys


class ChConf:

    def __init__(self, conf_fn):
        self.__conf_fn = conf_fn
        self.__cur_lines = list()

    def __enter__(self):
        """
        open and read conf file lines to buffer
        :return:
        """
        # open file and read the lines to __cur_lines
        conf_fn = self.__conf_fn
        if os.path.exists(conf_fn):
            # open for read('t'-def), if not exist, treat user will create a new
            with open(conf_fn, 'r') as fp:
                self.__cur_lines = fp.readlines()
        else:
            self.__cur_lines = list()
        return self

    def find_pstr(self, cstr):
        fnd_times = 0
        for line in self.__cur_lines:
            if line.find(cstr) != -1:
                fnd_times += 1
        return fnd_times

    def add_lines_all(self, add_lines, cstr, mthd):
        """
        add lines to conf file where found pstr after or before
        if pstr is '' then add head or tail which determine by mthd
        :param add_lines: lines list to add
        :param cstr: find the pstr line and then add
        :param mthd: add before - 'b', after - 'a'
        :return: int - add times, -n(<0) - failed
        """
        if mthd != 'a' and mthd != 'b':
            return -1

        tmp_lines = list()
        add_times = 0
        if len(cstr) == 0:
            if mthd == 'b':
                tmp_lines.extend(add_lines)
                tmp_lines.append(self.__cur_lines)
            else:
                tmp_lines.append(self.__cur_lines)
                tmp_lines.extend(add_lines)
            add_times += 1
        else:
            for line in self.__cur_lines:
                if len(cstr) > 0 and -1 != line.find(cstr):
                    if mthd == 'b':
                        tmp_lines.extend(add_lines)
                        tmp_lines.append(line)
                    else:
                        tmp_lines.append(line)
                        tmp_lines.extend(add_lines)
                    add_times += 1
                else:
                    tmp_lines.append(line)

        if add_times == 0:
            tmp_lines.extend(add_lines)
            add_times += 1

        # use [:] but not use l2 = l1--> we can't use list.clear()
        self.__cur_lines = tmp_lines[:]
        return add_times

    def add_lines_oseq(self, add_lines, cstr, mthd, occ_seq):
        """
        add lines to conf file where found pstr after or before
        if pstr is '' then return -1
        if find(pstr) == -1(not found): return 0
        :param add_lines: lines list to add
        :param cstr: find the pstr line and then add
        :param mthd: add before - 'b', after - 'a'
        :param occ_seq: add in the position that pstr occurs sequence
        :return: int - add times, -n(<0) - failed
        """
        if mthd != 'a' and mthd != 'b':
            return -1

        if len(cstr) == 0:
            return -1

        add_times = 0
        occ_times = 0
        tmp_lines = list()
        for line in self.__cur_lines:
            if len(cstr) > 0 and line.find(cstr) != -1:
                occ_times += 1
                if occ_times == occ_seq:
                    if mthd == 'b':
                        tmp_lines.extend(add_lines)
                        tmp_lines.append(line)
                    else:
                        tmp_lines.append(line)
                        tmp_lines.extend(add_lines)
                    add_times += 1
                else:
                    tmp_lines.append(line)
            else:
                tmp_lines.append(line)

        # use [:] but not use l2 = l1--> we can't use list.clear()
        self.__cur_lines = tmp_lines[:]
        return add_times

    def add_lines_head(self, add_lines):
        tmp_lines = add_lines[:]
        tmp_lines.extend(self.__cur_lines)
        self.__cur_lines = tmp_lines[:]

    def add_lines_tail(self, add_lines):
        self.__cur_lines.extend(add_lines[:])

    @staticmethod
    def dump_lines(lines):
        for line in lines:
            print(line)

    def add_lines_atno(self, add_lines, lnno):
        tmp_lines = list()
        line_cnt_bef = len(self.__cur_lines)

        added = False
        for i in range(0, len(self.__cur_lines)):
            if i == lnno:
                tmp_lines.extend(add_lines)
                added = True
            tmp_lines.append(self.__cur_lines[i])
        if added is False:  # handle the line no. out of all
            tmp_lines.extend(add_lines)

        self.__cur_lines = tmp_lines[:]
        line_cnt_aft = len(self.__cur_lines)
        assert (line_cnt_bef + len(add_lines)) == line_cnt_aft

    def del_line(self, cstr, ln=1):
        """
        delete the lines where line in dlines from conf file
        can't use pstr as '' to del all
        :param cstr: find the pstr line and then delete
        :param ln: delete n lines begin the found line
        :return: int - del times, if not found return 0
        """
        del_times = 0
        if len(cstr) == 0:
            return del_times

        tmp = 0
        tmp_lines = list()
        for line in self.__cur_lines:
            if tmp > 0:
                tmp -= 1
                continue
            if line.find(cstr) != -1:
                tmp = ln - 1    # exclusive the current found line
                del_times += 1
            else:
                tmp_lines.append(line)

        self.__cur_lines = tmp_lines[:]
        return del_times

    def rep_line_re(self, rep_lines, restr):
        if len(rep_lines) == 0 or len(restr) == 0:
            return
        p = re.compile(restr)
        tmp_lines = list()
        for line in self.__cur_lines:
            mres = p.search(line)
            if mres:
                tmp_lines.extend(rep_lines)
            else:
                tmp_lines.append(line)

        self.__cur_lines = tmp_lines[:]

    def rep_line(self, rep_lines, cstr, ln=1):
        """
        delete the lines where line in dlines from conf file
        :param rep_lines: to replace
        :param cstr: find the pstr line and then delete
        :param ln: replace line_count(found_line(1) + ln - 1) = ln
        :return:int replace times
        """
        rep_times = 0
        if len(cstr) == 0:
            return rep_times

        tmp = 0
        tmp_lines = list()
        for line in self.__cur_lines:
            if tmp > 0:
                tmp -= 1
                if line.find(cstr) != -1:
                    tmp = ln - 1
                    rep_times += 1
                    tmp_lines.extend(rep_lines)
                else:
                    tmp_lines.append(line)
            else:
                tmp_lines.append(line)

        self.__cur_lines = tmp_lines[:]
        return rep_times

    def __exit__(self, exc_type, exc_value, trace_back):
        """
        1 write back and flush to disk
        2 close find the pstr line and then add
        :return:
        """
        conf_fn = self.__conf_fn
        wrt_lines = 0
        # open for write('t'-def), if exist truncate or create new not exist
        with open(conf_fn, 'w') as fp:
            for line in self.__cur_lines:
                fp.write(line)
                wrt_lines += 1

        self.__cur_lines = list()


if __name__ == "__main__":
    alines = ['echo "Loading crunhtest.ko module"\n', 'insmod /lib/crunchtest.ko\n']
    pstr = 'mkblkdevs'
    try:
        init_path = os.path.join('..', 'initramfs-op', 'chconf', 'init')
        with ChConf(init_path) as ch:
            ch.add_lines_oseq(alines, pstr, 'a', 1)
            ch.del_line(alines[0], 2)
    except IOError as ex:
        print(ex)

    sys.exit(0)
