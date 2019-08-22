import argparse
import os
import queue
import threading
import time

MAX_WORK = 10


# 获取命令行参数
def get_cmd_args():
    args_parser = argparse.ArgumentParser(
        description="python /sbin/aio/logic_service/enum_dirs.py -root path --ex_dir dir1 --ex_dir dir2".format())
    args_parser.add_argument("-root", help="root path")
    args_parser.add_argument("--ex_dir", help="exclude dir", action='append')
    cmd_args = args_parser.parse_args()
    return cmd_args


class EnumDir(object):
    islink, join, isdir = os.path.islink, os.path.join, os.path.isdir

    def __init__(self, root_path, ex_dirs):
        self.root_path = root_path
        self.ex_dirs = ex_dirs if ex_dirs else list()
        self.dir_list = queue.Queue()
        self.size = list()
        self.all_path = list()

    def work(self):
        self.enum_dirs(self.root_path)
        work_list = list()
        for i in range(MAX_WORK):
            th = threading.Thread(target=self.th_work)
            work_list.append(th)

        for worker in work_list:
            worker.start()
        for worker in work_list:
            worker.join()

    def th_work(self):
        while True:
            try:
                path = self.dir_list.get(timeout=2)
            except queue.Empty:
                break
            self.enum_dirs(path)
            self.dir_list.task_done()

    def enum_dirs(self, dir_path):
        if self.check_valid(dir_path):
            or_files = os.listdir(dir_path)
            dirs = list()
            ok_count = 0
            for file in or_files:
                file_path = EnumDir.join(dir_path, file)
                if self.check_valid(file_path):
                    ok_count += 1
                    dirs.append(file_path)
                if ok_count > 1024:
                    return None
            for _dir in dirs:
                self.dir_list.put(_dir)

    def check_valid(self, path):
        return os.path.isdir(path) and not EnumDir.islink(path) and path not in self.ex_dirs


if __name__ == '__main__':
    args = get_cmd_args()
    root_path, ex_dirs = args.root, args.ex_dir
    st = time.time()
    EnumDir(root_path, ex_dirs).work()
    print('cost:{:.3f}s'.format(time.time() - st))
