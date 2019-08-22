import argparse
import os
import sys
from concurrent.futures import ProcessPoolExecutor


def sort_and_dump(filename):
    sorted_path = '{}.sorted'.format(filename)
    with open(filename) as f:
        lines = [line.split(',', 1) for line in f]
    lines.sort(key=lambda x: int(x[0]))
    with open(sorted_path, 'w') as f:
        f.write(''.join(line[1] for line in lines))
    return 0


# 获取命令行参数
def get_cmd_args():
    args_parser = argparse.ArgumentParser(
        description="python merge_hash_helper.py source_dir")
    args_parser.add_argument("source_dir", help="source dir")
    cmd_args = args_parser.parse_args()
    return cmd_args


def work(source_dir):
    try:
        files = [os.path.join(source_dir, filename) for filename in os.listdir(source_dir)]
        with ProcessPoolExecutor(max_workers=4) as executor:
            """
            需要进行迭代结果，否则内部异常不会自动抛出，同时异常退出进程会卡死主逻辑
            """
            result = list(executor.map(sort_and_dump, files))
        return 0
    except Exception as e:
        return 'error:{}'.format(e)


if __name__ == '__main__':
    args = get_cmd_args()
    sys.exit(work(args.source_dir))
