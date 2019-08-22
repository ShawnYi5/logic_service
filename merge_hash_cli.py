import sys
import argparse

sys.path.append('/sbib/aio/logic_service')
import merge_hash_core


def get_cmd_args():
    args_parser = argparse.ArgumentParser(
        description="python merge_hash_cli.py --size size --new_path path --mer_paths paths")
    args_parser.add_argument("--size", help="bitmap size")
    args_parser.add_argument("--new_path", help="New address to save")
    args_parser.add_argument("--mer_paths", help="will go merged dirs who splited by ',' of str ")
    cmd_args = args_parser.parse_args()
    return cmd_args


if __name__ == '__main__':
    args = get_cmd_args()
    set_bitmap_size = int(args.size)
    file_save_path = args.new_path
    filepath = args.mer_paths.split(',')
    testy = merge_hash_core.MergeHash(set_bitmap_size)
    testy.merge(file_save_path, filepath)
