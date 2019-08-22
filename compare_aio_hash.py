import sys
from enum import Enum

try:
    from box_dashboard import xlogging
except ImportError:
    import logging as xlogging

# =========================================================================================
_logger = xlogging.getLogger(__name__)


class RetryReadEnum(Enum):
    all = 1,
    left = 2,
    right = 3


class ChangeType(Enum):
    file_del = 0,
    file_add = 1,
    hash_change = 2,
    unknow = 3


def fetch_callback(search_dir, relative_path, change_type, oldline, newline):
    try:
        print('fetch_callback search_dir = {},relative_path = {}'.format(search_dir, relative_path))
        if change_type == ChangeType.file_del:
            print('del oldline = {}'.format(oldline))
        elif change_type == ChangeType.file_add:
            print('add newline = {}'.format(newline))
        elif change_type == ChangeType.hash_change:
            print('hash_change oldline = {},newline = {}'.format(oldline, newline))
        else:
            print('unknow oldline = {},newline = {}'.format(oldline, newline))
        return True
    except Exception as e:
        _logger.error(r'fetch_callback failed : {}'.format(e), exc_info=True)
        return True


def fetch_changes(old_hash_file_path, new_hash_file_path, context, fetch_callback_func, split=r'|',
                  cmp_type=r'cmp_str'):
    try:
        # 文件读取结束标示。
        old_end = False
        new_end = False

        retry_read = RetryReadEnum.all
        # 重读标示。默认为
        with open(old_hash_file_path, encoding='utf-8') as old_handle:
            with open(new_hash_file_path, encoding='utf-8') as new_handle:
                while True:
                    if retry_read == RetryReadEnum.all or retry_read == RetryReadEnum.left:
                        if old_end is not True:
                            line_old = old_handle.readline().strip()
                            if not line_old:
                                old_end = True

                    if retry_read == RetryReadEnum.all or retry_read == RetryReadEnum.right:
                        if new_end is not True:
                            line_new = new_handle.readline().strip()
                            if not line_new:
                                new_end = True

                    if old_end and new_end:
                        break

                    retry_read = RetryReadEnum.all
                    ret = True
                    if old_end is not True:
                        if new_end is not True:
                            # 左有，右有
                            # 获取左右字符串list
                            old_list = line_old.split(split)
                            new_list = line_new.split(split)
                            if cmp_type == 'cmp_hex_str':
                                old_val, new_val = int(old_list[0], base=16), int(new_list[0], base=16)
                            elif cmp_type == 'cmp_str':
                                old_val, new_val = old_list[0], new_list[0]
                            else:
                                old_val, new_val = old_list[0], new_list[0]

                            # 比较路径
                            if old_val < new_val:
                                # 小，报告左面删除，设置左面重读。
                                ret = fetch_callback_func(context, old_list[0], ChangeType.file_del, line_old, None)
                                if ret is False:
                                    return
                                retry_read = RetryReadEnum.left
                            elif old_val == new_val:
                                # 相同。比较其他值。
                                if old_list[1] != new_list[1]:
                                    ret = fetch_callback_func(context, old_list[0], ChangeType.hash_change, line_old,
                                                              line_new)
                                elif (len(old_list) > 2) and (old_list[2] != new_list[2]):
                                    ret = fetch_callback_func(context, old_list[0], ChangeType.unknow, line_old,
                                                              line_new)
                                if ret is False:
                                    return
                            else:
                                # 大，报告右面增加，设置右面重读。
                                ret = fetch_callback_func(context, new_list[0], ChangeType.file_add, None, line_new)
                                if ret is False:
                                    return
                                retry_read = RetryReadEnum.right
                        else:
                            # 左有，右没有，报告左面删除。
                            old_list = line_old.split(split)
                            ret = fetch_callback_func(context, old_list[0], ChangeType.file_del, line_old, None)
                            if ret is False:
                                return
                            retry_read = RetryReadEnum.left
                    else:
                        # new_end 必须不为 True
                        # 左没有，右有。报告右面增加。
                        new_list = line_new.split(split)
                        ret = fetch_callback_func(context, new_list[0], ChangeType.file_add, None, line_new)
                        if ret is False:
                            return
                        retry_read = RetryReadEnum.right
    except Exception as e:
        _logger.error(r'fetch_changes failed {}'.format(e), exc_info=True)
        return True


if __name__ == "__main__":
    xlogging.basicConfig(stream=sys.stdout, level=xlogging.NOTSET)
    fetch_changes('aio_hash_out.txt', 'aio_hash_out (2).txt', '/home/wolf', fetch_callback)
    if 'baaaa' < 'aaaa':
        _logger.info('success')
    else:
        _logger.info('success_err')
