import json
import os, sys
import subprocess
import shutil
import argparse

sys.path.append('..')
from modget2 import mod_dep_get, convert_dep_file_dict, get_alise_modinfo, base_sort, dep_dic_form_modinfo

BASE_PATH = os.path.dirname(os.path.abspath('__file__'))
TAR_SOURCE_DATA = os.path.join(BASE_PATH, 'test_modget_data')
PATH = os.path.join(BASE_PATH, 'hardwareinfo')  # 这个path是将压缩包解压后的文件存放的路径


# obtain_json获取测试用例的json文件
def obtain_json(path_json):
    for file_name in os.listdir(path_json):
        if 'json' in file_name:
            yield file_name


# obtain_json获取测试用例的json文件
def obtain_tar(path_json):
    tar_list = []  # 存tar包
    for file_name in os.listdir(path_json):
        if 'json' not in file_name:
            tar_list.append(file_name)
    return tar_list


def test_api(path1, found_list):
    if len(found_list) == 0:
        return 1
    temp_str = ''
    dep_dic = convert_dep_file_dict(path1)
    for d in dep_dic:
        temp_str = d.split('kernel')[0]
        break
    for i in found_list:
        i = [temp_str + s for s in i]
        for index, k in enumerate(i):
            temp = i[index:]
            index += 1
            if 'updates' in temp[0]:
                dep_dic[temp[0]] = None
            if temp is not None:
                bob = [v for v in temp if v in dep_dic[temp[0]]]
            else:
                break
            if len(bob) != 0:
                return -1
                break
    return 1


# 测试每条测试用例
def test_case(tar_name, load_dict, path, select_dir):
    for device_id in load_dict:
        # print(device_id["device"], path)
        returned, found, not_found = mod_dep_get(path, device_id["device"], select_dir)
        successful_or_fail = test_api(path, found)
        if successful_or_fail == 1:
            assert returned == 0, '{} != 0'.format(returned)
            assert len(device_id["found"]) == len(found), '{} != {}'.format(device_id["found"], found)
            assert len(device_id["notfound"]) == len(not_found), '{} != {}'.format(device_id["notfound"], not_found)
        else:
            print("fail")


# 对获取的测试用例的json文件进行jia
def test_json(path, TAR_SOURCE_DATA, select_dir, test_type):
    tar_list = obtain_tar(TAR_SOURCE_DATA)
    for name in obtain_json(TAR_SOURCE_DATA):
        split_name = name.split('.json')
        tar_name = split_name[0] + '.tar.gz'
        if tar_name in tar_list:
            extend_str = 'tar -zxf ' + TAR_SOURCE_DATA + '/' + tar_name + ' -C ' + path
            os.makedirs(path, exist_ok=True)
            subprocess.call(extend_str, shell=True)
            print(tar_name)
            try:
                if test_type == 'ordinary_test':
                    with open(os.path.join(TAR_SOURCE_DATA, name), 'r') as load_f:
                        load_dict = json.load(load_f)
                    test_case(tar_name, load_dict, path, select_dir)
                else:
                    temp = convert_dep_file_dict(PATH)
                    bedep = []
                    for i in temp:
                        bedep.append(i.split('/')[-1])
                    j = 0
                    for i in bedep:
                        j += 1
                        try:
                            print(j, base_sort(get_alise_modinfo(PATH, i)))
                        except Exception as e:
                            print(i, e)
                        dep_dic_form_modinfo.clear()
            finally:
                shutil.rmtree(path, ignore_errors=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default=PATH, help="path for test source")
    parser.add_argument("--data", default=TAR_SOURCE_DATA, help="path for test data")
    parser.add_argument("--select_dir", default='updates', help="select_dir")
    parser.add_argument("--test_type", default='ordinary_test', help="test type")
    args = parser.parse_args()
    test_json(args.source, args.data, args.select_dir, args.test_type)
