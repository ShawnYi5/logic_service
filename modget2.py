import modlink
import os
import xlogging
import traceback
from net_common import get_info_from_syscmd

mod_dep_all_find = dict()
_logger = xlogging.getLogger(__name__)
dep_dic_form_modinfo = dict()  # 这个字典是针对于我们要查找的xxxx文件的子依赖文件,包括xxxx本身的依赖
alias_split_list = ['alias pci:v', 'd', 'sv', 'sd', 'bc', 'sc', 'i', '* ']

'''
1.总体思路为首先将传入的pci_list中的元素转换为ko或者ko.xz
2.然后判断传入的.ko或者ko.xz文件相对于path有几个
3.如果只有一个或者有两个但是要updates后的依赖关系,则直接从modules.dep文件中读取
4.如果有两个相同的ko或者ko.xz时要旧的驱动时,则用modinfo命令查看旧的依赖关系
5.对于ko和ko.xz的判断是来自modules.dep文件
6.对于modules.dep文件中为绝对路径时的处理为先不考虑将绝对路径转为相对路径，而是先把所有父子依赖关系全部确定了之后
再将绝对路径处理为相对路径
'''


def convert_pci_str_2_pci_value_list(pci_str):
    """
    这个函数是用来拆分传入的pci_str串
    :param pci_str:
    :return: vlist
    :param pci_str:
    :return:
    """
    mlist = pci_str.split('&')
    clist = ['VEN', 'DEV', 'SUBSYS', 'REV', 'CLASS']
    vlist = list()
    i = 0
    for mlist_str in mlist:
        if i >= len(clist):
            _logger.error('pci pci_str {} invalid mlist_str {},pci list len {}'.format(pci_str, mlist_str, len(mlist)))
            return ''
        mmlist = mlist_str.split('_')
        if len(mmlist) != 2:
            _logger.error('pci mlist_str {} invalid mlist_str {}'.format(pci_str, mlist_str))
            return ''
        if mmlist[0] != clist[i]:
            _logger.error('pci mlist_str {} invalid mlist_str {}:{}'.format(pci_str, mlist_str, mmlist[0]))
            return ''
        vlist.append(mmlist[1])
        i += 1
    if len(vlist) != len(clist):
        _logger.error('pci mlist_str {} invalid,vlist {}'.format(pci_str, vlist))
        return ''
    _logger.debug('pci mlist_str {},get vlist {}'.format(pci_str, vlist))
    return vlist


def is_pci_value_valid(pci_list):
    """
     判断是不是有效的pci值
    :param pci_list:将pci_str拆分好的列表
    :return:
    """
    if len(pci_list) + 3 != len(alias_split_list):
        _logger.error('invalid pci_list {}, alias_split_list {}'.format(pci_list, alias_split_list))
        return False
    return True


def mod_file_get_from_pci(modpath, pci_str):
    """
    :param modpath: 这个modpath为kernel文件夹所在的绝对路径
    :param pci_str:为一个pci_str串
    :return:
    """
    vlist = convert_pci_str_2_pci_value_list(pci_str)
    if get_alise_from_alias(modpath, vlist) != '':
        return 0, get_alise_from_alias(modpath, vlist)
    else:
        return 1, pci_str


def is_pci_value_list_match(pci_list, text_line):
    """
    匹配输入的pci_str串
    :param pci_list: 将pci_str拆分好的列表
    :param text_line: 为modules.alias中的一行记录值
    :return: true or false匹配成功返回true否则返回flase
    """
    start_pos = 0
    glist = list()
    for i in range(len(alias_split_list) - 1):
        index1 = text_line[start_pos:].find(alias_split_list[i])
        if index1 < 0:
            break
        index2 = text_line[start_pos + index1:].find(alias_split_list[i + 1])
        if index2 < 0:
            break
        glist.append(text_line[start_pos + index1 + len(alias_split_list[i]):start_pos + index2])
        start_pos += index2  # glist存的是

    if len(glist) == len(pci_list) + 2:

        pci_list_tmp = [pci_list[0], pci_list[1], pci_list[2], pci_list[3],
                        pci_list[4][0] + pci_list[4][1],
                        pci_list[4][2] + pci_list[4][3],
                        pci_list[4][4] + pci_list[4][5]]
        # pci_list_tmp为['8086', '1C02', '1043844D', '05', '01', '06', '01']
        for i in range(6):
            mgstr = glist[i].lstrip('0')
            mpstr = pci_list_tmp[i].lstrip('0')
            if mgstr != '*' and mgstr != mpstr:
                return False

        if pci_list_tmp[4] != '01':
            mgstr = glist[6].lstrip('0')
            mpstr = pci_list_tmp[6].lstrip('0')
            if mgstr != '' and mgstr != mpstr:
                return False
        else:
            # base class为01(存储控制器)，不比较 interface
            pass

        return True
    else:
        return False


def get_alise_from_alias(modpath, pci_list):
    """
    从modules.alias文件中获取驱动的名字
    :param modpath:  这个modpath为kernel文件夹所在的绝对路径
    :param pci_list:
    :return: xxx.ko或者xxx.ko.xz
    """
    if not is_pci_value_valid(pci_list):
        return ''

    alias_file = os.path.join(modpath, 'modules.alias')
    if not os.path.isfile(alias_file):
        _logger.error('alias_file {} not exist'.format(alias_file))
        return ''
    ret = modlink.read_file(alias_file, 'r', False)

    if ret[0] != 0:
        _logger.error('alias_file {} read failed,err {}'.format(alias_file, ret))
        return ''

    mlist = ret[1].split('\n')
    for mlist_str in mlist:
        try:
            if is_pci_value_list_match(pci_list, mlist_str):
                strlist = mlist_str.strip(' ').split(' ')
                if len(strlist) < 3:
                    _logger.error('invalid mlist_str {}'.format(mlist_str))
                else:
                    _logger.debug('pci {} get mod success:{}'.format(pci_list, strlist[2]))
                    return strlist[2] + '.ko'
        except Exception as e:
            _logger.error('deal pci oneline {} except {} {}'.format(mlist_str, e, traceback.format_exc()))
    return ''


def find(ko_name, path, mod_dep_all):
    """
     递归查找find_mod相对与path的相对路径
     :param find_mod:
     :param path:
     :return: mod_dep_all_find
    """
    if ko_name in mod_dep_all:
        if mod_dep_all[ko_name] != ['']:
            mod_dep_all_find[ko_name] = mod_dep_all[ko_name]
            temp = mod_dep_all[ko_name]
            for key in temp:
                find(key, path, mod_dep_all)
        else:
            mod_dep_all_find[ko_name] = []
    return mod_dep_all_find


def base_sort(graph):
    in_degrees = dict((u, 0) for u in graph)  # 初始化所有顶点入度为0
    vertex_num = len(in_degrees)
    for u in graph:
        for v in graph[u]:
            in_degrees[v] += 1  # 计算每个顶点的入度
    Q = [u for u in in_degrees if in_degrees[u] == 0]  # 筛选入度为0的顶点
    Seq = []
    while Q:
        u = Q.pop()  # 默认从最后一个删除
        Seq.append(u)
        for v in graph[u]:
            in_degrees[v] -= 1  # 移除其所有指向
            if in_degrees[v] == 0:
                Q.append(v)  # 再次筛选入度为0的顶点
    if len(Seq) == vertex_num:  # 如果循环结束后存在非0入度的顶点说明图中有环，不存在拓扑排序
        return Seq[::-1]
    else:
        print("there's a circle.")


def search_mod_file_rel(path, file_mod):
    """
    查找file文件的相对路径
    :param path:这个path为kernel文件夹所在的绝对路径
    :param file_mod:
    :return: file_path_list返回file文件相对于path的相对路径列表，已经ko个数
    """
    file_path_list = list()
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            if '/' + file_mod in os.path.join(root, name):
                file_rel = os.path.relpath(os.path.join(root, name), path)
                file_path_list.append(file_rel)
    return len(file_path_list), file_path_list


def convert_dep_file_dict(path):
    """
    将dep文件中每个驱动文件对应的依赖存入字典，其中依赖作为将key,被依赖作为值
    :param path:这个path为kernel文件夹所在的绝对路径
    :return: mod_dep_all将以字典形式存的modules.dep返回
    """
    modules_dep_path = os.path.join(path, 'modules.dep')
    mod_dep_all = dict()  # 这个字典是存将.dep文件中所有的依赖关系存入字典
    ret = modlink.read_file(modules_dep_path, 'r', False)
    mlist = ret[1].split('\n')
    for i in mlist:
        temp = i.split(':')
        if len(temp) != 1:
            value = temp[1].strip().split(' ')
            mod_dep_all[temp[0]] = value
    return mod_dep_all


def depends_forms_modinfo(old_modfile, path0):
    modinfo_result = get_info_from_syscmd('cd ' + path0 + ';modinfo ' + old_modfile)
    modinfo_result_list = modinfo_result[1].replace(' ', '').split('\n')
    dep = []
    for filed in modinfo_result_list:
        temp = filed.split(':')
        if temp[0] == 'depends':
            dep = temp[1]
    return dep


def check_updates_ko(path0):
    """
    用来检查updates文件夹下有多少更新的驱动
    :param path0:
    :return:
    """
    update_path = os.path.join(path0, 'updates')
    update_ko = []
    for root, dirs, files in os.walk(update_path, topdown=False):
        ko = [i for i in files if '.ko' in i]
        update_ko = update_ko + ko
    return set(update_ko)


def sort_dep(dep_dic, modfile, path0):
    for i in dep_dic:
        if '/lib/modules/' in i:
            modfile = '/lib' + path0.split('lib')[-1] + '/' + modfile
            break
    son_and_father_modfile = list()
    son_and_father_modfile.append(modfile)
    for i in dep_dic:
        temp = [i]
        if modfile in dep_dic[i]:
            son_and_father_modfile = son_and_father_modfile + dep_dic[i] + temp

    son_and_father_modfile = set(son_and_father_modfile + dep_dic[modfile])
    son_and_father_modfile_dic = dict()
    for i in son_and_father_modfile:
        if i != '':
            if dep_dic[i] == ['']:
                son_and_father_modfile_dic[i] = []
            else:
                son_and_father_modfile_dic[i] = dep_dic[i]
    return len(son_and_father_modfile_dic), base_sort(son_and_father_modfile_dic)


def split_path(return_result):
    """
    用来处理dep文件中是绝对路径的情况
    :param return_result:
    :return:
    """
    kill_str = ''
    for i in return_result:
        if '/lib/modules/' in i:
            kill_str = '/lib' + path0.split('lib')[-1] + '/'
            break
    return kill_str


def son_and_father_modfile_form_dep(modfile, path0):
    """
    该函数是从modeps.dep文件中获取父子依赖关系
    :param modfile: 为一个相对路径
    :param path0:
    :return:
    """
    dep_dic = convert_dep_file_dict(path0)
    num, return_result = sort_dep(dep_dic, modfile, path0)
    kill_str = split_path(return_result)
    s = []
    if kill_str is not '':
        for index, j in enumerate(return_result):
            tmp = j.split(kill_str)[-1]
            s.append(tmp)
        return num, s
    return num, return_result


def son_and_father_modfile_form_dep_old(select_dir, modfile, path0, s):
    """
    该函数是从旧的驱动中获取父子依赖关系
    :param modfile: modfile为一个相对路径
    :param path0:
    :param s: 用来区分ko或者xz
    :return:
    """
    ko_update = list(check_updates_ko(path0))
    update_ko_path = dict()  # 用来存更新前后的相对路径,key为驱动名xxx.ko或者xxx.ko.xz
    old_depends = dict()
    for i in ko_update:
        num, result = search_mod_file_rel(path0, i)
        update_ko_path[i] = result
        temp = depends_forms_modinfo(result[1], path0)
        if temp == '':
            old_depends[result[1]] = []
        else:
            if len(temp) == 1:
                old_depends[result[1]] = search_mod_file_rel(path0, temp + s)[1][0]
            else:
                temp = temp.split(',')
                value_list = []
                for k in temp:
                    result1 = search_mod_file_rel(path0, k + s)[1]
                    if len(result) >= 2:
                        result1 = [i for i in result1 if select_dir in i]
                        value_list = value_list + result1
                    else:
                        value_list = result1 + value_list
                old_depends[result[1]] = value_list
    dep_dic = convert_dep_file_dict(path0)
    kill_str = split_path(dep_dic)
    for k in update_ko_path:
        dep_dic[kill_str + update_ko_path[k][1]] = dep_dic.pop(kill_str + update_ko_path[k][0])
    for m in dep_dic:
        if dep_dic[m] != ['']:
            if len(dep_dic[m]) == 1 and ('updates' in dep_dic[m][0]):
                for i in update_ko_path:
                    if i in dep_dic[m][0]:
                        del dep_dic[m][0]
                        dep_dic[m].append(update_ko_path[i][1])
            else:
                for index, s in enumerate(dep_dic[m]):
                    for i in update_ko_path:
                        if i in dep_dic[m][index]:
                            del dep_dic[m][index]
                            dep_dic[m].append(update_ko_path[i][1])
    modfile = update_ko_path[modfile][1]
    num, return_result = sort_dep(dep_dic, modfile, path0)
    if kill_str is not '':
        s = []
        for index, j in enumerate(return_result):
            tmp = j.split(kill_str)[-1]
            s.append(tmp)
        return num, s
    return num, return_result


def mod_dep_get(path, find_mod_list, select_dir='updates'):
    """
    对传入的pci_str_list一一获取依赖的ko关系
    :param path:这个path为kernel文件夹所在的绝对路径
    :param find_mod_list:包括xxx.ko和pci_str串的列表
    :param select_dir:如果有两个.ko文件指定使用updates中的还是kernel中的，默认使用updates中的
    :return:
    """
    ok_list = list()
    no_find_list = list()
    if os.path.exists(path):
        check_ko_xz = ''
        pci_ko_name = []
        for i in find_mod_list:
            if '.ko' not in i:
                ks, ko_name = mod_file_get_from_pci(path, i)
                for s in convert_dep_file_dict(path):
                    if 'xz' in s:
                        check_ko_xz = '.xz'
                        break
                ko_name = ko_name + check_ko_xz
                pci_ko_name.append(ko_name)
        for find_mod in find_mod_list + pci_ko_name:
            if '.ko' in find_mod:
                num, ko = search_mod_file_rel(path, find_mod)
                if num == 1:
                    num0, sort_over = son_and_father_modfile_form_dep(ko[0], path)
                    ok_list.append(sort_over)
                else:
                    if num == 0:
                        no_find_list.append(find_mod)
                    if num >= 2 and select_dir == 'updates':
                        num0, sort_over = son_and_father_modfile_form_dep(ko[0], path)
                        ok_list.append(sort_over)
                    else:
                        if '.xz' in find_mod:
                            num1, sort_over = son_and_father_modfile_form_dep_old(select_dir, find_mod, path, '.ko.xz')
                        else:
                            num1, sort_over = son_and_father_modfile_form_dep_old(select_dir, find_mod, path, '.ko')
                        ok_list.append(sort_over)
        return 0, ok_list, no_find_list
    else:
        return -1, []


if __name__ == "__main__":
    path0 = '/run/kvm_linux/1e176a1887264362918554928d36dd2d/lib/modules/3.10.0-327.el7.x86_64'
    # path0 = '/dev/shm/kvm_linux/63df2db6a242428b97d16a817a6af807/lib/modules/3.0.13-0.27-default'
    # find_mod_list = ['raid0.ko.xz', 'snd-pcm.ko.xz', 'abc.ko', '12343.ko',
    #                  'VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01&CLASS_020000']
    find_mod_list = ['serpent-avx2.ko', 'vport-vxlan.ko','VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01&CLASS_020000121']
    print(mod_dep_get(path0, find_mod_list, 'updates'))
    print('------------------------环路检测----------------------')
    # temp = convert_dep_file_dict(path0)
    # bedep = []
    # no_find_ko = list()
    # for i in temp:
    #     bedep.append(i)
    # # print(temp)
    # m = 0
    # for ko_name in bedep:
    #     m += 1
    #     try:
    #         mod_dep_all_find.clear()
    #         graph = find(ko_name, path0, temp)
    #         print(m, base_sort(graph))
    #     except Exception as e:
    #         print(e, ko_name)
    #         no_find_ko.append(ko_name)
    # print(no_find_ko)
