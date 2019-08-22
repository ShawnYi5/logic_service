import copy
import os
import pathlib
import traceback

import modlink
import xlogging

_logger = xlogging.getLogger(__name__)

mod_dict_header = {'file': '', 'in_attr': '', 'dep': [], 'bedep': []}
alias_split_list = ['alias pci:v', 'd', 'sv', 'sd', 'bc', 'sc', 'i', '* ']


def str_cmp(str1, str2):
    u'''
    :param str1:文件名
    :param str2:文件名
    :return:相同：0   不同：-1
    '''
    if len(str1) != len(str2):
        return -1
    for i in range(len(str1)):
        if (str1[i] == '-' or str1[i] == '_') and (str2[i] == '-' or str2[i] == '_'):
            continue
        if str1[i] != str2[i]:
            return -1
    return 0


def str_cmp_unsuffix(str1, str2):
    u'''
    :param str1:文件名
    :param str2:文件名
    :return:相同：0   不同：-1
    '''
    if not all(['.' in str1, '.' in str2]):
        return -1

    str1_unsuffix = '{}.{}'.format(str1.split('.')[0], str1.split('.')[1])
    str2_unsuffix = '{}.{}'.format(str2.split('.')[0], str2.split('.')[1])

    if len(str1_unsuffix) != len(str2_unsuffix):
        return -1
    for i in range(len(str1_unsuffix)):
        if (str1_unsuffix[i] == '-' or str1_unsuffix[i] == '_') and (
                str2_unsuffix[i] == '-' or str2_unsuffix[i] == '_'):
            continue
        if str1_unsuffix[i] != str2_unsuffix[i]:
            return -1
    return 0


def ModFileGetPath(path, modfile):
    u'''
    :param path: （驱动）所在的路径
    :param modfile: 文件名
    :return: modfile文件路径
    '''
    if os.path.isdir(path):
        for fn in os.listdir(path):
            mfile = os.path.join(path, fn)
            if os.path.isdir(mfile):
                ret = ModFileGetPath(mfile, modfile)
                if ret != '':
                    return ret
            else:
                if str_cmp_unsuffix(fn, modfile) == 0:
                    return mfile
    return ''


# the search order (in /etc/depmod.d/depmod.conf.dist is "search updates extra built-in weak-updates".
def ModFileGetPathWithPriority(dir_path, modfile):
    if os.path.isdir(dir_path):
        file_names = list(os.listdir(dir_path))
        first = 'updates'
        if first in file_names:
            file_names.remove(first)
            file_path = os.path.join(dir_path, first)
            returned = ModFileGetPath(file_path, modfile)
            if returned != '':
                return returned
        second = 'extra'
        if second in file_names:
            file_names.remove(second)
            file_path = os.path.join(dir_path, second)
            returned = ModFileGetPath(file_path, modfile)
            if returned != '':
                return returned
        for file_name in file_names:
            file_path = os.path.join(dir_path, file_name)
            returned = ModFileGetPath(file_path, modfile)
            if returned != '':
                return returned
    return ''


def is_pci_value_valid(pci_list):
    if len(pci_list) + 3 != len(alias_split_list):
        _logger.error('invalid pci_list {}, alias_split_list {}'.format(pci_list, alias_split_list))
        return False
    return True


def is_pci_value_list_match(pci_list, text_line):
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
        start_pos += index2

    if len(glist) == len(pci_list) + 2:
        pci_list_tmp = [pci_list[0], pci_list[1], pci_list[2], pci_list[3],
                        pci_list[4][0] + pci_list[4][1],
                        pci_list[4][2] + pci_list[4][3],
                        pci_list[4][4] + pci_list[4][5]]

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


def ModFileGetFromAlias(modpath, pci_list):
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


def convert_pci_str_2_pci_value_list(pci_str):
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


def ModFileGetFromPci(modpath, pci_str):
    vlist = convert_pci_str_2_pci_value_list(pci_str)
    return ModFileGetFromAlias(modpath, vlist)


def ModListAdd(modlist, addstr):
    for mdict in modlist:
        if addstr == mdict['file']:
            break
    else:
        mdict = copy.deepcopy(mod_dict_header)
        mdict['file'] = addstr
        mdict['in_attr'] = ''
        modlist.append(mdict)


def ModFileGetDep(modpath, modlist):
    try:
        # /run/kvm_linux/1e176a1887264362918554928d36dd2d/lib/modules/2.6.32.12-0.7-pae 截掉/run/kvm_linux/uuid
        abs_rootpath = str(list(pathlib.Path(modpath).parents)[-4])
    except IndexError:
        abs_rootpath = modpath
    rel_modpath = os.path.relpath(modpath, abs_rootpath)  # lib/modules/3.0.76-0.11-default
    abs_modpath = os.path.join('/', rel_modpath)  # /lib/modules/3.0.76-0.11-default

    depfile = os.path.join(modpath, 'modules.dep')
    # /dev/shm/kvm_linux/uuid/lib/modules/3.0.76-0.11-default/modules.dep
    if not os.path.isfile(depfile):
        _logger.error('depfile {} not exist'.format(depfile))
        return -1
    ret = modlink.read_file(depfile, 'r', False)

    if ret[0] != 0:
        _logger.error('depfile {} read failed,err {}'.format(depfile, ret))
        return -1
    mlist = ret[1].split('\n')
    '''
    /lib/modules/3.0.76-0.11-default/updates/pvdriver/vni_front/virtio.ko:
    /lib/modules/3.0.76-0.11-default/updates/pvdriver/vni_front/virtio_net.ko: /lib/modules/3.0.76-0.11-default/updates/pvdriver/vni_front/virtio.ko /lib/modules/3.0.76-0.11-default/updates/pvdriver/vni_front/virtio_ring.ko
    /lib/modules/3.0.76-0.11-default/updates/pvdriver/vni_front/virtio_pci.ko: /lib/modules/3.0.76-0.11-default/updates/pvdriver/vni_front/virtio_ring.ko /lib/modules/3.0.76-0.11-default/updates/pvdriver/vni_front/virtio.ko
    /lib/modules/3.0.76-0.11-default/updates/pvdriver/vni_front/virtio_ring.ko:
    '''

    mdict = dict()
    for i, mlist_str in enumerate(mlist):
        strlist = mlist_str.strip(' ').replace(':', '').split(' ')
        # ['/lib/modules/3.0.76-0.11-default/updates/pvdriver/vni_front/virtio_net.ko', '/lib/modules/3.0.76-0.11-default/updates/pvdriver/vni_front/virtio.ko', '/lib/modules/3.0.76-0.11-default/updates/pvdriver/vni_front/virtio_ring.ko']

        for _str_index, _str_path in enumerate(strlist):
            if os.path.isabs(_str_path):
                strlist[_str_index] = os.path.relpath(_str_path, abs_modpath)  # 转换为相对路径
        # ['updates/pvdriver/vni_front/virtio_net.ko', 'updates/pvdriver/vni_front/virtio.ko', 'updates/pvdriver/vni_front/virtio_ring.ko']

        mlist[i] = strlist
        for _mlist_str in strlist:
            if _mlist_str in mdict:
                mdict[_mlist_str].append(i)
            else:
                mdict[_mlist_str] = [i]

        # {
        #      'updates/pvdriver/vni_front/virtio_net.ko': ['updates/pvdriver/vni_front/virtio_net.ko', 'updates/pvdriver/vni_front/virtio.ko', 'updates/pvdriver/vni_front/virtio_ring.ko']
        # }

    i = 0
    while True:
        if i >= len(modlist):
            break
        moddict = modlist[i]
        modfile = moddict['file']
        mmlist = mdict[modfile]
        for index in mmlist:
            strlistlen = len(mlist[index])
            if strlistlen > 1 and modfile in mlist[index][1:]:
                moddict['bedep'].append(mlist[index][0])
                ModListAdd(modlist, mlist[index][0])
        i += 1

    i = 0
    while True:
        if i >= len(modlist):
            break
        moddict = modlist[i]
        modfile = moddict['file']
        mmlist = mdict[modfile]
        for index in mmlist:
            strlistlen = len(mlist[index])
            if modfile == mlist[index][0] and strlistlen > 1:
                moddict['dep'] += (mlist[index][1:])
                for mstr in mlist[index][1:]:
                    ModListAdd(modlist, mstr)
        i += 1
    return 0


def ModListSplit(modlist):
    retlist = list()
    retlistnum = 0
    while True:
        if len(modlist) <= 0:
            break
        mlist = [modlist[0]]
        del modlist[0]
        i = 0
        while True:
            if i >= len(mlist):
                break
            mdict = mlist[i]
            mmlist = mdict['dep'] + mdict['bedep']
            for file in mmlist:
                for j in range(len(modlist)):
                    mdict = modlist[j]
                    if file == mdict['file'] or file in mdict['dep'] or file in mdict['bedep']:
                        mlist.append(mdict)
                        del modlist[j]
                        break
            i += 1
        retlistnum += 1
        _logger.debug('get one modlist index {},size {},already have {}'.format(retlistnum, len(mlist), len(modlist)))
        retlist.append(mlist)
    return retlist


def ModListSort(modlist):
    sortlist = list()
    while True:
        if len(modlist) <= 0:
            break
        mlist = [modlist[0]]
        sortlist.append(modlist[0]['file'])
        del modlist[0]
        while True:
            i = len(mlist)
            if i <= 0:
                break
            while True:
                deplen = len(mlist[i - 1]['dep'])
                if deplen > 0:
                    modfile = mlist[i - 1]['dep'][0]
                    del mlist[i - 1]['dep'][0]
                    for mdict in mlist:
                        if modfile == mdict['file']:
                            _logger.error('detect an cycle modfile {} dep {}'.format(modfile, mlist))
                            return -1, []
                    for j in range(len(modlist)):
                        if modfile == modlist[j]['file']:
                            for k in range(len(sortlist)):
                                if sortlist[k] == mlist[i - 1]['file']:
                                    if k >= 1:
                                        sortlist.insert(k - 1, modfile)
                                    else:
                                        sortlist.insert(k, modfile)
                                    break
                            else:
                                _logger.error('can not find pre index sortlist {},mlist {},modlist {}'.
                                              format(sortlist, mlist, modlist))
                                return -1, []
                            mlist.append(modlist[j])
                            del modlist[j]
                            break
                    else:
                        continue
                else:
                    del mlist[i - 1]
                break
    _logger.debug('sort success {}'.format(sortlist))
    return 0, sortlist


def ModFileGet(modpath, modstr):
    try:
        if modstr.find('.ko') < 0:
            modfile = ModFileGetFromPci(modpath, modstr)
            if modfile == '':
                _logger.error('pci {} ModFileGetFromPci failed'.format(modstr))
        else:
            modfile = modstr
        if modfile != '':
            modfile = ModFileGetPathWithPriority(modpath, modfile)  # 返回一个绝对文件路径（不是目录！）
            if modfile != '':
                modfile = os.path.relpath(modfile, modpath)  # 从modpath开始计算相对路径
                return modfile
    except Exception as e:
        _logger.error('deal pci onestr {} except {} {}'.format(modstr, e, traceback.format_exc()))

    return ''


def ModDepGet(modpath, inlist):
    # lib_modules_path :/dev/shm/kvm_linux/6c9b39ffb047409ebfd2fd58a50835b6/lib/modules/3.10.0-693.el7.x86_64
    # pci_devices:['VEN_1AF4&DEV_1001&SUBSYS_15AD21AF4&REV_00&CLASS_010000','virtio.ko','virtio.ko.xz'...]
    oklist = list()
    faillist = list()
    # get ko or ko.xz file
    for fn in inlist:
        modfile = ModFileGet(modpath, fn)
        mdict = copy.deepcopy(mod_dict_header)
        mdict['file'] = modfile
        mdict['in_attr'] = fn
        if modfile != '':
            oklist.append(mdict)
        else:
            faillist.append(fn)
    # if contain virtio_pci.ko,add virtio_blk.ko, virtio_net.ko,virtio_scsi.ko AND
    # if contain virtio_pci.ko.xz,add virtio_blk.ko.xz, virtio_net.ko.xz,virtio_scsi.ko.xz
    extend_list = []
    for kodict in oklist:
        findindex = kodict['file'].find('virtio_pci.ko')
        if findindex > 0:
            check_list = ['virtio_blk.ko', 'virtio_net.ko', 'virtio_scsi.ko']
            for checkstr in check_list:
                modfile = ModFileGet(modpath, checkstr)
                if modfile != '':
                    mdict = copy.deepcopy(mod_dict_header)
                    mdict['file'] = modfile
                    extend_list.append(mdict)
            break
    oklist.extend(extend_list)
    # get file depend
    ret = ModFileGetDep(modpath, oklist)
    _logger.info('ModDepGet ModFileGetDep ret:{} ,oklist:{}'.format(ret, oklist))
    if ret != 0:
        _logger.error('ModFileGetDep failed')
        return -1, []
    # split mod list
    mlist = ModListSplit(oklist)
    # sort modlist
    retlist = list()
    for mmlist in mlist:
        ret = ModListSort(mmlist)
        if ret[0] != 0:
            _logger.error('sort failed {}'.format(mmlist))
            return -1, []
        retlist.append(ret[1])
    _logger.debug('ModDepGet success,faillist {},oklist {}'.format(faillist, retlist))
    return 0, retlist, faillist


if __name__ == "__main__":
    path = '/dev/shm/kvm_linux/63df2db6a242428b97d16a817a6af807/lib/modules/2.6.18-194.el5'
    _pci_str1 = 'VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01&CLASS_020000'
    print(ModDepGet(path, [_pci_str1]))
    _pci_str1 = 'VEN_8086&DEV_7110&SUBSYS_14140000&REV_01&CLASS_060100'
    print(ModDepGet(path, [_pci_str1]))
    _pci_str1 = 'VEN_8086&DEV_1C02&SUBSYS_1043844D&REV_05&CLASS_010601'
    print(ModDepGet(path, [_pci_str1]))
