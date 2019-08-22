from modget2 import mod_dep_get, convert_dep_file_dict
from modget import ModDepGet

def test_api(path1, find_mod_list):
    test = mod_dep_get(path1, find_mod_list)
    if test[1] != []:
        print(len(test[1][0]))
    temp_str = ''
    dep_dic = convert_dep_file_dict(path1)
    for d in dep_dic:
        temp_str = d.split('kernel')[0]
        break
    for i in test[1]:
        i = [temp_str + s for s in i]
        for index, k in enumerate(i):
            temp = i[index:]
            index += 1
            bob = [v for v in temp if v in dep_dic[temp[0]]]
            if len(bob) != 0:
                print('fail')
                break


if __name__ == "__main__":
    # eg:我们要找fcoe.ko,也可以是一串.ko文件的别名2.6.18-194.el7 3.10.0-693.el7.x86_64
    # /lib/modules/2.6.18-194.el5/kerne     l/net/bridge/netfilter/ebtables.ko
    path = '/dev/shm/kvm_linux/63df2db6a242428b97d16a817a6af807/lib/modules/2.6.18-194.el6'
    path1 = '/dev/shm/kvm_linux/63df2db6a242428b97d16a817a6af807/lib/modules/3.10.0-123.el7.x86_64'
    test_api(path1, ['snd-pcm.ko'])
    # test_ko_xz = ['snd-pcm.ko.xz', 'ahci.ko.xz', 'nfsv3.ko.xz', 'libahci.ko.xz']
    # test_ko = ['snd-pcm.ko', 'ahci.ko', 'nfsv3.ko', 'libahci.ko', 'ebt_among.ko']
    # pci_str1 = 'VEN_8086&DEV_1C02&SUBSYS_1043844D&REV_05&CLASS_010601'
    # pci_str2 = 'VEN_8086&DEV_1C0B&SUBSYS_1043844D&fREV_05&CLASS_010x01'  # 这是一个不存在的pci串
    # pci_str3 = 'VEN_10EC&DEV_8139&SUBSYS_58530001&REV_20&CLASS_020000'
    # pci_str4 = 'VEN_8086&DEV_7010&SUBSYS_1AF41100&REV_00&CLASS_010180'
    # pci_str5 = 'VEN_8086&DEV_100E&SUBSYS_1AF41100&REV_03&CLASS_020000'
    # pci_str6 = 'VEN_10EC&DEV_8139&SUBSYS_1AF41100&REV_20&CLASS_020000'
    # long = ['VEN_15AD&DEV_07B0&SUBSYS_15AD07B0&REV_01&CLASS_020000',
    #         "VEN_10EC&DEV_8139&SUBSYS_58530001&REV_20&CLASS_020000",
    #         "VEN_8086&DEV_7010&SUBSYS_1AF41100&REV_00&CLASS_010180",
    #         "VEN_8086&DEV_100E&SUBSYS_1AF41100&REV_03&CLASS_020000",
    #         "VEN_10EC&DEV_8139&SUBSYS_1AF41100&REV_20&CLASS_020000",
    #         "VEN_1000&DEV_0054&SUBSYS_15AD1976&REV_01&CLASS_010700",
    #         "VEN_8086&DEV_7111&SUBSYS_15AD1976&REV_01&CLASS_01018A",
    #         "VEN_15AD&DEV_07B0&SUBSYS_15AD07B0&REV_01&CLASS_020000"
    #         ]
    # test_ko_pci = [pci_str1, pci_str2, pci_str3, pci_str4, pci_str5, pci_str6]
