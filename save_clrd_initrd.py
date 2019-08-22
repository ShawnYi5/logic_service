# coding:utf-8
import os
import loadIce


clrd_initrd_dir_name = "saved_initrd_clrd"
clrd_initrd_json_file_name = "clrd_initrd.json"

# 不必保存vmlinuz, initrd, grub的md5sum了, 原来的设计是在原来的位置, 并没有保存, 所以要md5sum
key_vmlinuz_path = 'vmlinuz_path_clrd'              # 保存的安装后的vmlinuz文件
key_initrd_path = 'initrdfs_path_clrd'              # 保存的安装后的initrdfs文件
key_grub_path = 'original_grub_path_clrd'           # 保存的安装后原始的grub文件
key_grubenv_path = "original_grubenv_path_clrd"     # 保存的安装后原始的grubenv文件
key_grub_safe = 'backup_grub_file_clrd_is_safe'     # 保存的安装后原始的grub文件是否安全
key_driver_file_name_disksbd_linux = "clrd_driver_file_name_disksbd_linux"     # disksbd_linux的路径
key_insmod_cmd_disksbd_linux = "clrd_driver_insmod_cmd_disksbd_linux"          # disksbd_linux的insmod命令
key_insmod_cmd_cwd_disksbd_linux = "clrd_driver_insmod_cmd_cwd_disksbd_linux"  # disksbd_linux的insmod命令的cwd
key_driver_file_name_sbd_fun_linux = "clrd_driver_file_name_sbd_fun_linux"     # sbd_fun_linux的路径
key_insmod_cmd_sbd_fun_linux = "clrd_driver_insmod_cmd_sbd_fun_linux"          # sbd_fun_linux的insmod命令
key_insmod_cmd_cwd_sbd_fun_linux = "clrd_driver_insmod_cmd_cwd_sbd_fun_linux"  # sbd_fun_linux的insmod命令的cwd


def get_clrd_initrd_json_path(root_dir_install):

    global clrd_initrd_dir_name
    global clrd_initrd_json_file_name

    return os.path.join(root_dir_install, clrd_initrd_dir_name, clrd_initrd_json_file_name)


def get_clrd_initrd_dir_path(root_dir_install):

    global clrd_initrd_dir_name

    return os.path.join(root_dir_install, clrd_initrd_dir_name)


