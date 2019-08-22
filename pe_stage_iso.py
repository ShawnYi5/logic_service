import copy
import distutils.dir_util as dir_util
import json
import os
import shutil
import sqlite3
import time
import traceback

import chardet

import xlogging

_logger = xlogging.getLogger(__name__)

install_drv = "install_drv.py"
install_reg = "install_reg.py"
backup_drv = "backup_drivers.py"
replace_efi = 'replace_efi.py'
db_path = '/var/db/drvierid.db'
src_user_db_path = '/sbin/aio/box_dashboard/xdashboard/handle/drvierid_user.db'
user_db_path = '/var/db/drvierid_user.db'
cfg_oem_path = '/etc/aio/db_oem.cfg'

_DEBUG_PAUSE_IN_KVM_BEGIN = '/dev/shm/_debug_pause_in_kvm_begin'
_DEBUG_PAUSE_IN_KVM_END = '/dev/shm/_debug_pause_in_kvm_end'

# max_inf_time = 2999 * 365 + 12 * 30 + 31
g_del = 0
# g_type:1正常扫描数据。
# g_type:2 纯粹的驱动库。
g_type = 1
g_micro_score = 0x8000000

need_copy_file = [
    ["install_drv_org.py", install_drv],
    ["install_reg_org.py", install_reg],
    ["backup_drivers_org.py", backup_drv],
    ['replace_efi_org.py', replace_efi],
]
g_os_name_list = [
    {'os_name': "Server10_X64", 'major': 10, 'min': 0, 'bIs64': 1},
    {'os_name': "10_X64", 'major': 10, 'min': 0, 'bIs64': 1},
    {'os_name': "10_X86", 'major': 10, 'min': 0, 'bIs64': 0},

    {'os_name': "Server6_3_X64", 'major': 6, 'min': 3, 'bIs64': 1},
    {'os_name': "6_3_X64", 'major': 6, 'min': 3, 'bIs64': 1},
    {'os_name': "6_3_X86", 'major': 6, 'min': 3, 'bIs64': 0},

    {'os_name': "Server8_X64", 'major': 6, 'min': 2, 'bIs64': 1},
    {'os_name': "8_X64", 'major': 6, 'min': 2, 'bIs64': 1},
    {'os_name': "8_X86", 'major': 6, 'min': 2, 'bIs64': 0},

    {'os_name': "Server2008R2_X64", 'major': 6, 'min': 1, 'bIs64': 1},
    {'os_name': "7_X64", 'major': 6, 'min': 1, 'bIs64': 1},
    {'os_name': "7_X86", 'major': 6, 'min': 1, 'bIs64': 0},

    {'os_name': "Server2008_X64", 'major': 6, 'min': 0, 'bIs64': 1},
    {'os_name': "Server2008_X86", 'major': 6, 'min': 0, 'bIs64': 0},
    {'os_name': "Vista_X64", 'major': 6, 'min': 0, 'bIs64': 1},
    {'os_name': "Vista_X86", 'major': 6, 'min': 0, 'bIs64': 0},

    {'os_name': "Server2003_X64", 'major': 5, 'min': 2, 'bIs64': 1},
    {'os_name': "Server2003_X86", 'major': 5, 'min': 2, 'bIs64': 0},
    {'os_name': "XP_X64", 'major': 5, 'min': 1, 'bIs64': 1},
    {'os_name': "XP_X86", 'major': 5, 'min': 1, 'bIs64': 0},

    {'os_name': "2000", 'major': 5, 'min': 0, 'bIs64': 0}
]


class IsoMaker(object):
    def __init__(self, content_dir, driver_pool_dir, tmp_dir, iso_file_path):
        global db_path
        self._inf_list_list = list()
        self._content_dir = content_dir
        self._driver_pool_dir = driver_pool_dir
        self._tmp_dir = tmp_dir
        self._iso_file_path = iso_file_path
        self.have_iastorF_id = False
        # self._sub_id_list = ['B06BDRV\\', 'EBDRV\\', 'XEN\\', 'XENBUS\\', 'XENVIF\\', 'ROOT\\XENEVTCHN']
        self._sub_id_list = ['B06BDRV\\', 'EBDRV\\', 'QEBDRV\\']
        self._hw_name_array = self.load_hw_name_list()
        # 开始读取oem 需要包含的名单项。
        self.oem_include_list = list()
        try:
            with open(cfg_oem_path) as oem_include_handle:
                oem_include_str = oem_include_handle.read()
                self.oem_include_list = json.loads(oem_include_str)
                _logger.info('IsoMaker oem_include_list = {}'.format(self.oem_include_list))
        except:
            _logger.warning(r'IsoMaker can not find {}'.format(cfg_oem_path))

    # @staticmethod
    # def load_sub_id_list():
    #     sub_id_list = []
    #     try:
    #         with sqlite3.connect(db_path) as cx:
    #             cu = cx.cursor()
    #             i = 0
    #             while True:
    #                 cmd = r"select * from cfg_table where name='SUBID" + str(i) + r"'"
    #                 _logger.debug(cmd)
    #                 cu.execute(cmd)
    #                 one_db = cu.fetchone()
    #                 if one_db is None:
    #                     break
    #                 sub_id_list.append(one_db[2])
    #                 i = i + 1
    #         return sub_id_list
    #     except Exception as e:
    #         _logger.warning(r'load_hw_name_list failed {}'.format(e))
    #         return sub_id_list

    @staticmethod
    def load_hw_name_list():
        hw_name_list = ['']
        try:
            with sqlite3.connect(db_path) as cx:
                cu = cx.cursor()
                i = 1
                while True:
                    cmd = r"select * from cfg_table where name='paltform" + str(i) + r"'"
                    _logger.debug(cmd)
                    cu.execute(cmd)
                    one_db = cu.fetchone()
                    if one_db is None:
                        break
                    hw_name_list.append(one_db[2])
                    i = i + 1
        except Exception as e:
            _logger.warning(r'load_hw_name_list failed {}'.format(e))

        if len(hw_name_list) <= 1:
            # 数据库读取失败，兼容老版本。
            hw_name_list = ['', '用户导入', '腾讯云', '阿里云', '华三', '华为']
        _logger.info('load_hw_name_list {}'.format(hw_name_list))
        return hw_name_list

    def IsHwInOem(self, HWPlatform):
        try:
            # 注意如果 oem_include_list 为 空，说明没有配置文件，不需要处理。
            if 0 == len(self.oem_include_list):
                return True

            # 0是空字符串，没有平台。1：是用户导入驱动，不受影响。
            if HWPlatform <= 1:
                return True

            str_hw_db = self.__int_hw_2_str(HWPlatform)
            if 0 == len(str_hw_db):
                # 如果获取平台字符串出错。就不处理了。
                return True

            for one_oem_name in self.oem_include_list:
                if -1 != str_hw_db.find(self.oem_include_list[one_oem_name]):
                    return True

            # 查遍用户配置未找到匹配项。
            return False
        except Exception as e:
            _logger.warning(r'IsHwInOem failed {},int_hw_db_num={}'.format(e, HWPlatform), exc_info=True)
            # 出错之后要能显示平台驱动。
            return True

    def copy_default_files(self):
        try:
            os.makedirs(self._tmp_dir, exist_ok=True)

            source_files = os.path.join(self._content_dir, '*')
            cmd = r'cp -fr {source} "{target}"'.format(source=source_files, target=self._tmp_dir)
            _logger.info(r'iso copy files : {}'.format(cmd))
            os.system(cmd)

            source_files = os.path.join(self._tmp_dir, r'Python34/')
            cmd = r'mv -b "{source}"* "{target}"'.format(source=source_files, target=self._tmp_dir)
            _logger.info(r'iso copy Python34 : {}'.format(cmd))
            os.system(cmd)

            for copy_file in need_copy_file:
                if len(copy_file) == 2:
                    abs_path = os.path.join(self._tmp_dir, copy_file[1])
                else:
                    abs_path = os.path.join(self._tmp_dir, copy_file[0])
                shutil.copyfile(os.path.join(self._content_dir, copy_file[0]), abs_path)

            abs_path = os.path.join(self._tmp_dir, 'tools.zip')
            try:
                shutil.copyfile('/var/www/static/download/tools.zip', abs_path)
            except:
                pass  # 工具拷贝出错可以忽略

            if os.path.isfile(_DEBUG_PAUSE_IN_KVM_BEGIN):
                abs_path = os.path.join(self._tmp_dir, '_debug_pause_in_kvm_begin')
                os.mknod(abs_path)
            if os.path.isfile(_DEBUG_PAUSE_IN_KVM_END):
                abs_path = os.path.join(self._tmp_dir, '_debug_pause_in_kvm_end')
                os.mknod(abs_path)

        except Exception as e:
            xlogging.raise_system_error(r'导入ISO内容失败', r'copy_default_files failed {}'.format(e), 0, _logger)

    def str2sql(self, str_value):
        if str_value is None:
            return " '' "
        _logger.debug(str_value)
        return " '" + str_value + "' "

    def int2sql(self, num):
        if num is None:
            return " '' "
        return " " + str(num) + " "

    def strAname2sql(self, name, str_value):
        if name is None or str_value is None:
            return " "
        return " " + name + "='" + str_value + "' "

    def intAname2sql(self, name, num):
        if name is None or num is None:
            return " "
        return " " + name + "=" + str(num) + " "

    def _search_one_id_in_db(self, system_name, cx, one_id, tmp_path):
        global g_del
        # g_type:1正常扫描数据。
        # g_type:2 纯粹的驱动库。
        global g_type
        try:
            cu = cx.cursor()
            bRet = False
            db_system_name_list = self.__check_near_and_get_db_system_name(cu, one_id, system_name)
            for db_system_name, min_os_dec in db_system_name_list:
                if db_system_name is None:
                    return False
                cmd = "select * from id_table where " + self.strAname2sql('hard_or_comp_id', one_id) \
                      + "and" + self.intAname2sql('del', 0) + "and" + self.strAname2sql('system_name', db_system_name)
                _logger.debug(cmd)
                cu.execute(cmd)
                while True:
                    one_db = cu.fetchone()
                    if one_db is None:
                        break
                    if self.IsInDelTable(cx, one_db[12], system_name) is True:
                        continue
                    inf_old_path = one_db[11]
                    _logger.info('inf_old_path={}'.format(inf_old_path))
                    if inf_old_path is None:
                        # 是微软驱动，没有路径。
                        break
                    # 获取src_path的源目录。
                    if one_db[12] is None:
                        break
                    if 0 == len(one_db[12]):
                        break
                    src_dir = os.path.join(self._driver_pool_dir, os.path.splitext(one_db[12])[0])
                    _logger.info('src_dir={}'.format(src_dir))
                    new_des_path = os.path.join(tmp_path, os.path.splitext(one_db[12])[0])
                    _logger.info('new_des_path={}'.format(new_des_path))
                    # 删除目标路径目录。
                    # shutil.rmtree(new_des_path, True)
                    # 拷贝源目录到目标路径目录。
                    dir_util.copy_tree(src_dir, new_des_path)
                    # 建立配置文件。
                    ini_des_path_str_1 = new_des_path[len(self._tmp_dir):]
                    _logger.info('ini_des_path_str_1={}'.format(ini_des_path_str_1))
                    ini_des_path = "." + ini_des_path_str_1 + "/" + os.path.basename(inf_old_path)
                    _logger.info('ini_des_path={}'.format(ini_des_path))
                    _logger.info('_copy_inf_dir_and_gen_install_drv_str_and_time : {}'.format(ini_des_path))
                    inf_list = list()
                    inf_list.append(ini_des_path.replace('\\', '/'))
                    inf_list.append(one_db[10])
                    inf_list.append(one_db[7])
                    self._inf_list_list.append(inf_list)
                    _logger.info('_inf_list_list={}'.format(self._inf_list_list))
                    bRet = True
            return bRet
        except Exception as e:
            _logger.warning(r'_search_one_id_in_db failed {}'.format(e), exc_info=True)
            return False

    def _search_id_in_db(self, system_name, cx, hardward_id_list, compatible_id_list, tmp_path):
        try:
            for one_id in hardward_id_list:
                if self._search_one_id_in_db(system_name, cx, one_id, tmp_path) is True:
                    return

            for one_id in compatible_id_list:
                if self._search_one_id_in_db(system_name, cx, one_id, tmp_path) is True:
                    return

        except Exception as e:
            _logger.warning(r'_search_id_in_db failed {}'.format(e), exc_info=True)

    def _copy_need_drv(self, system_name, hardward_id_list, compatible_id_list, tmp_path, user_select_drv_list):
        try:
            for one_drv in user_select_drv_list:
                if one_drv['UserSelected'] == 0:
                    continue
                inf_old_path = one_drv['inf_path']
                _logger.info('_copy_need_drv inf_old_path={}'.format(inf_old_path))
                if inf_old_path is None:
                    # 是微软驱动，没有路径。
                    continue
                # 获取src_path的源目录。
                if one_drv['zip_path'] is None:
                    continue
                if 0 == len(one_drv['zip_path']):
                    continue
                src_dir = os.path.join(self._driver_pool_dir, os.path.splitext(one_drv['zip_path'])[0])
                _logger.info('_copy_need_drv src_dir={}'.format(src_dir))
                new_des_path = os.path.join(tmp_path, os.path.splitext(one_drv['zip_path'])[0])
                _logger.info('_copy_need_drv new_des_path={}'.format(new_des_path))
                only_sha256_flag = os.path.join(tmp_path, 'only_sha256.flag')
                if one_drv['OnlySAH256'] != 0:
                    if not os.path.exists(only_sha256_flag):
                        with open(only_sha256_flag, 'x') as out_put:
                            out_put.write("find sha 256")
                # 删除目标路径目录。
                # shutil.rmtree(new_des_path, True)
                # 拷贝源目录到目标路径目录。
                try:
                    dir_util.copy_tree(src_dir, new_des_path)
                except Exception as e:
                    _logger.info(
                        '_copy_need_drv can not find dir src_dir={},new_des_path={}'.format(src_dir, new_des_path))
                    # 建立配置文件。
                    # ini_des_path_str_1 = new_des_path[len(self._tmp_dir):]
                    # _logger.info('_copy_need_drv ini_des_path_str_1={}'.format(ini_des_path_str_1))
                    # ini_des_path = "." + ini_des_path_str_1 + "/" + os.path.basename(inf_old_path)
                    # _logger.info('_copy_need_drv ini_des_path={}'.format(ini_des_path))
                    # _logger.info('_copy_need_drv _copy_inf_dir_and_gen_install_drv_str_and_time : {}'.format(ini_des_path))
                    # inf_list = list()
                    # inf_list.append(ini_des_path.replace('\\', '/'))
                    # inf_list.append(one_drv['inf_driver_ver'])
                    # inf_list.append(one_drv['hard_or_comp_id'])
                    # self._inf_list_list.append(inf_list)
                    # _logger.info('_copy_need_drv _inf_list_list={}'.format(self._inf_list_list))
            pass
        except Exception as e:
            _logger.warning(r'_copy_need_drv failed {}'.format(e), exc_info=True)

    def __one_2_ini_des_path(self, tmp_path, one):
        try:
            new_des_path = os.path.join(tmp_path, os.path.splitext(one['zip_path'])[0])
            ini_des_path_str_1 = new_des_path[len(self._tmp_dir):]
            ini_des_path = "." + ini_des_path_str_1 + "/" + os.path.basename(one['inf_path'])
            ini_des_path = ini_des_path.replace('\\', '/')
            return ini_des_path
        except Exception as e:
            _logger.warning(r'__one_2_ini_des_path failed {}'.format(e), exc_info=True)
            return ''

    def WriteInstDrvPyBySelectOne(self, tmp_path, out_put, select_one, bForce=False):
        try:
            if bForce:
                out_put.write("    devcon_install_dev(r\'" + select_one[
                    'hard_or_comp_id'] + "\',r\'" + self.__one_2_ini_des_path(tmp_path, select_one) + "\',True)\r\n")
            else:
                out_put.write("    devcon_install_dev(r\'" + select_one[
                    'hard_or_comp_id'] + "\',r\'" + self.__one_2_ini_des_path(tmp_path, select_one) + "\')\r\n")

                # out_put.write(
                #     "    chk_reg_is_ok(" + self._one_to_list_to_one_str(select_one['hard_or_comp_id']) + ")\r\n")

        except Exception as e:
            _logger.error(r'WriteInstDrvPyBySelOne failed {}'.format(e), exc_info=True)

    def WriteInstDrvPyAndCheckSubBySelectOne(self, tmp_path, out_put, select_one, bForce=False):
        try:
            # 查询硬件id是否有子设备。
            # hwlist = list()
            self.WriteInstDrvPyBySelectOne(tmp_path, out_put, select_one, bForce)
            # hwlist.append(select_one['hard_or_comp_id'])
            sub_select_list = self.one_select_2_get_sub_drv_list(select_one)
            for one_sub in sub_select_list:
                self.WriteInstDrvPyBySelectOne(tmp_path, out_put, one_sub, bForce)
            return sub_select_list
        except Exception as e:
            _logger.error(r'WriteInstDrvPyBySelOne failed {}'.format(e), exc_info=True)
            return []

    def __install_platform_drv(self, hardward_id_list, tmp_path, out_put, user_select_drv_list):
        try:
            bHave_ChosePlatform = False
            for one in user_select_drv_list:
                if one['IsPlatform'] == 0:
                    continue
                if one['UserSelected'] == 1:
                    bHave_ChosePlatform = True

            bHaveInstall = False
            sub_select_list = list()
            for one in user_select_drv_list:
                if one['IsPlatform'] == 0:
                    continue
                if one['UserSelected'] == 1:
                    if bHaveInstall is not True:
                        bHaveInstall = True
                        sub_select_list = self.WriteInstDrvPyAndCheckSubBySelectOne(tmp_path, out_put, one, True)
                    else:
                        sub_select_list = self.WriteInstDrvPyAndCheckSubBySelectOne(tmp_path, out_put, one)

            if bHave_ChosePlatform:
                out_put.write("    chk_reg_is_ok(" + self._str_list_to_one_str(hardward_id_list) + ")\r\n")
                if 0 != len(sub_select_list):
                    out_put.write("    chk_reg_is_ok([r'" + sub_select_list[0]['hard_or_comp_id'] + "'])\r\n")

            return bHave_ChosePlatform

        except Exception as e:
            _logger.warning(r'__install_platform_drv failed {}'.format(e), exc_info=True)
            return False

    def __install_micro_drv(self, hardward_id_list, compatible_id_list, tmp_path, out_put, user_select_drv_list):
        try:
            bHave_Micro = False
            bHave_ChoseMicro = False
            for one in user_select_drv_list:
                if (one['IsMicro'] == 0) or (one['IsMicro'] is None):
                    continue
                bHave_Micro = True
                if one['UserSelected'] == 1:
                    bHave_ChoseMicro = True
                    for one_id in compatible_id_list:
                        if one_id == r"PCI\CC_0101":
                            out_put.write("    install_micro_drv_addition(False, 'mshdc.inf', 'PCI\\CC_0101')\r\n")
                            # out_put.write("    chk_reg_is_ok(" + self._str_list_to_one_str(hardward_id_list) + ")\r\n")
                            out_put.write(
                                "    chk_reg_is_ok(" + self._one_to_list_to_one_str(one['hard_or_comp_id']) + ")\r\n")
                    # out_put.write("    chk_reg_is_ok(" + self._str_list_to_one_str(hardward_id_list) + ",True)\r\n")
                    out_put.write(
                        "    chk_reg_is_ok(" + self._one_to_list_to_one_str(one['hard_or_comp_id']) + ",True)\r\n")
            return bHave_Micro, bHave_ChoseMicro

        except Exception as e:
            _logger.warning(r'__install_micro_drv failed {}'.format(e), exc_info=True)
            return False, False

    def __install_normal_drv(self, hardward_id_list, tmp_path, out_put, user_select_drv_list, bHave_ChosePlatform,
                             bHave_Micro, bHave_ChoseMicro):
        try:
            bHave_ChoseNormal = False
            for one in user_select_drv_list:
                if one['IsPlatform'] == 1:
                    continue
                if one['IsMicro'] == 1:
                    continue
                if one['UserSelected'] == 1:
                    bHave_ChoseNormal = True

            bHaveInstall = False
            sub_select_list = list()
            for one in user_select_drv_list:
                if one['IsPlatform'] == 1:
                    continue
                if one['IsMicro'] == 1:
                    continue
                if one['UserSelected'] == 0:
                    continue
                if one['ForceInst'] != 0:  # 用户要求强制安装。不能干扰原有逻辑。
                    bHaveInstall = True
                    sub_select_list = self.WriteInstDrvPyAndCheckSubBySelectOne(tmp_path, out_put, one, True)
                    continue
                if bHave_ChosePlatform:  # 平台驱动已选择，肯定是已经强制安装，只能普通安装。
                    bHaveInstall = True
                    sub_select_list = self.WriteInstDrvPyAndCheckSubBySelectOne(tmp_path, out_put, one)
                    continue
                if bHave_Micro is not True:  # 没有微软驱动，普通安装。
                    bHaveInstall = True
                    sub_select_list = self.WriteInstDrvPyAndCheckSubBySelectOne(tmp_path, out_put, one)
                    continue
                if bHave_ChoseMicro:  # 有微软驱动，用户选择了微软驱动。
                    bHaveInstall = True
                    sub_select_list = self.WriteInstDrvPyAndCheckSubBySelectOne(tmp_path, out_put, one)
                    continue
                # 有微软驱动，用户没有选择微软驱动。
                if bHaveInstall is not True:
                    bHaveInstall = True  # 如果是第一项，需要强制安装。
                    sub_select_list = self.WriteInstDrvPyAndCheckSubBySelectOne(tmp_path, out_put, one, True)
                else:
                    sub_select_list = self.WriteInstDrvPyAndCheckSubBySelectOne(tmp_path, out_put, one)

            if bHave_ChoseNormal:
                out_put.write("    chk_reg_is_ok(" + self._str_list_to_one_str(hardward_id_list) + ")\r\n")
                if 0 != len(sub_select_list):
                    out_put.write("    chk_reg_is_ok([r'" + sub_select_list[0]['hard_or_comp_id'] + "'])\r\n")

        except Exception as e:
            _logger.warning(r'__install_normal_drv failed {}'.format(e), exc_info=True)
            return False

    def install_system_driver(self, hardward_id_list, compatible_id_list):
        try:
            _logger.warning(r'install_system_driver hardward_id_list = {}'.format(hardward_id_list))
            _logger.warning(r'install_system_driver compatible_id_list = {}'.format(compatible_id_list))
            with open(os.path.join(self._tmp_dir, install_drv), 'a+') as out_put:
                out_put.write(
                    "    devcon_install_system_driver(" + self._str_list_to_one_str(hardward_id_list) + ")\r\n")
        except Exception as e:
            tb = traceback.format_exc()
            xlogging.raise_system_error(r'安装系统驱动程序失败',
                                        r'install_system_driver {} {} failed {} {}'.format(hardward_id_list,
                                                                                           compatible_id_list, e, tb),
                                        0, _logger)

    def backup_system_driver(self, hardward_id_list, compatible_id_list):
        try:
            _logger.warning(r'backup_system_driver hardward_id_list = {}'.format(hardward_id_list))
            with open(os.path.join(self._tmp_dir, backup_drv), 'a+') as out_put:
                out_put.write(
                    "    backup_driverfiles(" + self._str_list_to_one_str(hardward_id_list) + ")\r\n")
        except Exception as e:
            _logger.warning(r'backup_system_driver failed {}'.format(e))

    def replace_efi(self):
        try:
            with open(os.path.join(self._tmp_dir, replace_efi), 'a+') as out_put:
                out_put.write("    r.work()")
        except Exception as e:
            _logger.warning(r'replace_efi failed {}'.format(e))

    def search_flag_in_id_list(self, hardward_id_list, compatible_id_list, one_flag):
        try:
            _logger.warning(r'search_flag_in_id_list hardward_id_list = {},one_flag = {}'.
                            format(hardward_id_list, one_flag))
            for one in hardward_id_list:
                if -1 != one.upper().find(one_flag.upper()):
                    return True
            for one in compatible_id_list:
                if -1 != one.upper().find(one_flag.upper()):
                    return True
            return False
        except Exception as e:
            _logger.warning(r'search_flag_in_id_list failed {}'.format(e))
            return False

    def search_flag_list_in_id_list(self, hardward_id_list, compatible_id_list, flag_list):
        try:
            _logger.warning(r'search_flag_list_in_id_list hardward_id_list = {}'.format(hardward_id_list))
            for one_flag in flag_list:
                if self.search_flag_in_id_list(hardward_id_list, compatible_id_list, one_flag):
                    return True
            return False
        except Exception as e:
            _logger.warning(r'search_flag_list_in_id_list failed {}'.format(e))
            return False

    def search_iastorF(self, hardward_id_list, compatible_id_list):
        iastorF_id_list = ['PCI\\VEN_8086&DEV_1D02&CC_0106', 'PCI\\VEN_8086&DEV_1E02&CC_0106',
                           'PCI\\VEN_8086&DEV_8C02&CC_0106', 'PCI\\VEN_8086&DEV_8C03&CC_0106',
                           'PCI\\VEN_8086&DEV_8C82&CC_0106', 'PCI\\VEN_8086&DEV_8C83&CC_0106',
                           'PCI\\VEN_8086&DEV_9C02&CC_0106', 'PCI\\VEN_8086&DEV_9C03&CC_0106']
        self.have_iastorF_id = self.search_flag_list_in_id_list(hardward_id_list, compatible_id_list, iastorF_id_list)

    # one_info = {'UserSelected': 0, 'hard_or_comp_id': None, 'show_name': None, 'year': 0, 'mon': 0, 'day': 0,
    #             'inf_driver_ver': 0, 'inf_path': None, 'zip_path': None, 'system_name': None, 'IsMicro': 0,
    #             'HaveProcScore': 0, 'IsPlatform': 0, 'Str_HWPlatform': None, 'OnlySAH256': 0,'ForceInst':0}
    def add_drive(self, system_name, sys_bit, hardward_id_list, compatible_id_list, user_select_drv_list,
                  hw_platform_id=0):
        global db_path
        try:
            _logger.warning(r'add_drive hardward_id_list = {}'.format(hardward_id_list))
            _logger.warning(r'add_drive compatible_id_list = {}'.format(compatible_id_list))
            _logger.warning(r'add_drive user_select_drv_list = {}'.format(user_select_drv_list))
            _logger.warning(r'add_drive system_name = {},hw_platform_id = {}'
                            .format(system_name, hw_platform_id))
            # vid = vid.upper()
            drive_pool_path = os.path.join(self._driver_pool_dir)
            if not os.path.exists(drive_pool_path):
                _logger.warning(r'NOT exists drive_pool_path : {}'.format(drive_pool_path))
                return

            tmp_path = os.path.join(self._tmp_dir, 'inf')
            os.makedirs(tmp_path, 0o777, True)
            self._inf_list_list.clear()

            self.search_iastorF(hardward_id_list, compatible_id_list)

            bHave_Chose = False
            for one in user_select_drv_list:
                if one['UserSelected'] == 1:
                    bHave_Chose = True
                    break

            with sqlite3.connect(db_path) as cx:
                if bHave_Chose is not True:
                    # PCI\VEN_6789 & DEV_0002 & SUBSYS_00010001 & REV_01 需要特殊处理。
                    for one_hardware_id in hardward_id_list:
                        if one_hardware_id == r'PCI\VEN_6789&DEV_0002&SUBSYS_00010001&REV_01':
                            self._search_id_in_db(system_name, cx, hardward_id_list, compatible_id_list, tmp_path)
                            self._inf_list_list.sort(key=lambda x: x[1], reverse=True)
                            inf_list = list()
                            with open(os.path.join(self._tmp_dir, install_drv), 'a+') as out_put:
                                for i in self._inf_list_list:
                                    # out_put.write("    devcon_install_dev(r\'" + i[2] + "\',r\'" + i[0] + "\')\r\n")
                                    inf_list.append(i[0])
                                out_put.write("    safe_devcon_install_dev(r\'" + one_hardware_id + "\', "
                                              + self._str_list_to_one_str(inf_list) + ")\r\n")
                                out_put.write("    os.system(g_devcon_name + ' rescan')\r\n")
                                out_put.write("    time.sleep(15)\r\n")
                                out_put.write("    os.system(os.path.join(cur_file_dir_str, 'WaitSysI.exe 30'))\r\n")
                                return
                else:
                    self._copy_need_drv(system_name, hardward_id_list, compatible_id_list, tmp_path,
                                        user_select_drv_list)

            # self._inf_list_list.sort(key=lambda x: x[1], reverse=True)不能在此拍寻，因为现在用户全选择会丢失优先级。
            with open(os.path.join(self._tmp_dir, install_drv), 'a+') as out_put:
                if self.search_flag_in_id_list(hardward_id_list, compatible_id_list, 'VMBUS'):
                    out_put.write("    install_hyper_v()\r\n")

                if bHave_Chose is not True:
                    # out_put.write("    chk_reg_is_ok(" + self._str_list_to_one_str(hardward_id_list) + ")\r\n")
                    # 根据与jiessie讨论，用户没有选择驱动，现在放过。
                    pass
                else:
                    bHave_ChosePlatform = self.__install_platform_drv(hardward_id_list, tmp_path, out_put,
                                                                      user_select_drv_list)
                    bHave_Micro, bHave_ChoseMicro = self.__install_micro_drv(hardward_id_list, compatible_id_list,
                                                                             tmp_path, out_put, user_select_drv_list)
                    self.__install_normal_drv(hardward_id_list, tmp_path, out_put, user_select_drv_list,
                                              bHave_ChosePlatform, bHave_Micro, bHave_ChoseMicro)

                if self.search_flag_in_id_list(hardward_id_list, compatible_id_list, 'PCI\\VEN_5853&DEV_0001'):
                    out_put.write("    add_xen_filter_v1()\r\n")
                if self.search_flag_in_id_list(hardward_id_list, compatible_id_list, 'PCI\\VEN_5853&DEV_0002'):
                    out_put.write("    add_xen_filter_v2()\r\n")

        except Exception as e:
            tb = traceback.format_exc()
            xlogging.raise_system_error(r'添加设备驱动程序失败', r'add_drive {} {} failed {} {}'
                                        .format(hardward_id_list, compatible_id_list, e, tb), 0,
                                        _logger)

    def add_drive_end(self):
        try:
            with open(os.path.join(self._tmp_dir, install_drv), 'a+') as out_put:
                if self.have_iastorF_id:
                    out_put.write("    install_iasotrF()\r\n")
                else:
                    out_put.write("    uninstall_iasotrF()\r\n")
        except Exception as e:
            tb = traceback.format_exc()
            xlogging.raise_system_error(r'添加设备驱动程序结束函数', r'add_drive_end failed {} {}'.format(e, tb), 0, _logger)

    def add_drive_old(self, system_name, sys_bit, hardward_id_list, compatible_id_list):
        try:
            _logger.warning(r'add_drive hardward_id_list = {}'.format(hardward_id_list))
            _logger.warning(r'add_drive compatible_id_list = {}'.format(compatible_id_list))
            # vid = vid.upper()
            drive_pool_path = os.path.join(self._driver_pool_dir)
            if not os.path.exists(drive_pool_path):
                _logger.warning(r'NOT exists drive_pool_path : {}'.format(drive_pool_path))
                return

            tmp_path = os.path.join(self._tmp_dir, 'inf')
            os.makedirs(tmp_path, 0o777, True)
            self._inf_list_list.clear()

            for root, dirs, files in os.walk(drive_pool_path):
                for file in files:
                    if file.lower().endswith('.inf'):
                        _logger.warning(r'search name = {}'.format(os.path.join(root, file)))
                        self._search_id_in_not_know_charset_file(hardward_id_list, compatible_id_list,
                                                                 os.path.join(root, file),
                                                                 tmp_path)

            # self._inf_list_list.sort(key=lambda x: x[1])
            with open(os.path.join(self._tmp_dir, install_drv), 'a+') as out_put:
                for i in self._inf_list_list:
                    out_put.write("    devcon_install_dev(r\'" + i[2] + "\',r\'" + i[0] + "\')\r\n")
                out_put.write("    chk_reg_is_ok(" + self._str_list_to_one_str(hardward_id_list) + ")\r\n")
        except Exception as e:
            tb = traceback.format_exc()
            xlogging.raise_system_error(r'添加设备驱动程序失败', r'add_drive {} {} failed {} {}'
                                        .format(hardward_id_list, compatible_id_list, e, tb), 0,
                                        _logger)

    def __get_year_mon_day_by_inf_driver_ver(self, db_inf_driver_ver):
        try:
            year = int(db_inf_driver_ver / 10000)
            tmp = db_inf_driver_ver - int(db_inf_driver_ver / 10000) * 10000
            mon = int(tmp / 100)
            day = tmp - int(tmp / 100) * 100
            return year, mon, day
        except Exception as e:
            _logger.warning(r'__get_year_mon_day_by_inf_driver_ver failed {}'.format(e), exc_info=True)
            return 0, 0, 0

    def __proc_score(self, system_name, one_db, one_info, IsHardwardList, num, min_os_dec, e_s_1):
        global g_micro_score
        try:
            if one_info['IsMicro'] == 1:
                one_info['HaveProcScore'] = g_micro_score  # 微软驱动固定数值
                return
            if one_db[16] == 1:  # 用户导入的平台驱动。
                one_info['HaveProcScore'] = one_info['HaveProcScore'] + 0x20000000
            elif one_info['IsPlatform'] == 1:  # 其他平台驱动。
                one_info['HaveProcScore'] = one_info['HaveProcScore'] + 0x10000000

            # if 2 == one_db[15] & 2:  # 测试过的驱动
            #     one_info['HaveProcScore'] = one_info['HaveProcScore'] + 0x800000

            db_system_name = self.GetDBSysNameByInfSysName(system_name)
            if e_s_1 is not None:
                if -1 != e_s_1.find(db_system_name):
                    one_info['HaveProcScore'] = one_info['HaveProcScore'] + 0x800000

            if 1 == one_db[15] & 1:  # 有签名
                one_info['HaveProcScore'] = one_info['HaveProcScore'] + 0x400000

            # inf 小版本号匹配度
            one_info['HaveProcScore'] = one_info['HaveProcScore'] + 0x200000 - (min_os_dec * 0x10000)

            if IsHardwardList is True:
                one_info['HaveProcScore'] = one_info['HaveProcScore'] + 0xf000 - num * 0x100
            else:
                one_info['HaveProcScore'] = one_info['HaveProcScore'] + 0x7000 - num * 0x100

        except Exception as e:
            _logger.warning(r'__proc_score failed {}'.format(e), exc_info=True)

    def __int_hw_2_str(self, HWPlatform):
        try:
            return self._hw_name_array[HWPlatform]
        except Exception as e:
            _logger.warning(r'__int_hw_2_str failed {}'.format(e), exc_info=True)
            return ''

    def GetDBSysNameByInfSysName(self, inf_sys_name):
        try:
            bFindOldVer = False
            for one_os_name in g_os_name_list:
                if one_os_name['os_name'] == inf_sys_name:
                    # 老版本号被找到。兼容处理。
                    bFindOldVer = True
                    if 0 == one_os_name['bIs64']:
                        db_system_name = 'NTX86.' + str(one_os_name['major']) + '.' + str(one_os_name['min'])
                    else:
                        db_system_name = 'NTAMD64.' + str(one_os_name['major']) + '.' + str(one_os_name['min'])
                    return db_system_name
            if bFindOldVer is not True:
                # 老版本号未找到。采用新版本号处理。
                ver_list = inf_sys_name.split('.')
                if 0 == int(ver_list[2]):
                    db_system_name = 'NTX86.' + str(int(ver_list[0])) + '.' + str(int(ver_list[1]))
                elif 9 == int(ver_list[2]):
                    db_system_name = 'NTAMD64.' + str(int(ver_list[0])) + '.' + str(int(ver_list[1]))
                else:
                    _logger.error('inf_sys_name err = {},ver_list = {}'.format(inf_sys_name, ver_list))
                    print('inf_sys_name err = {},ver_list = {}'.format(inf_sys_name, ver_list))
                    # sys.exit(0)
                    return None
                return db_system_name
            return None
        except:
            _logger.error(traceback.format_exc())  # 生成数据库
            print(traceback.format_exc())  # 生成数据库
            return None

    def NewGetOSNameList(self, inf_sys_name):
        try:
            bFindOldVer = False
            for one_os_name in g_os_name_list:
                if one_os_name['os_name'] == inf_sys_name:
                    # 老版本号被找到。兼容处理。
                    bFindOldVer = True
                    return one_os_name['major'], one_os_name['min'], one_os_name['bIs64']
            if bFindOldVer is not True:
                # 老版本号未找到。采用新版本号处理。
                ver_list = inf_sys_name.split('.')
                if 0 == int(ver_list[2]):
                    return int(ver_list[0]), int(ver_list[1]), 0
                elif 9 == int(ver_list[2]):
                    return int(ver_list[0]), int(ver_list[1]), 1
                return None, None, None
            return None, None, None
        except:
            _logger.error(traceback.format_exc())  # 生成数据库
            return None, None, None

    def IsInDelTable(self, cx, zip_path, inf_sys_name):
        try:
            db_system_name = self.GetDBSysNameByInfSysName(inf_sys_name)
            if db_system_name is None:
                return False
            hash = zip_path.split('.')[0]
            cu = cx.cursor()
            cmd = "select count(*) from del_table where del_table.hash='" + hash + "' and del_table.system_name='" + db_system_name + "'"
            _logger.debug(cmd)
            cu.execute(cmd)
            one_db = cu.fetchone()
            if one_db is None:
                return False
            if one_db[0] != 0:
                return True
            return False
        except:
            _logger.error(traceback.format_exc())  # 生成数据库
            return False

    def __check_near_and_get_db_system_name(self, cu, one_id, system_name):
        try:
            # 判定此ID是否平台驱动
            ret_list = []
            cmd = "select count(*) from id_table where  del=0 and hard_or_comp_id='" + one_id + "' and HWPlatform <> 0"
            _logger.debug(cmd)
            cu.execute(cmd)
            one_db = cu.fetchone()
            if one_db is None:
                return ret_list
            if one_db[0] != 0:
                # 平台驱动。只能扫描固定平台。
                db_system_name = self.GetDBSysNameByInfSysName(system_name)
                if db_system_name is None:
                    return ret_list
                cmd = "select * from id_table where " + self.strAname2sql('hard_or_comp_id', one_id) \
                      + "and" + self.intAname2sql('del', 0) + "and system_name like '" + db_system_name + "%'"
                _logger.debug(cmd)
                cu.execute(cmd)
                while True:
                    one_db = cu.fetchone()
                    if one_db is None:
                        break
                    ret_list.append((one_db[13], 0))
                return list(set(ret_list))

            # 非平台驱动。
            inf_max, inf_min, inf_bIs64 = self.NewGetOSNameList(system_name)
            if inf_max is not None:
                # ============================================================================================
                # 依次递减小版本号进行匹配。
                for i in range(inf_min, -1, -1):
                    if 0 == inf_bIs64:
                        db_system_name = 'NTX86.' + str(inf_max) + '.' + str(i)
                    else:
                        db_system_name = 'NTAMD64.' + str(inf_max) + '.' + str(i)
                    cmd = "select * from id_table where " + self.strAname2sql('hard_or_comp_id', one_id) \
                          + "and" + self.intAname2sql('del', 0) + "and system_name like '" + db_system_name + "%'"
                    _logger.debug(cmd)
                    cu.execute(cmd)
                    while True:
                        one_db = cu.fetchone()
                        if one_db is None:
                            break
                        ret_list.append((one_db[13], inf_min - i))

                    if 0 == inf_bIs64:
                        db_system_name = 'NT.' + str(inf_max) + '.' + str(i)
                        cmd = "select * from id_table where " + self.strAname2sql('hard_or_comp_id', one_id) \
                              + "and" + self.intAname2sql('del', 0) + "and system_name like '" + db_system_name + "%'"
                        _logger.debug(cmd)
                        cu.execute(cmd)
                        while True:
                            one_db = cu.fetchone()
                            if one_db is None:
                                break
                            ret_list.append((one_db[13], inf_min - i))

                # ============================================================================================
                # 进行等于 NTAMD64.6. 匹配，不能包含避免出现未匹配的 大于当前小版本号。NTAMD64.6.20
                if 0 == inf_bIs64:
                    db_system_name = 'NTX86.' + str(inf_max) + '.'
                else:
                    db_system_name = 'NTAMD64.' + str(inf_max) + '.'
                cmd = "select * from id_table where " + self.strAname2sql('hard_or_comp_id', one_id) \
                      + "and" + self.intAname2sql('del', 0) + "and" + self.strAname2sql('system_name',
                                                                                        db_system_name)
                _logger.debug(cmd)
                cu.execute(cmd)
                while True:
                    one_db = cu.fetchone()
                    if one_db is None:
                        break
                    ret_list.append((one_db[13], inf_min - 0))

                if 0 == inf_bIs64:
                    db_system_name = 'NT.' + str(inf_max) + '.'
                    cmd = "select * from id_table where " + self.strAname2sql('hard_or_comp_id', one_id) \
                          + "and" + self.intAname2sql('del', 0) + "and" + self.strAname2sql('system_name',
                                                                                            db_system_name)
                    _logger.debug(cmd)
                    cu.execute(cmd)
                    while True:
                        one_db = cu.fetchone()
                        if one_db is None:
                            break
                        ret_list.append((one_db[13], inf_min - 0))

                # 进行等于 NTAMD64.6 匹配，不能包含避免出现未匹配的 NTAMD64.6.20
                if 0 == inf_bIs64:
                    db_system_name = 'NTX86.' + str(inf_max)
                else:
                    db_system_name = 'NTAMD64.' + str(inf_max)
                cmd = "select * from id_table where " + self.strAname2sql('hard_or_comp_id', one_id) \
                      + "and" + self.intAname2sql('del', 0) + "and" + self.strAname2sql('system_name',
                                                                                        db_system_name)
                _logger.debug(cmd)
                cu.execute(cmd)
                while True:
                    one_db = cu.fetchone()
                    if one_db is None:
                        break
                    ret_list.append((one_db[13], inf_min - 0))

                if 0 == inf_bIs64:
                    db_system_name = 'NT.' + str(inf_max)
                    cmd = "select * from id_table where " + self.strAname2sql('hard_or_comp_id', one_id) \
                          + "and" + self.intAname2sql('del', 0) + "and" + self.strAname2sql('system_name',
                                                                                            db_system_name)
                    _logger.debug(cmd)
                    cu.execute(cmd)
                    while True:
                        one_db = cu.fetchone()
                        if one_db is None:
                            break
                        ret_list.append((one_db[13], inf_min - 0))

                # 进行等于 NTAMD64.6.. 包含匹配
                if 0 == inf_bIs64:
                    db_system_name = 'NTX86.' + str(inf_max) + '..'
                else:
                    db_system_name = 'NTAMD64.' + str(inf_max) + '..'
                cmd = "select * from id_table where " + self.strAname2sql('hard_or_comp_id', one_id) \
                      + "and" + self.intAname2sql('del', 0) + "and system_name like '" + db_system_name + "%'"
                _logger.debug(cmd)
                cu.execute(cmd)
                while True:
                    one_db = cu.fetchone()
                    if one_db is None:
                        break
                    ret_list.append((one_db[13], inf_min - 0))

                if 0 == inf_bIs64:
                    db_system_name = 'NT.' + str(inf_max) + '..'
                    cmd = "select * from id_table where " + self.strAname2sql('hard_or_comp_id', one_id) \
                          + "and" + self.intAname2sql('del', 0) + "and system_name like '" + db_system_name + "%'"
                    _logger.debug(cmd)
                    cu.execute(cmd)
                    while True:
                        one_db = cu.fetchone()
                        if one_db is None:
                            break
                        ret_list.append((one_db[13], inf_min - 0))
                        # ============================================================================================
                        # # 进行等于 NTAMD64. 匹配，不能包含避免出现未匹配的 NTAMD64.6
                        # if 0 == inf_bIs64:
                        #     db_system_name = 'NTX86.'
                        # else:
                        #     db_system_name = 'NTAMD64.'
                        # cmd = "select * from id_table where " + self.strAname2sql('hard_or_comp_id', one_id) \
                        #       + "and" + self.intAname2sql('del', 0) + "and" + self.strAname2sql('system_name',
                        #                                                                         db_system_name)
                        # _logger.debug(cmd)
                        # cu.execute(cmd)
                        # one_db = cu.fetchone()
                        # if one_db is not None:
                        #     ret_list.append((one_db[13], 20))  # 因为有大平台版本差异，返回差值增大到20
                        #
                        # if 0 == inf_bIs64:
                        #     db_system_name = 'NT.'
                        #     cmd = "select * from id_table where " + self.strAname2sql('hard_or_comp_id', one_id) \
                        #           + "and" + self.intAname2sql('del', 0) + "and" + self.strAname2sql('system_name',
                        #                                                                             db_system_name)
                        #     _logger.debug(cmd)
                        #     cu.execute(cmd)
                        #     one_db = cu.fetchone()
                        #     if one_db is not None:
                        #         ret_list.append((one_db[13], 20))  # 因为有大平台版本差异，返回差值增大到20
                        #
                        # # 进行等于 NTAMD64 匹配，不能包含避免出现未匹配的 NTAMD64.6
                        # if 0 == inf_bIs64:
                        #     db_system_name = 'NTX86'
                        # else:
                        #     db_system_name = 'NTAMD64'
                        # cmd = "select * from id_table where " + self.strAname2sql('hard_or_comp_id', one_id) \
                        #       + "and" + self.intAname2sql('del', 0) + "and" + self.strAname2sql('system_name',
                        #                                                                         db_system_name)
                        # _logger.debug(cmd)
                        # cu.execute(cmd)
                        # one_db = cu.fetchone()
                        # if one_db is not None:
                        #     ret_list.append((one_db[13], 20))  # 因为有大平台版本差异，返回差值增大到20
                        #
                        # if 0 == inf_bIs64:
                        #     db_system_name = 'NT'
                        #     cmd = "select * from id_table where " + self.strAname2sql('hard_or_comp_id', one_id) \
                        #           + "and" + self.intAname2sql('del', 0) + "and" + self.strAname2sql('system_name',
                        #                                                                             db_system_name)
                        #     _logger.debug(cmd)
                        #     cu.execute(cmd)
                        #     one_db = cu.fetchone()
                        #     if one_db is not None:
                        #         ret_list.append((one_db[13], 20))  # 因为有大平台版本差异，返回差值增大到20
                        #
                        # # 进行等于 NTAMD64.. 包含匹配
                        # if 0 == inf_bIs64:
                        #     db_system_name = 'NTX86..'
                        # else:
                        #     db_system_name = 'NTAMD64..'
                        # cmd = "select * from id_table where " + self.strAname2sql('hard_or_comp_id', one_id) \
                        #       + "and" + self.intAname2sql('del', 0) + "and system_name like '" + db_system_name + "%'"
                        # _logger.debug(cmd)
                        # cu.execute(cmd)
                        # one_db = cu.fetchone()
                        # if one_db is not None:
                        #     ret_list.append((one_db[13], 20))  # 因为有大平台版本差异，返回差值增大到20
                        # if 0 == inf_bIs64:
                        #     db_system_name = 'NT..'
                        #     cmd = "select * from id_table where " + self.strAname2sql('hard_or_comp_id', one_id) \
                        #           + "and" + self.intAname2sql('del', 0) + "and system_name like '" + db_system_name + "%'"
                        #     _logger.debug(cmd)
                        #     cu.execute(cmd)
                        #     one_db = cu.fetchone()
                        #     if one_db is not None:
                        #         ret_list.append((one_db[13], 20))  # 因为有大平台版本差异，返回差值增大到20
            return list(set(ret_list))
        except Exception as e:
            _logger.warning(r'__check_near_and_get_db_system_name failed {}'.format(e), exc_info=True)
            return []

    def __check_list_in_db(self, db_full_path, system_name, _list, inf_list_list, IsHardwardList, hw_platform_id,
                           bShowMicro=True):
        global max_inf_time
        try:
            my_list = list()
            num = 0
            with sqlite3.connect(db_full_path) as cx:
                cu = cx.cursor()
                for one_id in _list:
                    one_id = one_id.upper()
                    db_system_name_list = self.__check_near_and_get_db_system_name(cu, one_id, system_name)
                    for db_system_name, min_os_dec in db_system_name_list:
                        if db_system_name is None:
                            continue
                        cmd = "select * from id_table where " + self.strAname2sql('hard_or_comp_id', one_id) \
                              + "and" + self.intAname2sql('del', 0) + "and" + self.strAname2sql('system_name',
                                                                                                db_system_name)
                        _logger.debug(cmd)
                        cu.execute(cmd)
                        num = num + 1
                        while True:
                            one_db = cu.fetchone()
                            if one_db is None:
                                break
                            if one_db[6] is not None:
                                if -1 != one_db[6].find('不支持'):
                                    continue
                            if self.IsHwInOem(one_db[16]) is not True:
                                continue
                            if self.IsInDelTable(cx, one_db[12], system_name) is True:
                                continue
                            one_info = {'UserSelected': 0, 'hard_or_comp_id': None, 'show_name': None, 'year': 0,
                                        'mon': 0,
                                        'day': 0, 'inf_driver_ver': 0, 'inf_path': None, 'zip_path': None,
                                        'system_name': None, 'IsMicro': 0, 'HaveProcScore': 0, 'IsPlatform': 0,
                                        'Str_HWPlatform': None, 'OnlySAH256': 0, 'ForceInst': 0}
                            one_info['hard_or_comp_id'] = one_db[7]
                            one_info['system_name'] = system_name
                            one_info['show_name'] = one_db[6]
                            one_info['inf_path'] = one_db[11]
                            one_info['IsMicro'] = one_db[14]
                            one_info['zip_path'] = one_db[12]
                            one_info['Str_HWPlatform'] = self.__int_hw_2_str(one_db[16])
                            one_info['OnlySAH256'] = one_db[19]
                            if 1 == one_db[16]:
                                one_info['IsPlatform'] = 1
                            elif 0 == hw_platform_id:
                                one_info['IsPlatform'] = 0
                            elif hw_platform_id != one_db[16]:
                                one_info['IsPlatform'] = 0
                            elif one_info['IsMicro'] != 1:  # 微软驱动不能算成平台驱动。容错处理。
                                one_info['IsPlatform'] = 1
                            self.__proc_score(system_name, one_db, one_info, IsHardwardList, num, min_os_dec,
                                              one_db[20])

                            if one_db[14] == 1:
                                if bShowMicro:
                                    # one_info['year'], one_info['mon'], one_info[
                                    #     'day'] = self.__get_year_mon_day_by_inf_driver_ver(max_inf_time)
                                    # one_info['inf_driver_ver'] = max_inf_time
                                    my_list.append(one_info)
                                else:
                                    pass
                            else:
                                one_info['year'], one_info['mon'], one_info[
                                    'day'] = self.__get_year_mon_day_by_inf_driver_ver(one_db[10])
                                one_info['inf_driver_ver'] = one_db[10]
                                my_list.append(one_info)
                    # my_list.sort(key=lambda x: x['inf_driver_ver'], reverse=True)
                    inf_list_list.extend(my_list)
        except Exception as e:
            _logger.error(r'__check_list_in_db failed : {}'.format(e), exc_info=True)

    def __proc_list_score(self, inf_list_list):
        try:
            inf_list_list.sort(key=lambda x: x['inf_driver_ver'])
            count = len(inf_list_list)
            for i in range(count):
                if (0 == inf_list_list[i]['IsMicro']) or (inf_list_list[i]['IsMicro'] is None):
                    inf_list_list[i]['HaveProcScore'] = inf_list_list[i]['HaveProcScore'] + i + 1

        except Exception as e:
            _logger.warning(r'__proc_list_score failed {}'.format(e), exc_info=True)

    def chk_and_copy_drvierid_user(self):
        global db_path
        global src_user_db_path
        global user_db_path
        try:
            _logger.warning(r'chk_and_copy_drvierid_user begin')
            if not os.path.exists(user_db_path):
                shutil.copyfile(src_user_db_path, user_db_path)
                _logger.warning(r'chk_and_copy_drvierid_user if not os.path.exists(user_db_path) end')
                return
            if 0 == os.path.getsize(user_db_path):
                while True:
                    _logger.warning(r'chk_and_copy_drvierid_user if 0 == os.path.getsize(user_db_path) :will remove')
                    os.remove(user_db_path)
                    if not os.path.exists(user_db_path):
                        _logger.warning(
                            r'chk_and_copy_drvierid_user if 0 == os.path.getsize(user_db_path) :remove not find file')
                        break
                    _logger.warning(
                        r'chk_and_copy_drvierid_user if 0 == os.path.getsize(user_db_path) :remove have find file,will sleep')
                    time.sleep(1)
                shutil.copyfile(src_user_db_path, user_db_path)
                _logger.warning(r'chk_and_copy_drvierid_user if 0 == os.path.getsize(user_db_path) end')
                return
        except Exception as e:
            tb = traceback.format_exc()
            _logger.warning(r'chk_and_copy_drvierid_user failed {} {}'.format(e, tb))

    def ChkIsSubId(self, hardward_id_list, compatible_id_list):
        try:
            for one_id in hardward_id_list:
                for one_sub in self._sub_id_list:
                    if 0 == one_id.upper().find(one_sub):
                        return True
            for one_id in compatible_id_list:
                for one_sub in self._sub_id_list:
                    if 0 == one_id.upper().find(one_sub):
                        return True
            return False
        except Exception as e:
            tb = traceback.format_exc()
            _logger.warning(r'ChkIsSubId failed {} {}'.format(e, tb))
            return False

    def bcm_one_select_2_get_sub_drv_list(self, one_select):
        ret_list = list()
        try:
            _logger.warning(r'bcm_one_select_2_get_sub_drv_list one_select = {}'.format(one_select))
            dev_find_num = one_select['hard_or_comp_id'].upper().find('&DEV_')
            if -1 == dev_find_num:
                return ret_list
            dev_str = one_select['hard_or_comp_id'][dev_find_num + len('&DEV_'):dev_find_num + len('&DEV_') + 4]

            subsys_str = None
            subsys_find_num = one_select['hard_or_comp_id'].upper().find('&SUBSYS_')
            if -1 != subsys_find_num:
                subsys_str = one_select['hard_or_comp_id'][subsys_find_num + len('&SUBSYS_'):]

            # 从数据库中查询 zip 对应的其它ID
            with sqlite3.connect(db_path) as cx:
                cu = cx.cursor()
                cmd = "select * from id_table where  hard_or_comp_id like '%{}%' " \
                      "and hard_or_comp_id like '%\L2ND%' and zip_path = '{}'" \
                    .format(dev_str, one_select['zip_path'])
                # cmd = "select hard_or_comp_id,inf_path from id_table where zip_path = '" + one_select[
                #     'zip_path'] + "'"
                _logger.debug(cmd)
                cu.execute(cmd)
                test_num = 1
                while True:
                    test_num += 1
                    print('test_num = {}\n'.format(test_num))
                    one_db = cu.fetchone()
                    if one_db is None:
                        break
                    # get_one_id = one_db[0]
                    # get_inf_path = one_db[1]
                    get_one_id = one_db[7]
                    get_inf_path = one_db[11]
                    # if -1 == get_one_id.upper().find('\\L2ND'):
                    #     continue  # 诊断驱动，scsi等虚拟驱动不理会。
                    if (-1 == get_one_id.upper().find('14E4')) \
                            and (-1 == get_one_id.upper().find('1077')) \
                            and (-1 == get_one_id.upper().find('4040')):
                        continue
                    get_dev_find_num = get_one_id.upper().find('&PCI_')
                    if -1 == get_dev_find_num:
                        continue
                    get_dev_str = get_one_id[get_dev_find_num + len('&PCI_'):get_dev_find_num + len('&PCI_') + 4]
                    if dev_str.upper() != get_dev_str.upper():
                        continue
                    if subsys_str is not None:
                        get_subsys_find_num = get_one_id.upper().find('&SUBSYS_')
                        if -1 == get_subsys_find_num:
                            continue
                        get_subsys_str = get_one_id[get_subsys_find_num + len('&SUBSYS_'):]
                        if subsys_str.upper() != get_subsys_str.upper():
                            continue
                    else:
                        # 父ID 没有 '&SUBSYS_'
                        get_subsys_find_num = get_one_id.upper().find('&SUBSYS_')
                        if -1 != get_subsys_find_num:
                            # 如果子ID 查找到 '&SUBSYS_'，说明不匹配。
                            continue
                    bHaveInsert = False
                    for one in ret_list:
                        if one['hard_or_comp_id'] == get_one_id:
                            bHaveInsert = True
                            break
                    if bHaveInsert:
                        continue  # 如果已经插入就不再插入。
                    one_select_copy = copy.deepcopy(one_select)
                    one_select_copy['hard_or_comp_id'] = get_one_id
                    one_select_copy['inf_path'] = get_inf_path
                    ret_list.append(one_select_copy)
            return ret_list
        except Exception as e:
            tb = traceback.format_exc()
            _logger.warning(r'one_select_2_get_sub_drv_list failed {} {}'.format(e, tb))
            return ret_list

    def xen_one_select_2_get_sub_drv_list(self, one_select):
        ret_list = list()
        try:
            # 从数据库中查询 zip 对应的其它ID
            with sqlite3.connect(db_path) as cx:
                cu = cx.cursor()
                cmd = "select hard_or_comp_id,inf_path from id_table where zip_path = '" + one_select[
                    'zip_path'] + "'"
                _logger.debug(cmd)
                cu.execute(cmd)
                while True:
                    one_db = cu.fetchone()
                    if one_db is None:
                        break
                    get_one_id = one_db[0].upper()
                    get_inf_path = one_db[1]
                    if 0 == get_one_id.find('PCI\\'):
                        continue
                    # 非 PCI\ 开头的都是正常ID.
                    one_select_copy = copy.deepcopy(one_select)
                    one_select_copy['hard_or_comp_id'] = get_one_id
                    one_select_copy['inf_path'] = get_inf_path
                    ret_list.append(one_select_copy)
            return ret_list
        except Exception as e:
            tb = traceback.format_exc()
            _logger.warning(r'one_select_2_get_sub_drv_list failed {} {}'.format(e, tb))
            return ret_list

    def one_select_2_get_sub_drv_list(self, one_select):
        try:
            if one_select['UserSelected'] == 0:
                return []
            if -1 != one_select['hard_or_comp_id'].upper().find('PCI\\VEN_14E4'):
                return self.bcm_one_select_2_get_sub_drv_list(one_select)
            # if -1 != one_select['hard_or_comp_id'].upper().find('PCI\\VEN_fffd'):
            #     return self.xen_one_select_2_get_sub_drv_list(one_select)
            # if -1 != one_select['hard_or_comp_id'].upper().find('PCI\\VEN_5853'):
            #     return self.xen_one_select_2_get_sub_drv_list(one_select)
            # if -1 != one_select['hard_or_comp_id'].upper().find('PCI\\VEN_1AF4&DEV_1110'):
            #     return self.xen_one_select_2_get_sub_drv_list(one_select)
            return []

        except Exception as e:
            return []

    # one_info = {'UserSelected': 0, 'hard_or_comp_id': None, 'show_name': None, 'year': 0, 'mon': 0, 'day': 0,
    #             'inf_driver_ver': 0, 'inf_path': None, 'zip_path': None, 'system_name': None, 'IsMicro': 0,
    #             'HaveProcScore': 0, 'IsPlatform': 0, 'Str_HWPlatform': None, 'OnlySAH256': 0,'ForceInst':0}
    def get_drive_list(self, system_name, sys_bit, hardward_id_list, compatible_id_list, hw_platform_id=0,
                       bShowMicro=True):
        global db_path
        global user_db_path
        try:
            _logger.warning(r'get_drive_list hardward_id_list = {}'.format(hardward_id_list))
            _logger.warning(r'get_drive_list compatible_id_list = {}'.format(compatible_id_list))
            _logger.warning(r'get_drive_list system_name = {},hw_platform_id = {},bShowMicro = {}'
                            .format(system_name, hw_platform_id, bShowMicro))
            inf_list_list = []
            self.chk_and_copy_drvierid_user()
            # inf_list_ret_list = []
            _logger.warning(r'get_drive_list __check_list_in_db 1 will open db = {}'.format(user_db_path))
            self.__check_list_in_db(user_db_path, system_name, hardward_id_list, inf_list_list, True, hw_platform_id,
                                    bShowMicro)
            _logger.warning(r'get_drive_list __check_list_in_db 2 will open db = {}'.format(user_db_path))
            self.__check_list_in_db(user_db_path, system_name, compatible_id_list, inf_list_list, False, hw_platform_id,
                                    bShowMicro)
            _logger.warning(r'get_drive_list __check_list_in_db 1 will open db = {}'.format(db_path))
            self.__check_list_in_db(db_path, system_name, hardward_id_list, inf_list_list, True, hw_platform_id,
                                    bShowMicro)
            _logger.warning(r'get_drive_list __check_list_in_db 2 will open db = {}'.format(db_path))
            self.__check_list_in_db(db_path, system_name, compatible_id_list, inf_list_list, False, hw_platform_id,
                                    bShowMicro)
            _logger.warning(r'get_drive_list find list = {}'.format(inf_list_list))
            # 从后往前删除相同inf的驱动。
            while True:
                del_num = 0
                count = len(inf_list_list)
                for i in range(0, count - 1, 1):
                    for j in range(count - 1, i, -1):
                        if (inf_list_list[i]['zip_path'] == inf_list_list[j]['zip_path']) and (
                                inf_list_list[i]['Str_HWPlatform'] == inf_list_list[j]['Str_HWPlatform']):
                            del_num = j
                            break
                    if del_num != 0:
                        break
                if del_num == 0:
                    break
                else:
                    del inf_list_list[del_num]
            _logger.warning(r'get_drive_list find list have del same inf = {}'.format(inf_list_list))
            self.__proc_list_score(inf_list_list)
            inf_list_list.sort(key=lambda x: x['HaveProcScore'], reverse=True)
            _logger.warning(r'get_drive_list end inf = {}'.format(inf_list_list))
            # 先把微软驱动的，添加到返回列表。
            # for one in inf_list_list:
            #     if one['IsMicro'] == 1:
            #         inf_list_ret_list.append(one)
            # _logger.warning(r'get_drive_list retnrn 1 = {}'.format(inf_list_ret_list))
            # # 再返回普通驱动
            # for one in inf_list_list:
            #     if one['inf_driver_ver'] != max_inf_time:
            #         inf_list_ret_list.append(one)
            # _logger.warning(r'get_drive_list retnrn 2 = {}'.format(inf_list_ret_list))
            return inf_list_list
        except Exception as e:
            tb = traceback.format_exc()
            xlogging.raise_system_error(r'获取设备驱动程序列表失败', r'get_drive_list {} {} failed {} {}'
                                        .format(hardward_id_list, compatible_id_list, e, tb), 0,
                                        _logger)

    def _search_id_in_not_know_charset_file(self, hardward_id_list, compatible_id_list, inf_path, tmp_path):
        charset_name = self._get_file_charset(inf_path)
        self._search_id_by_charset_name(hardward_id_list, compatible_id_list, charset_name, inf_path, tmp_path)
        # if 'UTF-16LE' == charset_name:
        #     self._search_id_by_charset_name(hardward_id_list, compatible_id_list, charset_name, inf_path, tmp_path)
        # elif 'ascii' == charset_name:
        #     self._search_id_by_charset_name(hardward_id_list, compatible_id_list, charset_name, inf_path, tmp_path)
        # elif 'UTF-8-SIG' == charset_name:
        #     self._search_id_by_charset_name(hardward_id_list, compatible_id_list, charset_name, inf_path, tmp_path)
        # else:
        #     _logger.warning(r'unsupport charset {} in {}'.format(charset_name, inf_path))

    def _search_id_by_charset_name(self, hardward_id_list, compatible_id_list, charset_name, inf_path, tmp_path):
        try:
            with open(inf_path, 'r', 1, charset_name) as file_obj:
                while True:
                    try:
                        one_line = file_obj.readline()
                        if one_line:
                            # print(one_line)
                            for one_id in hardward_id_list:
                                # _logger.warning(r'search id = {}'.format(one_id))
                                if self._bool_get_clean_sub_str_by_line(one_line, one_id):
                                    self._copy_inf_dir_and_gen_install_drv_str_and_time(one_id, inf_path, tmp_path,
                                                                                        charset_name)
                                    return

                            for one_id in compatible_id_list:
                                # _logger.warning(r'search id = {}'.format(one_id))
                                if self._bool_get_clean_sub_str_by_line(one_line, one_id):
                                    self._copy_inf_dir_and_gen_install_drv_str_and_time(one_id, inf_path, tmp_path,
                                                                                        charset_name)
                                    return
                        else:
                            break
                    except Exception as e:
                        _logger.warning(r'unsupport charset line {} in {}. {}'.format(
                            charset_name, inf_path, charset_name, e))
                        continue
            return
        except Exception as e:
            _logger.warning(r'unsupport charset {} in {}. {}'.format(charset_name, inf_path, charset_name, e))

    def _copy_inf_dir_and_gen_install_drv_str_and_time(self, one_id, inf_path, tmp_path, charset_name):
        try:
            # 获取src_path的源目录。
            src_dir = os.path.dirname(inf_path)
            new_des_path = os.path.join(tmp_path, src_dir[len(self._driver_pool_dir) + 1:])
            # 删除目标路径目录。
            # shutil.rmtree(new_des_path, True)
            # 拷贝源目录到目标路径目录。
            dir_util.copy_tree(src_dir, new_des_path)
            # 建立配置文件。
            ini_des_path_str_1 = new_des_path[len(self._tmp_dir):]
            ini_des_path = "." + ini_des_path_str_1 + "/" + os.path.basename(inf_path)
            _logger.info('_copy_inf_dir_and_gen_install_drv_str_and_time : {}'.format(ini_des_path))
            # 读取inf 内部版本号结中的时间。
            with open(inf_path, 'r', 1, charset_name) as file_obj:
                while True:
                    try:
                        one_line = file_obj.readline()
                        if one_line:
                            if 0 != one_line.find("DriverVer"):
                                continue
                            start_num = one_line.find("=")
                            end_num = one_line.find(",")
                            if -1 == start_num:
                                continue
                            if -1 == end_num:
                                continue
                            if start_num >= end_num:
                                continue
                            str_inf_of_time = one_line[start_num + 1:end_num]
                            mon = int(str_inf_of_time[0:str_inf_of_time.find("/")])
                            str_inf_of_time = str_inf_of_time[str_inf_of_time.find("/") + 1:]
                            day = int(str_inf_of_time[0:str_inf_of_time.find("/")])
                            year = int(str_inf_of_time[str_inf_of_time.find("/") + 1:])
                            all_day = year * 365 + mon * 30 + day
                            inf_list = list()
                            inf_list.append(ini_des_path)
                            inf_list.append(all_day)
                            inf_list.append(one_id)
                            self._inf_list_list.append(inf_list)
                            break
                        else:
                            break
                    except Exception as e:
                        continue
        except Exception as e:
            tb = traceback.format_exc()
            _logger.warning(r'_copy_inf_dir_and_gen_install_drv_str_and_time failed {} {}'.format(e, tb))

    @staticmethod
    def _bool_get_clean_sub_str_by_line(one_line, one_id):
        try:
            split_char = [' ', ',', '.', ':', '|', "'", '"', '.', '`', '(', ')', '#', '[', ']', '{', '}', '<', '>', ';']
            find_start = one_line.upper().find(one_id.upper())
            find_end = find_start + len(one_id)
            if -1 == find_start:
                return False
            # 判断头部，头部除空格，字符串起始，不能有其他字符。
            if 0 != find_start:
                bFindFirst = False
                for i in split_char:
                    if one_line[find_start - 1] == i:
                        bFindFirst = True
                        break
                if bFindFirst is False:
                    return False
            # 判断尾部，尾部除空格，字符串结束，'\r','\n'之外不能有其他字符。
            if find_end == len(one_line):
                return True
            if one_line[find_end] == '\r':
                return True
            if one_line[find_end] == '\n':
                return True
            for i in split_char:
                if one_line[find_end] == i:
                    return True
            return False
        except Exception as e:
            tb = traceback.format_exc()
            _logger.warning(r'_bool_get_clean_sub_str_by_line failed {} {}'.format(e, tb))
            return False

    @staticmethod
    def _get_file_charset(file_path):
        with open(file_path, 'rb') as file_obj:
            data = file_obj.read(10)
            return chardet.detect(data)['encoding']

    # def add_ip(self, hardward_id_list, NameServer, IPAddress_List, SubnetMask_List, DefaultGateway_List):
    #     try:
    #         with open(os.path.join(self._tmp_dir, install_reg), 'a+', encoding='utf-8') as out_put:
    #             write_str = "    set_ip_by_hardwrd_id_list("
    #             write_str = write_str + self._str_list_to_one_str(hardward_id_list) + ","
    #             write_str = write_str + self._str_to_one_str(NameServer) + ","
    #             write_str = write_str + self._str_list_to_one_str(IPAddress_List) + ","
    #             write_str = write_str + self._str_list_to_one_str(SubnetMask_List) + ","
    #             write_str = write_str + self._str_list_to_one_str(DefaultGateway_List) + ")\r\n"
    #             out_put.write(write_str)
    #     except Exception as e:
    #         tb = traceback.format_exc()
    #         xlogging.raise_system_error(r'添加IP配置失败', r'add_ip failed {} {}'.format(e, tb), 0, _logger)
    #
    # def add_ip_by_local(self, szDeviceInstanceID, NameServer, IPAddress_List, SubnetMask_List, DefaultGateway_List):
    #     try:
    #         with open(os.path.join(self._tmp_dir, install_reg), 'a+', encoding='utf-8') as out_put:
    #             write_str = "    set_ip_by_hardwrd_id_list_by_local("
    #             write_str = write_str + self._str_to_one_str(szDeviceInstanceID) + ","
    #             write_str = write_str + self._str_to_one_str(NameServer) + ","
    #             write_str = write_str + self._str_list_to_one_str(IPAddress_List) + ","
    #             write_str = write_str + self._str_list_to_one_str(SubnetMask_List) + ","
    #             write_str = write_str + self._str_list_to_one_str(DefaultGateway_List) + ")\r\n"
    #             out_put.write(write_str)
    #     except Exception as e:
    #         tb = traceback.format_exc()
    #         xlogging.raise_system_error(r'添加IP配置失败', r'add_ip failed {} {}'.format(e, tb), 0, _logger)

    def _str_list_to_one_str(self, user_list, quot='"'):
        out_str = "["
        try:
            for i in user_list:
                out_str = out_str + self._str_to_one_str(i, quot) + ","
            if out_str[-1] == ',':
                out_str = out_str[0:len(out_str) - 1]
            return out_str + "]"
        except Exception as e:
            _logger.error(r'_str_list_to_one_str failed {}'.format(e), exc_info=True)
            raise e

    def _one_to_list_to_one_str(self, one_str, quot='"'):
        user_list = list()
        user_list.append(one_str)
        return self._str_list_to_one_str(user_list, quot)

    @staticmethod
    def _str_to_one_str(str, quot='"'):
        if str is None:
            out_str = quot + quot
            return out_str
        if 0 == len(str):
            out_str = quot + quot
            return out_str
        out_str = "r" + quot + str + quot
        return out_str

    # def add_ip_hardware(self, one_ip_list):
    #     try:
    #         _logger.warning(r'add_ip_hardware one_ip_list = {}'.format(one_ip_list))
    #         with open(os.path.join(self._tmp_dir, install_reg), 'a+') as out_put:
    #             write_str = "    save_dev_reg_info("
    #             list_str = ''
    #             for one in one_ip_list:
    #                 one_str = self._str_to_one_str(one['NameGUID']) + ","
    #                 one_str = one_str + self._str_to_one_str(one['LocationInformation']) + ","
    #                 one_str = one_str + self._str_list_to_one_str(one['HardwareID']) + ","
    #                 one_str = one_str + str(one['UINumber']) + ","
    #                 one_str = one_str + str(one['Address']) + ","
    #                 one_str = one_str + self._str_to_one_str(one['ContainerID']) + ","
    #                 one_str = one_str + self._str_to_one_str(one['Service'])
    #                 one_str = '(' + one_str + ')'
    #                 list_str = list_str + one_str + ','
    #             list_str = '[' + list_str.strip(',') + ']'
    #             write_str = write_str + list_str + ")\r\n"
    #             out_put.write(write_str)
    #     except Exception as e:
    #         tb = traceback.format_exc()
    #         xlogging.raise_system_error(r'添加IP配置关联硬件失败', r'add_ip_hardware failed {} {}'
    #                                     .format(e, tb), 0, _logger)
    #
    # def add_ip_hardware_by_local(self, one_ip_list):
    #     try:
    #         _logger.warning(r'add_ip_hardware_by_local one_ip_list = {}'.format(one_ip_list))
    #         with open(os.path.join(self._tmp_dir, install_reg), 'a+') as out_put:
    #             write_str = "    save_dev_reg_info_by_local("
    #             list_str = ''
    #             for one in one_ip_list:
    #                 one_str = self._str_to_one_str(one['NameGUID']) + ","
    #                 one_str = one_str + self._str_to_one_str(one['LocationInformation']) + ","
    #                 one_str = one_str + self._str_list_to_one_str(one['HardwareID']) + ","
    #                 one_str = one_str + str(one['UINumber']) + ","
    #                 one_str = one_str + str(one['Address']) + ","
    #                 one_str = one_str + self._str_to_one_str(one['ContainerID']) + ","
    #                 one_str = one_str + self._str_to_one_str(one['Service']) + ","
    #                 one_str = one_str + self._str_to_one_str(one['szDeviceInstanceID'])
    #                 one_str = '(' + one_str + ')'
    #                 list_str = list_str + one_str + ','
    #             list_str = '[' + list_str.strip(',') + ']'
    #             write_str = write_str + list_str + ")\r\n"
    #             out_put.write(write_str)
    #     except Exception as e:
    #         tb = traceback.format_exc()
    #         xlogging.raise_system_error(r'添加IP配置关联硬件失败', r'add_ip_hardware failed {} {}'
    #                                     .format(e, tb), 0, _logger)

    def add_ip_v2(self, szDeviceInstanceID, hardward_id_list, NameServer, IPAddress_List, SubnetMask_List,
                  DefaultGateway_List, one_ip_to_nadrv_list, nic_name, mtu):
        try:
            _logger.warning(r'add_ip_v2 szDeviceInstanceID = {}'.format(szDeviceInstanceID))
            _logger.warning(r'add_ip_v2 hardward_id_list = {}'.format(hardward_id_list))
            _logger.warning(r'add_ip_v2 NameServer = {}'.format(NameServer))
            _logger.warning(r'add_ip_v2 IPAddress_List = {}'.format(IPAddress_List))
            _logger.warning(r'add_ip_v2 SubnetMask_List = {}'.format(SubnetMask_List))
            _logger.warning(r'add_ip_v2 DefaultGateway_List = {}'.format(DefaultGateway_List))
            _logger.warning(r'add_ip_v2 one_ip_to_nadrv_list = {}'.format(one_ip_to_nadrv_list))
            _logger.warning(r'add_ip_v2 nic_name = {}'.format(nic_name))
            _logger.warning(r'add_ip_v2 mtu = {}'.format(mtu))
            context = {'mtu': mtu}
            with open(os.path.join(self._tmp_dir, install_reg), 'a+', encoding='utf-8') as out_put:
                write_str = "    add_ip_v2("
                write_str = write_str + self._str_to_one_str(szDeviceInstanceID) + ","
                write_str = write_str + self._str_list_to_one_str(hardward_id_list) + ","
                write_str = write_str + self._str_to_one_str(NameServer) + ","
                write_str = write_str + self._str_list_to_one_str(IPAddress_List) + ","
                write_str = write_str + self._str_list_to_one_str(SubnetMask_List) + ","
                write_str = write_str + self._str_list_to_one_str(DefaultGateway_List) + ","
                write_str = write_str + self._str_to_one_str(nic_name) + ","
                write_str = write_str + json.dumps(context) + ","

                list_str = ''
                for one in one_ip_to_nadrv_list:
                    one_str = self._str_to_one_str(one['NameGUID']) + ","
                    one_str = one_str + self._str_to_one_str(one['LocationInformation']) + ","
                    one_str = one_str + self._str_list_to_one_str(one['HardwareID']) + ","
                    one_str = one_str + str(one['UINumber']) + ","
                    one_str = one_str + str(one['Address']) + ","
                    one_str = one_str + self._str_to_one_str(one['ContainerID']) + ","
                    one_str = one_str + self._str_to_one_str(one['Service']) + ","
                    one_str = one_str + self._str_to_one_str(one['szDeviceInstanceID'])
                    one_str = '(' + one_str + ')'
                    list_str = list_str + one_str + ','
                list_str = '[' + list_str.strip(',') + ']'
                write_str = write_str + list_str + ")\r\n"
                out_put.write(write_str)
        except Exception as e:
            tb = traceback.format_exc()
            xlogging.raise_system_error(r'添加IP配置失败', r'add_ip failed {} {}'.format(e, tb), 0, _logger)

    def create_agent_service_configs(self, cfgs):
        try:
            cfg_path = os.path.join(self._tmp_dir, 'agentServiceCfg.txt')
            with open(cfg_path, 'w') as p:
                json.dump(cfgs, p)
            _logger.debug('create agent_cfg_file ,filepath:{}'.format(cfg_path))
        except Exception as e:
            tb = traceback.format_exc()
            xlogging.raise_system_error(r'生成客户端配置文件失败', r'create_agent_service_configs failed {} {}'
                                        .format(e, tb), 0, _logger)

    def create_non_master_nics_configs_in_iso(self, nics_cfgs):
        try:
            iso_nics_cfg = os.path.join(self._tmp_dir, 'ht.json')
            with open(iso_nics_cfg, 'wt') as fout:
                if nics_cfgs:
                    json.dump(nics_cfgs, fout)
                else:
                    fout.write('')
            _logger.debug('create_non_master_nics_configs_in_iso ,filepath: {}'.format(iso_nics_cfg))
        except Exception as e:
            tb = traceback.format_exc()
            xlogging.raise_system_error(r'在光盘内创建非主网卡配置文件失败',
                                        r'create_non_master_nics_configs_in_iso failed {} {}'.format(e, tb), 0, _logger)

    def make(self):
        for root, dirs, files in os.walk(self._tmp_dir):
            for f in files:
                try:
                    by = bytes(f, 'utf-8')
                except UnicodeEncodeError:
                    file_path = os.path.join(root, f)
                    os.remove(file_path)
                    _logger.warning(r'delete some file with invalid name')
                    _logger.warning(file_path)
                    continue

        try:
            cmd = "mkisofs -o " + self._iso_file_path + " -udf -R -A -V -v " + self._tmp_dir
            status = os.system(cmd)
            if status != 0:
                xlogging.raise_system_error(r'生成ISO文件失败', r'make {} failed {}'.format(cmd, status), 0, _logger)
            os.system(r'rm -rf {}'.format(self._tmp_dir))
        except Exception as e:
            tb = traceback.format_exc()
            xlogging.raise_system_error(r'生成ISO失败', r'make failed {} {}'.format(e, tb), 0, _logger)


if __name__ == "__main__":
    global db_path
    global src_user_db_path
    global user_db_path
    global cfg_oem_path
    cfg_oem_path = r'o:\driver_pool\db_oem.cfg'
    db_path = r'O:\driver_pool\uploadtosqldb\drvierid.db'
    src_user_db_path = r'O:\work\code\aio\box_dashboard\xdashboard\handle\drvierid_user.db'
    user_db_path = r'O:\driver_pool\drvierid_user.db'
    print('pe_stage_iso.py start')
    iso_maker = IsoMaker(r'O:\work\code\aio\restore-iso', r'o:\driver_pool\driver_pool_update', r'o:\driver_pool\tmp',
                         r'o:\driver_pool\iso')
    # iso_maker.add_drive('05.02.09.03', 64,
    #                     ['PCI\\VEN_1AF4&DEV_1000&SUBSYS_00011AF4&REV_00', 'PCI\\VEN_1AF4&DEV_1000&SUBSYS_00011AF4',
    #                      'PCI\\VEN_1AF4&DEV_1000&CC_020000', 'PCI\\VEN_1AF4&DEV_1000&CC_0200'],
    #                     ['PCI\\VEN_1AF4&DEV_1000&REV_00', 'PCI\\VEN_1AF4&DEV_1000', 'PCI\\VEN_1AF4&CC_020000',
    #                      'PCI\\VEN_1AF4&CC_0200', 'PCI\\VEN_1AF4', 'PCI\\CC_020000', 'PCI\\CC_0200'],
    #                     [{'show_name': 'Red Hat VirtIO Ethernet Adapter', 'year': 2015, 'system_name': '05.02.09.03',
    #                       'Str_HWPlatform': 'Virtio', 'OnlySAH256': 0,
    #                       'inf_path': '05.02.09/HWPlatform/10/virtio/netkvm.inf', 'HaveProcScore': 6352641,
    #                       'zip_path': '56e13f8f354f08d1deb57efa3c2046991e2c79b2.zip', 'day': 10, 'IsPlatform': 0,
    #                       'hard_or_comp_id': 'PCI\\VEN_1AF4&DEV_1000&SUBSYS_00011AF4&REV_00',
    #                       'inf_driver_ver': 20150810, 'UserSelected': 1, 'mon': 8, 'IsMicro': 0}])
    iso_maker.copy_default_files()
    # iso_maker.add_ip_by_local('以太网', '8.8.8.8,4.4.4.4', ['172.16.6.61', '192.168.6.61'],
    #                           ['255.255.0.0', '255.255.255.0'], '172.16.1.1')
    # hw1 = r'PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01'
    # hw2 = r'PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD'
    # hw3 = r'PCI\VEN_15AD&DEV_07B0&CC_020000'
    # hw4 = r'PCI\VEN_15AD&DEV_07B0&CC_0200'
    #
    # cm1 = r'PCI\VEN_15AD&DEV_07B0&REV_01'
    # cm2 = r'PCI\VEN_15AD&DEV_07B0'
    # cm3 = r'PCI\VEN_15AD&CC_020000'
    # cm4 = r'PCI\VEN_15AD&CC_0200'
    # cm5 = r'PCI\VEN_8086'
    # cm6 = r'PCI\CC_01018A'
    # cm7 = r'PCI\CC_0101'

    hw1 = 'PCI\VEN_14E4&DEV_164C&SUBSYS_164C14E4&REV_12'
    hw2 = 'PCI\\VEN_14E4&DEV_164C&SUBSYS_164C14E4'
    hw3 = 'PCI\\VEN_14E4&DEV_164C&CC_020000'
    hw4 = 'PCI\\VEN_14E4&DEV_164C&CC_0200'

    cm1 = 'PCI\\VEN_14E4&DEV_164C&REV_12'
    cm2 = 'PCI\\VEN_14E4&DEV_164C'
    cm3 = 'PCI\\VEN_14E4&CC_020000'
    cm4 = 'PCI\\VEN_14E4&CC_0200'
    cm4 = 'PCI\VEN_14E4'
    cm5 = 'PCI\\CC_020000'
    cm6 = 'PCI\\CC_0200'
    #
    # print(iso_maker.ChkIsSubId([hw1, hw2, hw3, hw4], [cm1, cm2, cm3, cm4]))
    # print(iso_maker.ChkIsSubId(['B06BDRV\\aaa'], []))
    # print(iso_maker.ChkIsSubId(['XENVIF\\aaa'], []))
    #
    get_drv_list = iso_maker.get_drive_list('06.01.09.00', '64', [hw1, hw2, hw3, hw4], [cm1, cm2, cm3, cm4, cm5, cm6],
                                            0)
    get_drv_list[0]['UserSelected'] = 0
    get_drv_list[1]['UserSelected'] = 1
    get_drv_list[2]['UserSelected'] = 1
    iso_maker.add_drive('06.01.09.00', 64, [hw1, hw2, hw3, hw4], [cm1, cm2, cm3, cm4, cm5, cm6], get_drv_list, 0)
    # ret_list = iso_maker.one_select_2_get_sub_drv_list(get_drv_list[0])
    # print(ret_list)

    # hw1 = r'PCI\VEN_14E4&DEV_1639'
    # get_drv_list = iso_maker.get_drive_list('05.02.09.00', '64', [hw1], [], 0)
    # get_drv_list[0]['UserSelected'] = 1
    # ret_list = iso_maker.one_select_2_get_sub_drv_list(get_drv_list[0])
    # print(ret_list)

    # iso_maker.get_drive_list('05.02.09.03', '64',
    #                          ['PCI\\VEN_1000&DEV_0030&SUBSYS_197615AD&REV_01', 'PCI\\VEN_1000&DEV_0030&SUBSYS_197615AD',
    #                           'PCI\\VEN_1000&DEV_0030&CC_010000', 'PCI\\VEN_1000&DEV_0030&CC_0100'],
    #                          ['PCI\\VEN_1000&DEV_0030&REV_01', 'PCI\\VEN_1000&DEV_0030', 'PCI\\VEN_1000&CC_010000',
    #                           'PCI\\VEN_1000&CC_0100', 'PCI\\VEN_1000', 'PCI\\CC_010000', 'PCI\\CC_0100'])
    # get_drv_list = iso_maker.get_drive_list('06.02.00.03', '32', ['PCI\VEN_1AF4&DEV_1041&SUBSYS_11001AF4&REV_01'],
    #                                         ['PCI\VEN_1AF4&DEV_1041&SUBSYS_11001AF4&REV_01'])
    # get_drv_list[0]['UserSelected'] = 1
    # iso_maker.add_drive('6_3_X64', 64, ['PCI\VEN_19A2&DEV_0222'], [], get_drv_list, 0)

    # iso_maker.add_drive('6_3_X64', 64, ['VMBUS\\{992aeca7-0aa8-423d-bac8-ecf60daa66d2}',
    #                                     'VMBUS\\{ba6163d9-04a1-4d29-b605-72e2ffb1dc7f}'],
    #                     ['VMBUS\\{ba6163d9-04a1-4d29-b605-72e2ffb1dc7f}'], [], 4)
    # iso_maker.install_system_driver(
    #     ['VMBUS\\{992aeca7-0aa8-423d-bac8-ecf60daa66d2}', 'VMBUS\\{ba6163d9-04a1-4d29-b605-72e2ffb1dc7f}'],
    #     ['VMBUS\\{ba6163d9-04a1-4d29-b605-72e2ffb1dc7f}'])

    hw1 = r'PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01'
    hw2 = r'PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD'
    hw3 = r'PCI\VEN_15AD&DEV_07B0&CC_020000'
    hw4 = r'PCI\VEN_15AD&DEV_07B0&CC_0200'

    one_ip_list = list()
    one_ip = {'NameGUID': '1212121', 'LocationInformation': '123231',
              'HardwareID': [hw1, hw2, hw3, hw4],
              'UINumber': 11, 'Address': 111, 'ContainerID': r'', 'Service': 'aa',
              'szDeviceInstanceID': r'PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\FF290C0092C195FE00'}
    one_ip_list.append(one_ip)
    one_ip = {'NameGUID': None, 'LocationInformation': '123232',
              'HardwareID': [r'PCI\VEN_1000&DEV_0054&SUBSYS_197615AD&REV_01',
                             r'PCI\VEN_1000&DEV_0054&SUBSYS_197615AD', r'PCI\VEN_1000&DEV_0054&CC_010700',
                             r'PCI\VEN_1000&DEV_0054&CC_0107'],
              'UINumber': 12, 'Address': -1, 'ContainerID': r'a', 'Service': 'aa',
              'szDeviceInstanceID': r'PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\FF290C0092C195FE00'}
    one_ip_list.append(one_ip)
    one_ip = {'NameGUID': '1212123', 'LocationInformation': '123233',
              'HardwareID': [r'PCI\VEN_15AD&DEV_07A0', r'PCI\VEN_15AD&DEV_07A0&SUBSYS_07A015AD'],
              'UINumber': 13, 'Address': 113, 'ContainerID': r'b', 'Service': 'aa',
              'szDeviceInstanceID': r'PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\FF290C0092C195FE00'}
    one_ip_list.append(one_ip)
    iso_maker.add_ip_v2(r'PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\FF290C0092C195FE00', [hw1, hw2, hw3, hw4],
                        '8.8.8.8,4.4.4.4', ['172.16.6.61', '192.168.6.61'],
                        ['255.255.0.0', '255.255.255.0'], ['172.16.1.1'], one_ip_list, 'ha1')
    # iso_maker.add_ip_v2(r'PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\FF', [hw1, hw2, hw3, hw4],
    #                     '8.8.8.8,4.4.4.4', ['172.16.6.61', '192.168.6.61'],
    #                     ['255.255.0.0', '255.255.255.0'], ['172.16.1.1'], one_ip_list, '')

    # iso_maker.add_ip_hardware(one_ip_list)
    # iso_maker.add_ip_v2('以太网', '8.8.8.8,4.4.4.4', ['172.16.6.61', '192.168.6.61'],
    #                     ['255.255.0.0', '255.255.255.0'], '172.16.1.1')

    print('search end')
    # iso_maker.make()
