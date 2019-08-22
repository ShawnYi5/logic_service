import fnmatch
import itertools
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from functools import wraps

import Ice

import BackupOptimize
import InstallLinuxAgent
import merge_hash_core
import all_big_mm
import archive
import authCookies
import bitmap
import cdpFile
import cluster_diff_images
import hostSession
import kvm
import kvm_host
import kvm_linux
import nbd
import net_base
import net_common
import passwd_set
import pe_stage_iso
import qcow_helper
import samba
import store_manage
import xlogging
from file_backup import file_backup_mgr
from kvm_shell import kvm_shell_mgr
from media import media_objects
import generate_cluster_diff_qcow

_g = None
_logger = xlogging.getLogger(__name__)
_net_setting_locker = threading.Lock()
_store_manage_locker = threading.Lock()
_store_manage = None
_last_enum_storage_nodes = None
_sync_threading = None

import Box
import BoxLogic
import IMG
import Utils
from myfilesystem import getRawDiskFiles
from kvm_msrs import ignore_kvm_msrs

g_LinuxAgentPacket = '/var/www/static/download/client/linux/aio.tar.gz'


def _get_property_as_int(key_name):
    global _g
    return _g.communicator.getProperties().getPropertyAsInt(key_name)


def block(filename):
    def _wrap(func):
        @wraps(func)
        def work_fun(*args, **kwargs):
            while os.path.exists(filename):
                _logger.warning('{} block until {} not exists!'.format(func.__name__, filename))
                time.sleep(5)
            return func(*args, **kwargs)

        return work_fun

    return _wrap


class LogicI(BoxLogic.Logic):
    def __init__(self):
        global _logger
        _logger.info(r'LogicI start ...')
        xlogging.TraceDecorator(['refreshSnapshotToken', 'QueryJsonData']).decorate()
        xlogging.ExceptionHandlerDecorator().decorate()

    def ping(self, current=None):
        global _logger
        _logger.debug(r'~~~ping~~~')

    def queryHostName(self, ident, info, current=None):
        info_object = json.loads(info)
        computer_name = '未知的客户端'
        if ('System' in info_object.keys()) and ('ComputerName' in info_object['System'].keys()) and \
                (len(info_object['System']['ComputerName'].strip()) > 0):
            computer_name = info_object['System']['ComputerName'].strip()

        user_ident = info_object.get('UserIdent', 'none_user_ident').strip()
        if len(user_ident) == 0:
            user_ident = 'empty_user_ident'

        # 修正长mac
        nics = info_object['Nic']
        if nics:
            for nic in nics:
                if nic['Mac'] is not None:
                    nic['Mac'] = nic['Mac'][0:17]
        macs = ident.Hardware
        if macs:
            for key, mac in enumerate(macs):
                macs[key] = macs[key][0:12]

        return hostSession.http_query_host_name(ident, computer_name, user_ident,
                                                json.dumps(info_object, ensure_ascii=False))

    def login(self, hostName, remoteAddress, localAddress, tunnelIndex, current=None):
        return hostSession.http_login(hostName, remoteAddress, localAddress, tunnelIndex)

    def logout(self, hostName, current=None):
        hostSession.http_logout(hostName)

    def queryHostSoftIdent(self, hostName, current=None):
        return hostSession.http_query_host_soft_ident(hostName)

    def clearAllHostSession(self, current=None):
        hostSession.http_clear_all()
        hostSession.http_pe_host_clear_all()

    def reportAgentModuleError(self, hostName, ame, current=None):
        hostSession.http_report_agent_module_error(hostName, ame)

    def reportBackupProgress(self, hostName, progress, current=None):
        hostSession.http_report_backup_progress(hostName, progress)

    def reportBackupFinish(self, hostName, code, current=None):
        hostSession.http_report_backup_finish(hostName, code)

    def reportVolumeRestoreStatus(self, pe_host, code, msg, debug, current=None):
        hostSession.http_report_volume_restore(pe_host, code, msg, debug)

    def peLogin(self, info, remoteAddress, localAddress, tunnelIndex, more_info, current=None):
        more_info = json.loads(more_info) if (more_info and isinstance(more_info, str)) else None
        return hostSession.http_pe_host_login(
            info.diskInfos, remoteAddress, localAddress, info.bootDiskId, info.loginType, tunnelIndex, more_info)

    def peLogout(self, pe_ident, current=None):
        hostSession.http_pe_host_logout(pe_ident)

    def updateCDPToken(self, token, lastFilePath, current=None):
        hostSession.http_get_cdp_new_name(token, lastFilePath)

    def closeCDPToken(self, token, current=None):
        hostSession.http_close_cdp_token(token)

    def refreshSnapshotToken(self, token, current=None):
        hostSession.http_refresh_token(token)

    def reportRestoreStatus(self, token, progress, finished, hostIdent, current=None):
        host_ident = hostIdent if (hostIdent and isinstance(hostIdent, str)) else None
        hostSession.http_report_restore_status(token, progress, finished, host_ident)

    def updateRestoreToken(self, updateConfig, current=None):
        token = json.loads(updateConfig)['token']
        hostSession.http_update_restore_token(token)

    def startKvm(self, pe_ident, current=None):
        hostSession.http_start_kvm(pe_ident)

    def updateTrafficControl(self, token, io_session, current=None):
        hostSession.http_update_traffic_control(token, io_session)

    def fetchProxyEndPoints(self, current=None):
        hostSession.http_fetch_proxy_endpoints()

    def queryLastCdpDetailByRestoreToken(self, token, current=None):
        json_data = hostSession.http_query_last_cdp_detail_by_restore_token(token)
        return BoxLogic.LastCdpDetail(
            json_data['cdp_token'], json_data['cdp_timestamp_seconds'], json_data['cdp_timestamp_microseconds'])

    def queryNetworkTransmissionType(self, info, current=None):
        user_ident = info.strip()
        if len(user_ident) == 0:
            user_ident = 'empty_user_ident'

        return hostSession.http_query_network_transmission_type(user_ident)

    def dataQueuingReport(self, jsonContent, current=None):
        return hostSession.http_data_queuing_report(jsonContent)

    def queryLastCdpDetailByCdpToken(self, token2id_str, hostName, current=None):
        assert '|' in token2id_str
        token2id = token2id_str.split('|')
        returned, json_data = hostSession.http_query_last_cdp_detail_by_cdp_token(token2id[0], hostName, token2id[1])
        detail = BoxLogic.LastCdpDetail(
            json_data['cdp_token'], json_data['cdp_timestamp_seconds'], json_data['cdp_timestamp_microseconds'])
        return returned, detail

    def VmwareAgentReport(self, jsonContent, current=None):
        return hostSession.http_vmware_agent_report(jsonContent)

    def getHashFilePathByRestoreToken(self, token, current=None):
        return hostSession.http_get_hash_file_path_by_restore_token(token)

    def QueryJsonData(self, ident, jsonContent, current=None):
        return json.dumps(hostSession.http_post_query_json_data(ident, jsonContent))


def install_agent_thread(session, flag_json):
    _logger.info(r'[install_agent_thread] enter...')

    InstallLinuxAgent.setup_agent_thread(session, _g, flag_json)

    _logger.info(r'[install_agent_thread] finish...')


class SetupI(BoxLogic.Setup):
    def __init__(self):
        global _logger
        _logger.info(r'SetupI start ...')
        xlogging.ExceptionHandlerDecorator().decorate()
        xlogging.TraceDecorator().decorate()

    @staticmethod
    def startSetup(session_name, flag_json, current=None):
        _logger.info(r'[startSetup] enter...')

        t = threading.Thread(target=install_agent_thread, args=(session_name, flag_json))
        t.start()

        _logger.info(r'[startSetup] finish...')

    @staticmethod
    def cancelSetup(session_name, current=None):
        pass


make_dirs_locker = threading.Lock()


class LogicInternalI(BoxLogic.LogicInternal):
    def __init__(self):
        global _logger
        _logger.info(r'LogicInternalI start ...')
        xlogging.ExceptionHandlerDecorator().decorate()
        xlogging.TraceDecorator(
            ['pathJoin', 'isFileExist', 'makeDirs', 'remove', 'enumStorageNodes', 'refreshExternalDevice',
             'isFolderExist', 'runCmd', 'pathJoin', 'isFileExist', 'AllFilesExist', 'isFolderExist']).decorate()

    @staticmethod
    def pathJoin(paths, current=None):
        result = os.path.join(*paths)
        # _logger.info(r'pathJoin : {}'.format(result))
        return result

    @staticmethod
    def isFileExist(path, current=None):
        path = os.path.normpath(path)
        result = os.path.isfile(path)
        if not result:
            _logger.warning(r'isFileExist : {} path : {}'.format(result, path))
        return result

    @staticmethod
    def AllFilesExist(paths, current=None):
        for path in paths:
            path = os.path.normpath(path)
            if not os.path.isfile(path):
                _logger.warning('AllFilesExist : file {} not exists'.format(path))
                break
        else:
            return True
        _logger.warning('AllFilesExist : paths {} not exists'.format(paths))
        return False

    @staticmethod
    def isFolderExist(path, current=None):
        path = os.path.normpath(path)
        result = os.path.isdir(path)
        if not result:
            _logger.warning(r'isFolderExist : {} path : {}'.format(result, path))
        return result

    @staticmethod
    def makeDirs(path, existOk, mode, current=None):
        with make_dirs_locker:
            os.makedirs(path, mode, existOk)
        _logger.info(r'makeDirs : {}'.format(path))

    @staticmethod
    def remove(path, current=None):
        if os.path.isfile(path):
            os.remove(path)
            _logger.info(r'remove file : {}'.format(path))
        elif os.path.isdir(path):
            shutil.rmtree(path, True)
            _logger.info(r'remove dir : {}'.format(path))
        else:
            _logger.warning(r'remove nothing . not exist path : {}'.format(path))

    @staticmethod
    def copy(params, current=None):
        params = json.loads(params)
        try:
            shutil.copy(params['path'], params['new_path'])
        except Exception as e:
            xlogging.raise_system_error(
                r'拷贝文件失败', 'copy {} -> {} : {}'.format(params['path'], params['new_path'], e), 0)

    @staticmethod
    def findFiles(params, current=None):
        result = list()
        params_dict = json.loads(params)
        for root, dirs, files in os.walk(params_dict['path']):
            for name in files:
                if fnmatch.fnmatch(name, params_dict['pattern']):
                    result.append(os.path.join(root, name))
        return result

    @staticmethod
    def queryCdpTimestampRange(path, discard_dirty_data, current=None):
        return cdpFile.queryTimestampRange(path, discard_dirty_data)

    @staticmethod
    def queryCdpTimestamp(path, timestamp, current=None):
        return cdpFile.queryTimestamp(path, timestamp)

    @staticmethod
    def formatCdpTimestamp(timestamp, current=None):
        return cdpFile.formatTimestamp(timestamp)

    @staticmethod
    def mergeCdpFile(params_string, current=None):
        params = json.loads(params_string)
        cdp_file = params['cdp_file']
        cdp_time_range = params['cdp_time_range']
        disk_bytes = params['disk_bytes']
        qcow_file = params['qcow_file']
        qcow_ident = params['qcow_ident']
        last_snapshots = params['last_snapshots']

        nbd_object = nbd.nbd_wrapper(nbd.nbd_wrapper_disable_lvm_allocator(nbd.nbd_wrapper_local_device_allocator()))
        nbd_thread = nbd.nbd_direct_images(r'mergeCdpFile {}'.format(qcow_ident), nbd_object, last_snapshots)
        nbd_thread.start()
        time.sleep(5)  # 等待nbd启动
        nbd.nbd_wrapper.wait_nbd_read_ok(nbd_object)

        try:
            cdpFile.merge(cdp_file, cdp_time_range, disk_bytes, qcow_file, qcow_ident, last_snapshots, nbd_object)
        finally:
            nbd_object.unmount()
            nbd_object.wait_no_mounting()
            nbd_object.set_no_longer_used()
            nbd_thread.join()

    @staticmethod
    def mergeCdpFiles(config_string, current=None):
        config = json.loads(config_string)
        cdpFile.mergeFiles(config)

    @staticmethod
    def cutCdpFile(config_string, current=None):
        config = json.loads(config_string)
        cdpFile.cut(config)

    @staticmethod
    def isHardwareDriverExist(hardware, os_type, os_bit, current=None):
        iso_content_folder, iso_driver_pool_folder = r'/sbin/aio/restore-iso', r'/home/aio/driver_pool'
        isoWorkerFolderPath, isoFilePath = r'/tmp', r'/iso'

        iso = pe_stage_iso.IsoMaker(iso_content_folder, iso_driver_pool_folder, isoWorkerFolderPath, isoFilePath)
        return len(iso.get_drive_list(os_type, os_bit, hardware.HWIds, hardware.CompatIds)) > 0

    @staticmethod
    def GetDriversVersions(hardware, os_type, os_bit, current=None):
        iso_content_folder, iso_driver_pool_folder = r'/sbin/aio/restore-iso', r'/home/aio/driver_pool'
        isoWorkerFolderPath, isoFilePath = r'/tmp', r'/iso'

        iso = pe_stage_iso.IsoMaker(iso_content_folder, iso_driver_pool_folder, isoWorkerFolderPath, isoFilePath)
        return json.dumps(iso.get_drive_list(os_type, os_bit, hardware.HWIds, hardware.CompatIds))

    @staticmethod
    def ChkIsSubId(hardware, current=None):
        iso_content_folder, iso_driver_pool_folder = r'/sbin/aio/restore-iso', r'/home/aio/driver_pool'
        isoWorkerFolderPath, isoFilePath = r'/tmp', r'/iso'

        iso = pe_stage_iso.IsoMaker(iso_content_folder, iso_driver_pool_folder, isoWorkerFolderPath, isoFilePath)
        return iso.ChkIsSubId(hardware.HWIds, hardware.CompatIds)

    @staticmethod
    def GetDriversSubList(userSelect, current=None):
        iso_content_folder, iso_driver_pool_folder = r'/sbin/aio/restore-iso', r'/home/aio/driver_pool'
        isoWorkerFolderPath, isoFilePath = r'/tmp', r'/iso'

        iso = pe_stage_iso.IsoMaker(iso_content_folder, iso_driver_pool_folder, isoWorkerFolderPath, isoFilePath)
        return json.dumps(iso.one_select_2_get_sub_drv_list(json.loads(userSelect)))

    @staticmethod
    def is_master_ipconfig(ipconfig):
        multi_infos = json.loads(ipconfig.multiInfos)
        return multi_infos['target_nic']['isConnected']

    def get_master_nic_ipconfig(self, ipconfigs):
        for ipconfig in ipconfigs:
            if self.is_master_ipconfig(ipconfig):
                return ipconfig

        raise Exception('not found master nic in target nics, {}'.format(ipconfigs))

    @staticmethod
    def get_gateway(ip, mask, gateway):
        if not gateway:
            return None
        ip_list = list(map(lambda x: int(x), ip.split('.')))
        mask_list = list(map(lambda x: int(x), mask.split('.')))
        gateway_list = list(map(lambda x: int(x), gateway.split('.')))
        for i in range(4):
            if (ip_list[i] & mask_list[i]) != (gateway_list[i] & mask_list[i]):
                return None
        return gateway

    def is_global_gateway_belong_to_master_nic(self, ipconfigs):
        master_ipconfig = self.get_master_nic_ipconfig(ipconfigs)
        multi_infos = json.loads(master_ipconfig.multiInfos)
        master_ip_mask_pairs = multi_infos['ip_mask_pair']
        global_gateway = multi_infos['gate_way']
        if not global_gateway:
            return True

        for pair in master_ip_mask_pairs:
            if self.get_gateway(pair['Ip'], pair['Mask'], global_gateway):
                return True
        return False

    # 异机还原时: 所有网卡使用全局的gateway,dns_list
    # 本机还原时: 仅关心主网卡, 使用主网卡在备份点的gateway,dns_list
    def get_global_gateway_dns_list(self, ipconfigs):
        master_ipconfig = self.get_master_nic_ipconfig(ipconfigs)
        mst_multi_infos = json.loads(master_ipconfig.multiInfos)
        return mst_multi_infos['gate_way'], mst_multi_infos['dns_list']

    def generate_master_nic_params(self, ipconfigs):
        master_ipconfig = self.get_master_nic_ipconfig(ipconfigs)
        mst_multi_infos = json.loads(master_ipconfig.multiInfos)
        hardware_config = json.loads(master_ipconfig.hardwareConfig)
        is_to_self = mst_multi_infos['is_to_self']
        params = {'instId': mst_multi_infos['src_instance_id'],
                  'hard_ids': hardware_config[0]['HardwareID'],
                  'dns': '',
                  'ips': [],
                  'masks': [],
                  'gateways': [],
                  'name': mst_multi_infos.get('name', None),
                  'mtu': int(mst_multi_infos.get('mtu', -1))
                  }

        gateway, dns_list = self.get_global_gateway_dns_list(ipconfigs)
        if is_to_self:
            params['gateways'] = [gateway]
        else:
            params['gateways'] = [gateway if self.is_global_gateway_belong_to_master_nic(ipconfigs) else '']

        params['dns'] = ','.join(dns_list)  # dns始终全部设置到"主网卡"

        for ip_mask in mst_multi_infos['ip_mask_pair']:
            params['ips'].append(ip_mask['Ip'])
            params['masks'].append(ip_mask['Mask'])

        _logger.info('generate_master_nic_params, {}, {}, {}'.format(params, is_to_self, hardware_config))
        return params, is_to_self, hardware_config

    # 设置目标机主网卡
    # 本机还原, 该网卡的ip_mask_pair, dns_list, gateway来自备份点中该网卡的信息
    # 异机还原, 该网卡的ip_mask_pair, dns_list, gateway来自界面用户填写该网卡的值, 其中dns_list,gateway为网卡的全局值
    def set_target_master_nic_ipconfig(self, ipconfigs, iso):
        params, is_to_self, hardware_config = self.generate_master_nic_params(ipconfigs)

        if is_to_self:
            iso.add_ip_v2(params['instId'], params['hard_ids'], params['dns'], params['ips'], params['masks'],
                          params['gateways'], hardware_config, params['name'], params['mtu'])
        else:
            iso.add_ip_v2('', params['hard_ids'], params['dns'], params['ips'], params['masks'],
                          params['gateways'], hardware_config, params['name'], params['mtu'])
        # if not is_to_self:
        #     iso.add_ip(params['hard_ids'], params['dns'], params['ips'], params['masks'], params['gateways'])
        #     iso.add_ip_hardware(hardware_config)
        # else:
        #     iso.add_ip_by_local(params['instId'], params['dns'], params['ips'], params['masks'], params['gateways'])
        #     iso.add_ip_hardware_by_local(hardware_config)

        return is_to_self

    # 设置目标机副网卡(异机还原)
    # 每张网卡需要设置: ip_mask_pairs, gateway
    # 其中gateway设置在了主卡, 这里就不需要再设置
    def set_target_non_master_nics_ipconfig(self, ipconfigs, iso):
        if self.is_global_gateway_belong_to_master_nic(ipconfigs):
            gate_way = ''
        else:
            gate_way = self.get_global_gateway_dns_list(ipconfigs)[0]
        gate_way = gate_way if gate_way else None

        ipconfigs = itertools.filterfalse(self.is_master_ipconfig, ipconfigs)
        nics_cfgs_json = {'SetIpInfo': []}
        for ipconfig in ipconfigs:
            multi_infos = json.loads(ipconfig.multiInfos)
            mac, ip_mask_pairs = multi_infos['target_nic']['szMacAddress'], multi_infos['ip_mask_pair']
            ip_mask_list = [{'ip': pair['Ip'], 'ip_type': 0, 'mask': pair['Mask']} for pair in ip_mask_pairs]
            nics_cfgs_json['SetIpInfo'].append({
                'mac': mac,
                'ip_mask_list': ip_mask_list,
                'gate_way': gate_way,
                'dns_list': [],
                'nic_name': multi_infos.get('name', None),
                'mtu': int(multi_infos.get('mtu', -1)),
            })
        _logger.info('set_target_non_master_nics_ipconfig, {}'.format(nics_cfgs_json))

        if not nics_cfgs_json['SetIpInfo']:
            nics_cfgs_json = None

        iso.create_non_master_nics_configs_in_iso(nics_cfgs=nics_cfgs_json)

    def generatePeStageIso(self, isoWorkerFolderPath, isoFilePath, hardwares, ipconfigs, pci_bus_device_ids,
                           os_type, os_bit, driversIds, agentServiceConfigure, current=None):
        iso_content_folder = r'/sbin/aio/restore-iso'
        iso_driver_pool_folder = r'/home/aio/driver_pool'
        json_config = json.loads(agentServiceConfigure)
        htb_mode = False
        htb_task_uuid = json_config.get('htb_task_uuid', '')
        if htb_task_uuid and len(htb_task_uuid) == 32:
            htb_mode = True
        iso = pe_stage_iso.IsoMaker(iso_content_folder, iso_driver_pool_folder, isoWorkerFolderPath, isoFilePath)
        iso.copy_default_files()
        iso.create_agent_service_configs(json_config)
        driversIds = driversIds.replace('|', '\\')
        driversIds_dict = json.loads(driversIds)
        _logger.debug(driversIds_dict)
        if len(pci_bus_device_ids) != 0:
            iso.install_system_driver([r'PCI\VEN_6789&DEV_0002&SUBSYS_00010001&REV_01'], [])
            iso.add_drive(os_type, os_bit, [r'PCI\VEN_6789&DEV_0002&SUBSYS_00010001&REV_01'], [], [])
        for hardware in hardwares:
            _logger.debug(hardware.HWIds[0])
            if self.is_iso_ignore_hardware_id(hardware.HWIds):
                continue
            else:
                iso.install_system_driver(hardware.HWIds, hardware.CompatIds)
                if htb_mode:
                    iso.backup_system_driver(hardware.HWIds, hardware.CompatIds)
                user_select_list = driversIds_dict.get(hardware.HWIds[0], list())
                iso.add_drive(os_type, os_bit, hardware.HWIds, hardware.CompatIds, user_select_list)
        if json_config.get('replace_efi'):
            iso.replace_efi()
        iso.add_drive_end()

        restore_to_self = self.set_target_master_nic_ipconfig(ipconfigs, iso)
        if restore_to_self:
            iso.create_non_master_nics_configs_in_iso(nics_cfgs=None)  # 清除网卡配置文件ht.json
        else:
            self.set_target_non_master_nics_ipconfig(ipconfigs, iso)  # 异机还原, 设置副网卡信息

        iso.make()

    @staticmethod
    def is_iso_ignore_hardware_id(hardware_id):
        for _id in hardware_id:
            if '&CC_0601' in _id.upper():
                _logger.warning(r'is_iso_ignore_hardware_id find {}'.format(hardware_id))
                return True
        else:
            return False

    @staticmethod
    def is_generate_rom():
        return (_get_property_as_int('Logic.Kvm.Logic') & kvm.ADD_DISABLE_DEVICE_HARD_ID_TO_ROM) != 0

    def runRestoreKvm(self, params_string, current=None):
        params = json.loads(params_string)
        takeover_params = params.get('takeover_params', None)
        if params['logic'] == 'windows':
            self._runRestoreKvmWindows(params)
            self._check_htb_disk_file(params['htb_disk_path'])
        else:
            self._runRestoreKvmLinux(params)
            if takeover_params:
                self._runRestoreKvmWindows(params)

        if takeover_params is None:
            self._check_floppy_file(params['floppy_path'])
        else:
            pass  # 接管流程不用检查位图数据是否正确拷贝

    @staticmethod
    @xlogging.convert_exception_to_value(None)
    def rmdir_without_except(path):
        os.rmdir(path)

    @staticmethod
    @xlogging.convert_exception_to_value(None)
    def _boot_nbd_object_by_takeover_params(takeover_params):
        if not takeover_params:
            return None
        disk_snapshots = takeover_params['disk_snapshots']
        nbdinfo = disk_snapshots['boot_devices'][0]['device_profile'].get('nbd', None)
        if not nbdinfo:
            _logger.warning(r'takeover_params without boot_nbd_object. {}'.format(disk_snapshots))
            return None
        return nbd.nbd_wrapper(
            nbd.nbd_wrapper_disable_lvm_allocator(
                nbd.nbd_wrapper_empty_allocator(
                    nbdinfo['device_index'], nbdinfo['device_name'],
                    nbdinfo['device_path'], nbdinfo['vnc_address'])
            )
        )

    @staticmethod
    @xlogging.convert_exception_to_value(None)
    def _nbd_object_by_data_device(data_device):
        device_profile = data_device.get('device_profile', None)
        if not device_profile:
            return
        nbdinfo = device_profile.get('nbd', None)
        if not nbdinfo:
            _logger.warning(r'device_profile without nbd_object. {}'.format(device_profile))
            return None
        return nbd.nbd_wrapper(
            nbd.nbd_wrapper_disable_lvm_allocator(
                nbd.nbd_wrapper_empty_allocator(nbdinfo['device_index'], nbdinfo['device_name'],
                                                nbdinfo['device_path'], nbdinfo['vnc_address'])
            )
        )

    @staticmethod
    @xlogging.convert_exception_to_value((None, None, None,))
    def _boot_nbd_object_by_run_on_other_host_params(run_on_other_host_params):
        if not run_on_other_host_params:
            return None, None, None
        run_on_other_host_params = json.loads(run_on_other_host_params)
        run_on_other_host = dict()
        run_on_other_host["password_login"] = None
        run_on_other_host["public_key_login"] = dict()
        run_on_other_host["public_key_login"]['key'] = run_on_other_host_params['ssh_key']
        run_on_other_host["public_key_login"]['pwd'] = run_on_other_host_params.get('ssh_key_pwd', None)
        run_on_other_host["remote_ip"] = run_on_other_host_params['ssh_ip']
        run_on_other_host["remote_port"] = int(run_on_other_host_params['ssh_port'])
        run_on_other_host["remote_dir"] = run_on_other_host_params['ssh_path']
        run_on_other_host["local_ip"] = run_on_other_host_params['aio_ip']
        run_on_other_host["base_files"] = LogicInternalI._get_kvm_base_files(run_on_other_host_params['ssh_os_type'])
        _logger.info('_runRestoreKvmWindows run_on_other_host={}'.format(run_on_other_host))
        # {
        #     "password_login": null,
        #     "public_key_login": {
        #         "key": "xxxxx",
        #         "pwd": "yyyyy"
        #     },
        #     "remote_ip": "172.16.6.81",
        #     "remote_port": 22,
        #     "remote_dir": "/tmp/clw",
        #     "local_ip": "172.16.6.82",
        #     "base_files": "/sbin/aio/remote_host/zzzzzz.tar.gz"
        # }
        remote_kvm_host_object = kvm_host.kvm_host(run_on_other_host)
        kvm.kvm_wrapper.push_base_files(remote_kvm_host_object, run_on_other_host['base_files'])
        remote_nbd_config_path = kvm.kvm_wrapper.create_remote_nbd_config(run_on_other_host['local_ip'])
        # TODO 需要从远端主机中查询可用的nbd序号
        boot_nbd_object = nbd.nbd_on_remote(nbd.nbd_wrapper_local_device_allocator(), remote_kvm_host_object)
        return boot_nbd_object, remote_nbd_config_path, remote_kvm_host_object

    def _runRestoreKvmLinux(self, params):
        pe_ident = params['pe_ident']
        boot_disk_token = params['boot_disk_token']
        boot_disk_bytes = params['boot_disk_bytes']
        boot_device_normal_snapshot_ident = params['boot_device_normal_snapshot_ident']
        data_devices = params['data_devices']
        linux_disk_index_info = params['linux_disk_index_info']
        linux_storage = params['linux_storage']
        root_path = params['mount_path']
        linux_info = params['linux_info']
        link_path = params['link_path']
        restore_config = params['restore_config']
        floppy_path = params['floppy_path']
        ipconfigs = params['ipconfigs']
        kvm_virtual_devices = params['kvm_virtual_devices']
        start_kvm_flag_file = params['start_kvm_flag_file']
        kvm_vbus_devices = params['kvm_vbus_devices']
        htb_key_data_dir = params['htb_key_data_dir']
        open_kvm_params = params.get('open_kvm_params', None)
        takeover_params = params.get('takeover_params', None)

        for ip_config in ipconfigs:
            hardwareConfig = json.loads(ip_config.pop('hardwareConfig'))[0]
            ip_config['mac'] = hardwareConfig['Mac']

        os.makedirs(root_path, exist_ok=True)
        os.makedirs(link_path, exist_ok=True)

        to_hyper_v_one = False
        to_xen = False
        if kvm_vbus_devices is not None:
            if r'VMBUS' in kvm_vbus_devices.upper():
                to_hyper_v_one = True
            if r'XEN' in kvm_vbus_devices.upper():
                to_xen = True

        try:
            kvm_flag = _get_property_as_int('Logic.LinuxKvm.Logic')

            boot_nbd_object = self._boot_nbd_object_by_takeover_params(takeover_params)
            if boot_nbd_object is None:
                boot_nbd_object = nbd.nbd_wrapper(nbd.nbd_wrapper_local_device_allocator())

            data_nbd_objects = list()
            for data_device in data_devices:
                nbd_object = self._nbd_object_by_data_device(data_device)
                if nbd_object is None:
                    nbd_object = nbd.nbd_wrapper(nbd.nbd_wrapper_local_device_allocator())
                data_nbd_objects.append({'nbd_object': nbd_object, 'data_device': data_device})

            kvm_object = kvm_linux.kvm_linux(
                pe_ident, boot_disk_token, boot_disk_bytes, boot_device_normal_snapshot_ident, boot_nbd_object,
                data_nbd_objects, linux_disk_index_info, linux_storage, root_path, linux_info, link_path,
                restore_config, floppy_path, ipconfigs, kvm_virtual_devices, start_kvm_flag_file, to_hyper_v_one,
                to_xen, takeover_params, htb_key_data_dir, open_kvm_params)
            kvm_object.run(kvm_flag)
            if kvm_object.some_error is not None:
                xlogging.raise_system_error(kvm_object.some_error[0], kvm_object.some_error[1], 0)
        finally:
            self.rmdir_without_except(root_path)
            self.remove(link_path)

    @staticmethod
    def _get_kvm_base_files(ssh_os_type):
        if ssh_os_type == 'cd79d984e62e4c5fbb12188e5b8cc7f8':
            return r'/sbin/aio/remote_host/cd79d984e62e4c5fbb12188e5b8cc7f8.tar.gz'
        else:
            xlogging.raise_system_error(r'无效的kvm运行平台', '_get_kvm_base_files : {}'.format(ssh_os_type), 0)

    def _runRestoreKvmWindows(self, params):
        pe_ident = params['pe_ident']
        boot_disk_token = params['boot_disk_token']
        boot_disk_bytes = params['boot_disk_bytes']
        kvm_virtual_devices = params['kvm_virtual_devices']
        kvm_cpu_id = params['kvm_cpu_id']
        iso_path = params['iso_path']
        kvm_virtual_device_hids = params['kvm_virtual_device_hids']
        floppy_path = params['floppy_path']
        data_devices = params['data_devices']
        is_efi = params.get('is_efi', False)
        kvm_vbus_devices = params['kvm_vbus_devices']
        start_kvm_flag_file = params['start_kvm_flag_file']
        htb_disk_path = params['htb_disk_path']
        takeover_params = params.get('takeover_params', None)
        run_on_other_host_params = params.get('run_on_other_host', None)

        remote_nbd_config_path = None
        remote_kvm_host_object = None
        boot_nbd_object = self._boot_nbd_object_by_takeover_params(takeover_params)
        if boot_nbd_object is None:
            boot_nbd_object, remote_nbd_config_path, remote_kvm_host_object = \
                self._boot_nbd_object_by_run_on_other_host_params(run_on_other_host_params)
        if boot_nbd_object is None:
            boot_nbd_object = nbd.nbd_wrapper(nbd.nbd_wrapper_local_device_allocator())

        rom_path = kvm.kvm_wrapper.create_rom_file(kvm_virtual_device_hids if self.is_generate_rom() else [])
        vbus_bin_path = kvm.kvm_wrapper.create_vbus_file(kvm_vbus_devices)

        data_nbd_objects = list()
        for data_device in data_devices:
            nbd_object = self._nbd_object_by_data_device(data_device)
            if nbd_object is None and remote_kvm_host_object:
                # TODO 需要从远端主机中查询可用的nbd序号
                nbd_object = nbd.nbd_on_remote(nbd.nbd_wrapper_local_device_allocator(), remote_kvm_host_object)
            if nbd_object is None:
                nbd_object = nbd.nbd_wrapper(nbd.nbd_wrapper_local_device_allocator())

            data_nbd_objects.append({'nbd_object': nbd_object, 'data_device': data_device})

        try:
            max_kvm_minutes = _get_property_as_int('Logic.Kvm.MaxMinutes')
            kvm_flag = _get_property_as_int('Logic.WindowsKvm.Logic')
            kvm_object = kvm.kvm_wrapper(
                max_kvm_minutes, boot_nbd_object, pe_ident, boot_disk_token, boot_disk_bytes, kvm_virtual_devices,
                kvm_cpu_id, iso_path, rom_path, floppy_path, data_nbd_objects, is_efi, vbus_bin_path,
                start_kvm_flag_file, htb_disk_path, takeover_params, remote_nbd_config_path, remote_kvm_host_object)
            kvm_object.run(kvm_flag)
            if kvm_object.some_error is not None:
                xlogging.raise_system_error(kvm_object.some_error[0], kvm_object.some_error[1], 0)
        finally:
            self.remove(rom_path)
            if vbus_bin_path is not None:
                self.remove(vbus_bin_path)

    @staticmethod
    def _check_floppy_file(floppy_file_path):
        if os.path.exists(floppy_file_path):
            with open(floppy_file_path, 'rb') as f:
                _logger.info(r'_check_floppy_file {} skip 4k'.format(floppy_file_path))
                f.seek(4 * 1024)

                content = f.read(4 * 1024)
                for byte in content:
                    if byte is not 0:
                        break
                else:
                    xlogging.raise_system_error(
                        "还原失败，准备关键数据失败",
                        '_check_floppy_file floopy is empty file path {} '.format(floppy_file_path), 7)

            floppy_temp_file_path = floppy_file_path + '.skip_temp'
            with open(floppy_file_path, 'rb') as rf:
                with open(floppy_temp_file_path, 'wb') as wf:
                    wf.truncate((1024 * 1024 * 2) + 4096)
                    wf.seek(0)
                    rf.seek(4 * 1024)
                    wf.write(rf.read((1024 * 1024 * 2) - (4 * 1024) - 512))
                    wf.seek(4 * 1024, os.SEEK_CUR)
                    wf.write(rf.read())
                    wf.flush()

            os.remove(floppy_file_path)
            os.rename(floppy_temp_file_path, floppy_file_path)
        else:
            xlogging.raise_system_error("还原失败，准备关键数据失败",
                                        '_check_floppy_file floopy miss path {} '.format(floppy_file_path), 8)

    @staticmethod
    def _check_htb_disk_file(htb_disk_path):
        if not htb_disk_path:
            return True
        if os.path.exists(htb_disk_path):
            with open(htb_disk_path, 'rb') as f:
                content = f.read(4 * 1024)
                for byte in content:
                    if byte is not 0:
                        return True
        _logger.warning(r'_check_htb_disk_file Failed.htb_disk_path={}'.format(htb_disk_path))
        return False

    @staticmethod
    @xlogging.LockDecorator(_net_setting_locker)
    def getCurrentNetworkInfos(current=None):
        return net_base.net_get_info()

    @staticmethod
    @xlogging.LockDecorator(_net_setting_locker)
    def setNetwork(net_infos, current=None):
        return net_base.net_set_info(net_infos)

    @xlogging.LockDecorator(_store_manage_locker)
    def setGlobalDoubleChap(self, user_name, password, current=None):
        returned = _store_manage.set_global_double_chap(user_name, password)
        if returned != 0:
            xlogging.raise_system_error(
                r'配置双向验证失败',
                'call set_global_double_chap({}, {}) failed {}'.format(user_name, password, returned),
                returned)

    @xlogging.LockDecorator(_store_manage_locker)
    def getGlobalDoubleChap(self, current=None):
        user_name, password = _store_manage.get_global_double_chap()
        if user_name is None or password is None or user_name == '' or password == '':
            return False, '', ''
        return True, user_name, password

    @xlogging.LockDecorator(_store_manage_locker)
    def getLocalIqn(self, current=None):
        returned = _store_manage.get_local_iqn()
        if returned is None:
            xlogging.raise_system_error(
                r'获取设备IQN失败', 'call get_local_iqn failed', -1)
        return returned

    @xlogging.LockDecorator(_store_manage_locker)
    def setLocalIqn(self, iqn, current=None):
        returned = _store_manage.set_local_iqn(iqn)
        if returned != 0:
            if returned == -2:
                xlogging.raise_system_error(
                    r'设置设备IQN失败，不正确IQN格式',
                    'call set_local_iqn({}) failed {}'.format(iqn, returned),
                    returned)
            else:
                xlogging.raise_system_error(
                    r'设置设备IQN失败',
                    'call set_local_iqn({}) failed {}'.format(iqn, returned),
                    returned)

    @staticmethod
    @xlogging.LockDecorator(_store_manage_locker)
    def enumStorageNodes(current=None):
        global _last_enum_storage_nodes
        enum_nodes = _store_manage.Enum()
        nodes = _convert_store_manage_item_to_dict(enum_nodes)
        result = json.dumps(nodes, ensure_ascii=False)
        if _last_enum_storage_nodes != result:
            _logger.info(r'enum_storage_nodes : {}'.format(result))
            _last_enum_storage_nodes = result
        return result

    # 使用字段 ： logic_device_path
    @xlogging.LockDecorator(_store_manage_locker)
    def formatAndInitializeStorageNode(self, node, current=None):
        node_content = json.loads(node)
        logic_device_path = node_content['logic_device_path']
        if (logic_device_path is None) or (len(logic_device_path) < 8):
            xlogging.raise_system_error(r'初始化存储节点失败，无效的节点设备',
                                        'formatAndInitializeStorageNode invalid : {}'.format(node), 0)
        if node_content['is_mounting']:
            _store_manage.umount(node_content['file_system_name'])
        _store_manage.InitDisk(logic_device_path)

    # 使用字段 ： file_system_name， mount_path
    @xlogging.LockDecorator(_store_manage_locker)
    def mountStorageNode(self, node, current=None):
        node_content = json.loads(node)
        file_system_name = node_content['file_system_name']
        mount_path = node_content['mount_path']
        if (file_system_name is None) or (len(file_system_name) < 8) or (mount_path is None) or (len(mount_path) < 8):
            xlogging.raise_system_error(r'挂载存储节点失败，无效的参数',
                                        'mountStorageNode invalid : {}'.format(node), 0)

        os.makedirs(mount_path, 0o755, True)
        net_common.get_info_from_syscmd("sync")
        returned = _store_manage.mount(file_system_name, mount_path)
        if returned != 0:
            _store_manage.umount(file_system_name)  # do not check returned
            returned = _store_manage.mount(file_system_name, mount_path)
        if returned != 0:
            xlogging.raise_system_error(
                r'挂载存储节点失败',
                'mountStorageNode call mount({}, {}) failed {}'.format(file_system_name, mount_path, returned),
                returned)

    def CmdCtrl(self, cmdinfo, current=None):
        return samba.ice_cmd_ctrl(cmdinfo)

    # 使用字段 ： file_system_name(可选)， mount_path
    @xlogging.LockDecorator(_store_manage_locker)
    def unmountStorageNode(self, node, current=None):
        node_content = json.loads(node)
        file_system_name = node_content['file_system_name']
        mount_path = node_content['mount_path']
        if (mount_path is None) or (len(mount_path) < 8):
            xlogging.raise_system_error(r'卸载存储节点失败，无效的参数',
                                        'unmountStorageNode invalid : {}'.format(node), 0)

        if (file_system_name is not None) and (len(file_system_name) >= 8):
            unmount_name = file_system_name
        else:
            unmount_name = mount_path

        net_common.get_info_from_syscmd("sync")
        returned = _store_manage.umount(unmount_name, True)

        # 这里引发过一次所有备份数据的丢失，不可以解除注释。
        # self.remove(mount_path)

        if returned != 0:
            xlogging.raise_system_error(
                r'卸载存储节点失败', 'unmountStorageNode call umount({}) failed {}'.format(unmount_name, returned),
                returned)

    @staticmethod
    @xlogging.LockDecorator(_store_manage_locker)
    def refreshExternalDevice(iqn, current=None):
        if iqn == '':
            returned = _store_manage.rescan_all()
            if returned != 0:
                pass
                # xlogging.raise_system_error(
                #     r'刷新所有外部存储设备的状态失败', 'refreshExternalDevice call rescan_all() failed {}'.format(returned),
                #     returned)
        else:
            returned = _store_manage.rescan_one(iqn)
            if returned != 0:
                pass
                # xlogging.raise_system_error(
                #     r'外部刷新存储设备（{}）的状态失败'.format(iqn),
                #     'refreshExternalDevice call rescan_one({}) failed {}'.format(iqn, returned),
                #     returned)

    @xlogging.LockDecorator(_store_manage_locker)
    def logoutExternalDevice(self, iqn, current=None):
        returned = _store_manage.extern_store.del_node_by_iqn(iqn)
        if returned != 0:
            xlogging.raise_system_error(
                r'卸载外部存储设备（{}）的状态失败'.format(iqn),
                'logoutExternalDevice call .extern_store.del_node_by_iqn({}) failed {}'.format(iqn, returned),
                returned)

    @xlogging.LockDecorator(_store_manage_locker)
    def loginExternalDevice(self, ip, port, use_chap, user_name, password, current=None):
        returned, iqn = _store_manage.login_one(ip, port, use_chap, user_name, password)
        if (returned != 0) and (iqn is not None) and (len(iqn) != 0):
            # logout 后再来一次
            _logger.warning(r'logoutExternalDevice when loginExternalDevice iqn:{}'.format(iqn))
            _store_manage.extern_store.del_node_by_iqn(iqn)
            returned, iqn = _store_manage.login_one(ip, port, use_chap, user_name, password)
        if returned != 0:
            xlogging.raise_system_error(
                r'登陆存储设备失败',
                'loginExternalDevice call login_one(ip:{ip} port:{port} use_chap:{use_chap} user_name:{user_name} '
                'password:{password}) failed {returned}'.format(ip=ip, port=port, use_chap=use_chap,
                                                                user_name=user_name, password=password,
                                                                returned=returned),
                returned)
        return iqn

    def runCmd(self, cmd, shell, current=None):
        lines = list()
        if shell:
            with subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True, shell=True) as p:
                for line in p.stdout:
                    lines.append(line.rstrip())
            return p.returncode, lines
        else:
            split_cmd = shlex.split(cmd)
            with subprocess.Popen(split_cmd, stdout=subprocess.PIPE, universal_newlines=True) as p:
                for line in p.stdout:
                    lines.append(line.rstrip())
            return p.returncode, lines

    def getPasswd(self, current=None):
        return passwd_set.get_root_passwd()

    def setPasswd(self, passwdinfo, current=None):
        return passwd_set.set_root_passwd(passwdinfo)

    def calcClusterTime0Hash(self, config, current=None):
        return cluster_diff_images.CalcClusterTime0Hash(json.loads(config)).calc()

    def generateClusterDiffImages(self, config, current=None):
        return cluster_diff_images.ClusterDiffImages(json.loads(config)).generate()

    def getRawDiskFiles(self, binpath, destpath, current=None):
        return getRawDiskFiles(binpath, destpath)

    def NbdFindUnusedReverse(self, current=None):
        device_index, device_name, device_path, vnc_address, serial_address = nbd.nbd_wrapper.find_unused_reverse()
        return json.dumps({
            'device_index': device_index,
            'device_name': device_name,
            'device_path': device_path,
            'vnc_address': vnc_address,
            'serial_address': serial_address
        }, ensure_ascii=False)

    def NbdSetUnused(self, device_name, current=None):
        return nbd.nbd_wrapper.set_unused(device_name)

    def NbdSetUsed(self, device_name, current=None):
        return nbd.nbd_wrapper.set_used(device_name)

    def queryTakeOverHostInfo(self, query_string, current=None):
        return json.dumps(all_big_mm.CAllocBigMM.queryInfo())

    def mergeQcowFile(self, json_args, current=None):
        return qcow_helper.MergeQcowFileHandle(json_args).work()

    def startBackupOptimize(self, json_args, current=None):
        result_optimize = BackupOptimize.MountSnapshot.mount_snapshot(json_args)
        try:
            j_args = json.loads(json_args)
            hash_files = j_args.get('hash_files', None)
            if hash_files:
                disk_bytes = j_args['disk_bytes']
                ordered_hash_file = j_args['ordered_hash_file']
                mergehash = merge_hash_core.MergeHash(disk_bytes)
                ordered_hash_file = mergehash.merge(ordered_hash_file, hash_files, j_args.get('include_cdp', False),
                                                    j_args.get('snapshots', list()))
                result_optimize['hash_file_path'] = ordered_hash_file
        except Exception:
            BackupOptimize.MountSnapshot.unmount_snapshot(json.dumps([result_optimize]))
            raise
        else:
            return json.dumps(result_optimize)

    def stopBackupOptimize(self, json_args, current=None):
        result_optimize = BackupOptimize.MountSnapshot.unmount_snapshot(json_args)
        return result_optimize

    def mergeHashFile(self, json_args, current=None):
        j_args = json.loads(json_args)
        disk_bytes = j_args['disk_bytes']
        old_path = j_args['old_path']
        new_path = j_args['path']
        mergehash = merge_hash_core.MergeHash(disk_bytes)
        return mergehash.merge_one2other_hashv2(old_path, new_path)

    def generateBitMapFromQcowFile(self, json_args, current=None):
        py_args = json.loads(json_args)
        qcow_file_path = py_args['qcow_file_path']
        bit_map_path = py_args['bit_map_path']
        nbytes = qcow_helper.GenerateBitMapFromMaps.get_qcow_file_size(qcow_file_path)
        map_paths = qcow_helper.GenerateBitMapFromMaps.get_map_paths_from_qcow2file(qcow_file_path)
        return qcow_helper.GenerateBitMapFromMaps(map_paths, bit_map_path, nbytes).work()

    def fromMapGetQcowMaxSize(self, map_path, current=None):
        return qcow_helper.GenerateBitMapFromMaps.from_map_get_qcow_max_size(map_path)

    @block('/dev/shm/block_gen_hash')
    def reorganizeHashFile(self, bitmap_array, json_params, current=None):
        _bit_map = bitmap.BitMap()
        _bit_map.bitmap = bytearray(bitmap_array)
        self._reorganize_hash(_bit_map, json_params)

    def _reorganize_hash(self, _bit_map, json_params):
        params = json.loads(json_params)
        if os.path.exists('/sbin/aio/hash_helper_old.so'):  # 测试代码 会比较2个不同版本计算出来的hash是否一致
            _logger.warning('reorganizeHashFile in test mod')
            if os.path.exists(params['hash_file_tmp']):
                os.remove(params['hash_file_tmp'])
            old_new_hash = params['hash_file'] + '.oldver'
            old_new_hash_reg = old_new_hash + '.reg'
            new_hash_reg = params['hash_file'] + '.reg'
            try:
                merge_hash_core.ReorganizeHashFilOldVer(_bit_map, params['snapshots'], old_new_hash,
                                                        params['hash_file_tmp']).work()
                merge_hash_core.ReorganizeHashFile(_bit_map, params['snapshots'], params['hash_file'],
                                                   params['hash_file_tmp'], params['disk_bytes']).work()
                merge_hash_core.MergeHash(params['disk_bytes']).merge(new_hash_reg, [params['hash_file']])
                merge_hash_core.MergeHash(params['disk_bytes']).merge(old_new_hash_reg, [old_new_hash])
                import hashlib
                with open(new_hash_reg, 'rb') as f:
                    new_hash_reg_md5 = hashlib.md5(f.read()).hexdigest()
                with open(old_new_hash_reg, 'rb') as f:
                    old_new_hash_reg_md5 = hashlib.md5(f.read()).hexdigest()
                if new_hash_reg_md5 != old_new_hash_reg_md5:
                    _logger.info('new version old version not equal')
                    raise Exception('整理HASH失败')
            except Exception:
                raise
            else:
                if os.path.exists(old_new_hash):
                    os.remove(old_new_hash)
                if os.path.exists(old_new_hash_reg):
                    os.remove(old_new_hash_reg)
                if os.path.exists(new_hash_reg):
                    os.remove(new_hash_reg)
        else:
            merge_hash_core.ReorganizeHashFile(_bit_map, params['snapshots'], params['hash_file'],
                                               params['hash_file_tmp'], params['disk_bytes']).work()

    @block('/dev/shm/block_gen_hash')
    def reorganizeHashFilev2(self, bitmap_path, json_params, current=None):
        _bit_map = bitmap.MmapBitMap(os.path.getsize(bitmap_path), bitmap_path)
        self._reorganize_hash(_bit_map, json_params)

    def hash2Interval(self, json_params, current=None):
        """
         比较2份有序的hash文件，找出bash_hash与parent_hash不一样的地方，并将不一样的块转换成线段存储在文件中
        :param json_inputs: base_hash, parent_hash, map_path
        :param current:
        :return:
        """
        params = json.loads(json_params)
        return merge_hash_core.Hash2Interval(params['base_hash'], params['parent_hash'], params['map_path']).work()

    def exportSnapshot(self, json_params, current=None):
        params = json.loads(json_params)
        return json.dumps(archive.ExportSnapshotsLogic(params).work())

    def archiveMediaOperation(self, params, current=None):
        return media_objects.operations(params)

    def getArchiveFileMetaData(self, json_params, current=None):
        file_uuid = json.loads(json_params)['file_uuid']
        with archive.AnalyseArchiveMeidaFile(file_uuid) as f:
            return json.dumps(f.get_meta_data())

    def genArchiveQcowFile(self, json_params, current=None):
        parameter = json.loads(json_params)
        return archive.WriteArchiveQcowFile(parameter['task_id']).genArchiveQcowFile(parameter['qcow_file_parameter'])

    def fileBackup(self, json_params, current=None):
        return file_backup_mgr.work(json.loads(json_params))

    def kvmRpc(self, json_params, current=None):
        return kvm_shell_mgr.work(json.loads(json_params))

    def generateClusterDiffQcow(self, json_params, current=None):
        return generate_cluster_diff_qcow.MainLogic(json.loads(json_params)).work()


def _convert_str_to_int(s):
    if (s is None) or (s == 'None') or (len(s) == 0):
        return None
    else:
        return int(s)


def _convert_store_manage_item_to_dict(enum_nodes):
    nodes = list()
    for enum_node in enum_nodes:
        node = {'is_internal': enum_node[0], 'external_ip': enum_node[1],
                'external_port': _convert_str_to_int(enum_node[2]),
                'external_iqn': enum_node[3], 'external_lun': enum_node[4], 'logic_device_path': enum_node[5],
                'disk_size': enum_node[6], 'device_name': enum_node[7], 'has_file_system': enum_node[8],
                'file_system_name': enum_node[9], 'company_code': enum_node[10], 'version_guid': enum_node[11],
                'node_guid': enum_node[12], 'is_mounting': enum_node[13], 'mount_path': enum_node[14]}
        nodes.append(node)
    return nodes


# def _convert_dict_to_store_manage_item(nodes):
#     enum_nodes = list()
#     for node in nodes:
#         enum_node = [node['is_internal'], node['external_ip'], node['external_port'],
#                      node['external_iqn'], node['external_lun'], node['logic_device_path'],
#                      node['disk_size'], node['device_name'], node['has_file_system'],
#                      node['file_system_name'], node['company_code'], node['logic_device_path'],
#                      node['node_guid'], node['is_mounting'], node['mount_path'],
#                      ]
#         enum_nodes.append(enum_node)
#     return enum_nodes


class _logic_service(object):
    def __init__(self):
        global _logger
        _logger.info(r'logic_service starting ...')

        self.__boxPrx = None
        self.__ktsPrx = None
        self.__imgPrx = None

        initData = Ice.InitializationData()
        initData.properties = Ice.createProperties()
        initData.properties.setProperty(r'Ice.LogFile', r'/var/log/aio/logic_service_ice.log')
        initData.properties.setProperty(r'Ice.ThreadPool.Server.Size', r'8')
        initData.properties.setProperty(r'Ice.ThreadPool.Server.SizeMax', r'64')
        initData.properties.setProperty(r'Ice.ThreadPool.Server.StackSize', r'8388608')
        initData.properties.setProperty(r'Ice.ThreadPool.Client.Size', r'8')
        initData.properties.setProperty(r'Ice.ThreadPool.Client.SizeMax', r'64')
        initData.properties.setProperty(r'Ice.ThreadPool.Client.StackSize', r'8388608')
        initData.properties.setProperty(r'Ice.Default.Host', r'localhost')
        initData.properties.setProperty(r'Ice.Warn.Connections', r'1')
        initData.properties.setProperty(r'Ice.ACM.Heartbeat', r'3')
        initData.properties.setProperty(r'Ice.ThreadPool.Client.ThreadIdleTime', r'0')
        initData.properties.setProperty(r'Ice.ThreadPool.Server.ThreadIdleTime', r'0')
        initData.properties.setProperty(r'LogicAdapter.Endpoints', r'tcp -h localhost -p 21100')
        initData.properties.setProperty(r'LogicInternalAdapter.Endpoints', r'tcp -h localhost -p 21109')
        initData.properties.setProperty(r'SetupServiceAdapter.Endpoints', r'tcp -h localhost -p 21111')
        initData.properties.setProperty(r'Logic.WebApi.Url', r'http://localhost:8000/')
        initData.properties.setProperty(r'Logic.WebApi.Username', r'web_api')
        initData.properties.setProperty(r'Logic.WebApi.Password', r'd24609a757394b40bb838c8f3a378fb1')
        initData.properties.setProperty(r'Logic.Nbd.DeviceSize', r'512')
        initData.properties.setProperty(r'Logic.Kvm.Logic', r'1')
        initData.properties.setProperty(r'Logic.Kvm.MaxMinutes', r'120')
        initData.properties.setProperty(r'Logic.LinuxKvm.Logic', r'0')
        initData.properties.setProperty(r'Logic.WindowsKvm.Logic', r'1')
        initData.properties.setProperty(r'BoxSerivce.Proxy', r'apis : tcp -h 127.0.0.1 -p 21105')
        initData.properties.setProperty(r'KTSerivce.Proxy', r'kts : tcp -h 127.0.0.1 -p 21108')
        initData.properties.setProperty(r'ImageSerivce.Proxy', r'img : tcp -h 127.0.0.1 -p 21101')
        initData.properties.setProperty(r'Ice.MessageSizeMax', r'131072')  # 单位KB, 128MB

        config_path = r'/etc/aio/logic_service.cfg'
        if os.path.exists(config_path):
            initData.properties.load(config_path)

        authCookies.init(
            initData.properties.getProperty(r'Logic.WebApi.Url'),
            initData.properties.getProperty(r'Logic.WebApi.Username'),
            initData.properties.getProperty(r'Logic.WebApi.Password'))
        nbd.init(initData.properties.getPropertyAsInt(r'Logic.Nbd.DeviceSize'))
        ignore_kvm_msrs()
        self.communicator = Ice.initialize(sys.argv, initData)

        adapter = self.communicator.createObjectAdapter(r'LogicAdapter')
        adapter.add(LogicI(), self.communicator.stringToIdentity(r'logic'))
        adapter.activate()

        adapterInternal = self.communicator.createObjectAdapter(r'LogicInternalAdapter')
        adapterInternal.add(LogicInternalI(), self.communicator.stringToIdentity(r'logicInternal'))
        adapterInternal.activate()

        adapterSetupService = self.communicator.createObjectAdapter(r'SetupServiceAdapter')
        adapterSetupService.add(SetupI(), self.communicator.stringToIdentity(r'setup'))
        adapterSetupService.activate()

    def run(self):
        global _logger
        self.communicator.waitForShutdown()
        _logger.info(r'logic_service stopped.')

    def stop(self):
        _logger.info(r'logic_service stopping.')
        self.communicator.destroy()

    def getBoxPrx(self):
        if self.__boxPrx is None:
            self.__boxPrx = Box.ApisPrx.checkedCast(self.communicator.propertyToProxy(r'BoxSerivce.Proxy'))
        return self.__boxPrx

    def getKtsPrx(self):
        if self.__ktsPrx is None:
            self.__ktsPrx = Box.ApisPrx.checkedCast(self.communicator.propertyToProxy(r'KTSerivce.Proxy'))
        return self.__ktsPrx

    def getImgPrx(self):
        if self.__imgPrx is None:
            self.__imgPrx = IMG.ImgServicePrx.checkedCast(self.communicator.propertyToProxy(r'ImageSerivce.Proxy'))
        return self.__imgPrx


def handler(signum, frame):
    global _g
    _g.stop()


def _sync_thread():
    while True:
        time.sleep(30)
        os.system(r'sync')


def run():
    global _g, _store_manage, _sync_threading

    if _store_manage is None:
        try:
            _store_manage = store_manage.CStoreManage()
        except Exception as e:
            _logger.error(r'_store_manage constructor failed. {}'.format(e), exc_info=True)
            raise

    if _g is None:
        try:
            _g = _logic_service()
            signal.signal(signal.SIGINT, handler)
            _g.run()
        except Exception as e:
            _logger.error(r'_logic_service run failed. {}'.format(e), exc_info=True)
            raise

    if _sync_threading is None:
        _sync_threading = threading.Thread(target=_sync_thread, daemon=True)
        _sync_threading.start()


def createNormalDiskSnapshot(ident, last_snapshot, disk_bytes, flag):
    handle = _g.getImgPrx().create(ident, last_snapshot, disk_bytes, flag)
    if handle == 0 or handle == -1:
        xlogging.raise_system_error(
            r'创建快照磁盘镜像失败',
            r'create snapshot {} - {} failed, {} {} {}'.format(ident, last_snapshot, disk_bytes, handle, flag),
            handle,
        )
    else:
        _logger.info(r'createNormalDiskSnapshot ok {} {} {} {} {}'.format(
            handle, ident, last_snapshot, disk_bytes, flag))
        return handle


def closeNormalDiskSnapshot(handle, successful):
    _logger.info(r'closeNormalDiskSnapshot : {} {}'.format(handle, successful))
    _g.getImgPrx().close(handle, successful)


def write2NormalDiskSnapshot(handle, byteOffset, data):
    try:
        _g.getImgPrx().write(handle, byteOffset, data)
    except Utils.SystemError as e:
        if e.rawCode == -28:
            xlogging.raise_system_error(r'快照文件写入失败，存储空间不足',
                                        '{} {} {} {}'.format(e.description, e.debug, handle, byteOffset),
                                        e.rawCode)
        elif e.rawCode == -12:
            xlogging.raise_system_error(r'快照文件写入失败，写入偏移大于磁盘大小',
                                        '{} {} {} {}'.format(e.description, e.debug, handle, byteOffset),
                                        e.rawCode)
        else:
            xlogging.raise_system_error(r'快照文件写入失败', '{} {} {} {}'.format(e.description, e.dubug, handle, byteOffset),
                                        e.rawCode)
    except Exception as e:
        xlogging.raise_system_error(r'快照文件写入失败',
                                    'write2NormalDiskSnapshot failed {} {} {}'.format(handle, byteOffset, e), 1)


def readNormalDiskSnapshot(handle, byteOffset, size):
    try:
        _size, data = _g.getImgPrx().read(handle, byteOffset, size)
        if _size != size:
            raise Exception('readNormalDiskSnapshot fail, _size != size _size:{} size:{}'.format(_size, size))
        return data
    except Exception as e:
        xlogging.raise_system_error(r'快照文件读失败',
                                    'readNormalDiskSnapshot failed {} {} {} {}'.format(handle, byteOffset, size, e), 2)


def readNormalDiskSnapshotEx(handle, byteOffset, size):
    try:
        _size, data = _g.getImgPrx().readEx(handle, byteOffset, size)
        if _size != size:
            raise Exception('readNormalDiskSnapshotEx fail, _size != size _size:{} size:{}'.format(_size, size))
        return data
    except Exception as e:
        xlogging.raise_system_error(r'快照文件读失败1',
                                    'readNormalDiskSnapshotEx failed {} {} {} {}'.format(handle, byteOffset, size,
                                                                                         e), 3)


def delNormalDiskSnapshot(snapshot):
    return _g.getImgPrx().DelSnaport(snapshot)


def openDiskSnapshot(snapshots, flag):
    handle = _g.getImgPrx().open(snapshots, flag)
    if handle == 0 or handle == -1:
        xlogging.raise_system_error(
            r'打开快照磁盘镜像失败',
            r'open snapshot {} failed, {} {}'.format(snapshots, handle, flag),
            handle,
        )
    else:
        _logger.info(r'openDiskSnapshot ok {} {} {}'.format(handle, snapshots, flag))
        return handle


@xlogging.convert_exception_to_value(0)
def getTotalUesdBlockBitmap(handle, index):
    return _g.getImgPrx().getTotalUesdBlockBitmap(handle, index)


def readDisk(hostName, diskIndex, sectorOffset, numberOfSectors):
    _, bs = _g.getBoxPrx().readDisk(hostName, diskIndex, sectorOffset, numberOfSectors)
    return bs


def writeDisk(hostName, diskIndex, sectorOffset, numberOfSector, bs):
    return _g.getBoxPrx().writeDisk(hostName, diskIndex, sectorOffset, numberOfSector, bs)


def testDisk(hostName, diskIndex, sectorOffset, numberOfSectors):
    return _g.getBoxPrx().testDisk(hostName, diskIndex, sectorOffset, numberOfSectors)


def JsonFuncV2(hostName, jsonStr, rawBytes):
    return _g.getBoxPrx().JsonFuncV2(hostName, jsonStr, rawBytes)


def JsonFunc(hostName, jsonStr):
    return _g.getBoxPrx().JsonFunc(hostName, jsonStr)


def get_communicator():
    return _g.communicator


class SnapshotsUsedBitMap(object):
    def __init__(self, snapshots, flag):
        self.snapshots = snapshots
        self.flag = flag
        self.bit_map = b''
        self.handle = None

    def __enter__(self):
        _logger.info(r'SnapshotsUsedBitMap begin open {}'.format(self.flag))
        self.handle = openDiskSnapshot(self.snapshots, self.flag)
        _logger.info(r'SnapshotsUsedBitMap end open {}'.format(self.flag))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        _logger.info(r'SnapshotsUsedBitMap begin close {}'.format(self.flag))
        closeNormalDiskSnapshot(self.handle, True)
        _logger.info(r'SnapshotsUsedBitMap end close{}'.format(self.flag))

    def read(self):
        _logger.info(r'SnapshotsUsedBitMap begin read {}'.format(self.flag))
        index = 0
        while True:
            index, bitmap, finish = getTotalUesdBlockBitmap(self.handle, index)
            if index == 0:
                return b''
            self.bit_map += bitmap
            if finish:
                break
        _logger.info(r'SnapshotsUsedBitMap end read {}'.format(self.flag))
        return self.bit_map
