import json
import os

import clerware_linux_driver
import loadIce
import modget
import xlogging

_logger = xlogging.getLogger(__name__)


def _get_db_json():
    with open(os.path.join(loadIce.current_dir, r'linux_devices.json')) as f:
        return json.load(f)


def _search_db_json(db_json, kernel_version, release_version, arch, pci_value_list):
    for key in db_json.keys():
        if modget.is_pci_value_list_match(pci_value_list, db_json[key]['alias']):
            _logger.info(r'_search_db_json find device {} : {}'.format(pci_value_list, db_json[key]))
            match_entry = clerware_linux_driver.search_db_json(db_json[key], kernel_version, release_version, arch)
            if match_entry is not None:
                return match_entry['relative_folder'], match_entry['files']
    return None, None


def get_device_files(kernel_version, release_version, arch, device):
    """
    得到  设备驱动文件列表 的绝对路径
    :param kernel_version: linux 内核版本
    :param release_version: linux 发行版本
    :param arch: "32" "64" "32_PAE"  x86 or x86_64 or x86_PAE
    :param device: 设备描述
    :return: 成功返回路径数组
    """
    pci_value_list = modget.convert_pci_str_2_pci_value_list(device)
    if not modget.is_pci_value_valid(pci_value_list):
        _logger.error(r'modget.is_pci_value_valid False : {}'.format(pci_value_list))
        return None

    db_json = _get_db_json()
    relative_folder, files = _search_db_json(db_json, kernel_version, release_version, arch, pci_value_list)
    if relative_folder is None:
        xlogging.raise_system_error(r'不支持的设备：{}'.format(device),
                                    r'get_device_files failed : {} {} {} {}'.format(
                                        kernel_version, release_version, arch, device), 1)

    result = list()
    for file in files:
        result.append(os.path.join(loadIce.current_dir, relative_folder, file))
    return result
