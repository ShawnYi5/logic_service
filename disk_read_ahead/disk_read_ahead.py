import binascii
import re

import xlogging

_logger = xlogging.getLogger(__name__)
"""
用来存储分区信息
device_type={'type_guid':'',' lba_start','lba_end':'','partition_mbyte'}
"""
DISK_IS_GPT = 0
DISK_IS_MBR = 1
PARTITION_TABLE_SECTOR = 32
ONE_SECTOR_BYTES = 512


def check_gpt_or_mbr(device):
    """
    this is device is gpt or mbr
    :param device: mount device
    :return:0 is gpt，1 is mbr
    """
    with open(device, 'rb') as disk:
        disk_type = disk.read(ONE_SECTOR_BYTES)[450]
        _logger.info('device is gpt or mgr(gpt is  238) {}'.format(disk_type))
        if disk_type == 238:  # ee的十进制为238
            return DISK_IS_GPT
        else:
            return DISK_IS_MBR


def sort_out_partition_item_guid(guid_str):
    """
    this is calc guid
    :param guid_str:guid_str is hex str
    :return: update_guid
    """
    test = str(guid_str)
    guid = "".join([i for index, i in enumerate(test) if index != 0]).replace('\'', '')
    footer = guid[-12:]
    intermediate1 = guid[-16:-12]
    intermediate0 = guid[12:16]  # d211
    result = re.sub(r"(?<=\w)(?=(?:\w\w)+$)", " ", guid[:12]).split(' ')
    result1 = re.sub(r"(?<=\w)(?=(?:\w\w)+$)", " ", intermediate0).split(' ')
    intermediate0 = "".join(result1[::-1])  # 11d2
    header = "".join(result[:4][::-1])
    intermediate = "".join(result[4:][::-1])
    update_guid = header + '-' + intermediate + '-' + intermediate0 + '-' + intermediate1 + '-' + footer
    return update_guid


def partition_info_gpt(disk):
    device_info = []  # 用来存磁盘信息
    for i in range(PARTITION_TABLE_SECTOR):  # 遍历32个分区表项扇区
        byte_stream = disk.read(ONE_SECTOR_BYTES)
        if i > 1 and int(binascii.b2a_hex(byte_stream), 16) != 0:
            partition_info1 = byte_stream[0:128]
            partition_info2 = byte_stream[128:256]
            partition_info3 = byte_stream[256:384]
            partition_info4 = byte_stream[384:512]
            partition_list = [partition_info1, partition_info2, partition_info3, partition_info4]
            for partition in partition_list:
                check = binascii.b2a_hex(partition)
                partition_info = {}  # 用来存分区信息
                if int(check, 16) != 0:
                    partition_info['type_guid'] = sort_out_partition_item_guid(
                        binascii.b2a_hex(partition[0:16]))
                    partition_info['lba_start'] = int.from_bytes(partition[32:40], 'little')
                    partition_info['lba_end'] = int.from_bytes(partition[40:48], 'little')
                    partition_mbyte = (partition_info['lba_end'] - partition_info[
                        'lba_start'] + 1) * ONE_SECTOR_BYTES // (
                                              1024 * 1024)
                    partition_info['partition_mbyte'] = partition_mbyte
                    _logger.info('磁盘分区信息:{}'.format(partition_info))
                    device_info.append(partition_info)
    return device_info


def partition_info_mbr(disk):
    device_info = []  # 用来存磁盘信息
    header_bytes = disk.read(ONE_SECTOR_BYTES)
    partition_info = header_bytes[446:510]
    partition_info1 = partition_info[0:16]
    partition_info2 = partition_info[16:32]
    partition_info3 = partition_info[32:48]
    partition_info4 = partition_info[48:64]
    partition_list = [partition_info1, partition_info2, partition_info3, partition_info4]
    for partition in partition_list:
        check = binascii.b2a_hex(partition)
        partition_info = {}  # 用来存分区信息
        check_activity = hex(partition[0])
        if int(check, 16) != 0:  # 检查分区表项是不是有意义的分区表项,且为活动分区
            partition_info['check_activity'] = check_activity
            partition_info['check_main'] = hex(partition[4])
            partition_info['lba_start'] = int.from_bytes(partition[8:12], 'little')
            sum_sector = int.from_bytes(partition[12:16], 'little')
            partition_info['lba_end'] = sum_sector + partition_info['lba_start']
            partition_info['partition_mbyte'] = (partition_info['lba_end'] - partition_info[
                'lba_start'] + 1) * ONE_SECTOR_BYTES // (1024 * 1024)
            _logger.info('磁盘分区信息:{}'.format(partition_info))
            device_info.append(partition_info)
    return device_info


@xlogging.convert_exception_to_value((None, None,))
def from_sector_partition_item(device):
    """
    statistics disk information
    :param device:mount device
    :return:device_info
    """
    device_type = check_gpt_or_mbr(device)
    _logger.info('this disk is {}(0 is gpt)'.format(device_type))

    with open(device, 'rb') as disk:
        if device_type == DISK_IS_GPT:  # 当等于0时为gpt分区
            return partition_info_gpt(disk), device_type
        else:
            result = [i for i in partition_info_mbr(disk) if i['check_activity'] == '0x80']
            return result, device_type


def read_one_partion(partition, device):
    """
    read a partition
    :param partition: partition info
    :param device:device is a nbd
    :return:
    """
    lba_start = partition['lba_start']
    lba_end = partition['lba_end']
    sum_setor = lba_end - lba_start + 1
    with open(device, 'rb') as open_partition:
        open_partition.seek(lba_start * ONE_SECTOR_BYTES)
        for i in range(sum_setor):
            open_partition.read(ONE_SECTOR_BYTES)


def force_read_ESP_and_MSR_partition_range(device):
    disk_info, gpt_or_mbr = from_sector_partition_item(device)
    _logger.info('磁盘信息为:{} {}'.format(disk_info, gpt_or_mbr))
    if disk_info is None or gpt_or_mbr is None:
        _logger.warning('force_read_ESP_and_MSR_partition_range  {},it is none'.format(device))
        return
    if gpt_or_mbr == DISK_IS_GPT:
        msr_guid = 'e3c9e316-0b5c-4db8-817d-f92df00215ae'
        esp_guid = 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b'
        for partition in disk_info:
            if (partition['type_guid'] == msr_guid) or (partition['type_guid'] == esp_guid):
                _logger.info('gpt read begin correct partition{}'.format(partition))
                read_one_partion(partition, device)
                _logger.info('gpt read over correct partition {}'.format(partition))
    if gpt_or_mbr == DISK_IS_MBR:
        for partition in disk_info:
            # 检查分区是不是小于1024MB,且为主分区
            if partition['partition_mbyte'] < 1024 and partition['check_main'] == '0x7':
                _logger.info('msr read begin correct partition {}'.format(partition))
                read_one_partion(partition, device)
                _logger.info('msr read over correct partition {}'.format(partition))


@xlogging.convert_exception_to_value((None, None,))
def read_head_tail_to_2m(device):
    """
    用来读取每个分区开头和结尾的2M大小
    :param device:
    :return:
    """
    device_type = check_gpt_or_mbr(device)

    with open(device, 'rb') as disk:
        if device_type == DISK_IS_GPT:  # 当等于0时为gpt分区
            partition_infos = partition_info_gpt(disk)
        else:
            partition_infos = partition_info_mbr(disk)
    _logger.info('read_head_tail_to_2m:{}'.format(partition_infos))
    for partition_info in partition_infos:
        _logger.info('read_head_tail_to_2m,partition_info{}'.format(partition_info))
        read_setor = 4096
        read_setor_start = partition_info['lba_start']
        end_setor_start = partition_info['lba_end'] - read_setor
        setor_sum = partition_info['lba_end'] - partition_info['lba_start'] + 1
        if setor_sum > 10240:
            with open(device, 'rb') as open_partition:
                open_partition.seek(read_setor_start * ONE_SECTOR_BYTES)
                open_partition.read(read_setor * ONE_SECTOR_BYTES)
            with open(device, 'rb') as open_partition:
                open_partition.seek(end_setor_start * ONE_SECTOR_BYTES)
                open_partition.read(read_setor * ONE_SECTOR_BYTES)
        else:
            with open(device, 'rb') as open_partition:
                open_partition.read(setor_sum * ONE_SECTOR_BYTES)


if __name__ == "__main__":
    force_read_ESP_and_MSR_partition_range('\\\\.\\PHYSICALDRIVE0')
    read_head_tail_to_2m('\\\\.\\PHYSICALDRIVE0')
