import datetime
import threading
import time
import re
import psutil

import xlogging

_logger = xlogging.getLogger(__name__)
_locker = threading.Lock()
g_next_alloc = datetime.datetime.now()

RESTORE_KVM_MEMORY_MB = 3 * 1024


class CAllocBigMM:
    @staticmethod
    @xlogging.LockDecorator(_locker)
    def try_alloc(alloc_mem_mb):
        global g_next_alloc

        while g_next_alloc > datetime.datetime.now():
            time.sleep(1)

        try:
            _have_used_mem_mb = CAllocBigMM.get_current_memory()
            _total_memory_mb = CAllocBigMM.get_total_memory_mb()
            _logger.info('CAllocBigMM try_alloc:{} used_mem_mb:{} total_memory_mb:{}'.format(
                alloc_mem_mb, _have_used_mem_mb, _total_memory_mb))

            if _have_used_mem_mb + alloc_mem_mb <= _total_memory_mb:
                g_next_alloc = datetime.datetime.now() + datetime.timedelta(seconds=16)
                return True
            else:
                return False
        except Exception as e:
            _logger.error('try_alloc failed {}'.format(e), exc_info=True)
            return False

    @staticmethod
    def get_current_memory():
        used_info = UsedKvmInfo.get_kvm_used_info()
        used_memory_array = [i[0] for i in used_info]
        return sum(used_memory_array)

    @staticmethod
    def get_total_memory_mb():
        mem = psutil.virtual_memory()
        total_mb = mem.total // 1024 // 1024
        return total_mb - ((total_mb - 3 * 1024) // 5) - (3 * 1024)  # 至少保留 3GB + 剩余内存的1/5

    @staticmethod
    def get_total_memory_mb_for_takeover():
        return CAllocBigMM.get_total_memory_mb() - RESTORE_KVM_MEMORY_MB  # 至少保留可以启动一台还原kvm的内存

    @staticmethod
    def queryInfo():
        total_memory_mb_for_takeover = CAllocBigMM.get_total_memory_mb_for_takeover()
        one_cpu_number_for_takover = psutil.cpu_count()
        used_info = UsedKvmInfo.get_kvm_used_info()
        used_memory_mb = sum([i[0] for i in used_info])
        used_memory_mb_for_restore = sum([i[0] for i in used_info if 1 == i[2]])
        used_memory_mb_for_takover = sum([i[0] for i in used_info if 2 == i[2]])
        used_cpu_number = sum([i[1] for i in used_info])
        used_cpu_number_for_restore = sum([i[1] for i in used_info if 1 == i[2]])
        used_cpu_number_for_takover = sum([i[1] for i in used_info if 2 == i[2]])
        result = {
            'total_memory_mb_for_takeover': total_memory_mb_for_takeover,
            'total_cpu_number_for_takover': one_cpu_number_for_takover * 3,
            'one_memory_mb_for_takeover': total_memory_mb_for_takeover,
            'one_cpu_number_for_takover': one_cpu_number_for_takover,
            'used_memory_mb': used_memory_mb,
            'used_memory_mb_for_restore': used_memory_mb_for_restore,
            'used_memory_mb_for_takover': used_memory_mb_for_takover,
            'used_cpu_number': used_cpu_number,
            'used_cpu_number_for_restore': used_cpu_number_for_restore,
            'used_cpu_number_for_takover': used_cpu_number_for_takover,
        }
        return result


class UsedKvmInfo(object):
    @staticmethod
    def get_kvm_used_info():
        result = [(UsedKvmInfo.get_mem(p), UsedKvmInfo.get_cpu(p), UsedKvmInfo.get_type(p))
                  for p in psutil.process_iter() if UsedKvmInfo.is_equal_name(p)]
        _logger.info('find kvm process:{}'.format(result))
        return result

    @staticmethod
    @xlogging.convert_exception_to_value(False)
    def is_equal_name(x):
        return x.name() == 'qemu-kvm'


    @staticmethod
    @xlogging.convert_exception_to_value(0)
    def get_mem(ps_obj):
        find = False
        for line in ps_obj.cmdline():
            if find:
                return UsedKvmInfo.format_to_mb(line)
            if line == '-m':
                find = True
        return 0


    @staticmethod
    @xlogging.convert_exception_to_value(0)
    def get_cpu(ps_obj):
        find = False
        for line in ps_obj.cmdline():
            if find:
                p = re.compile('sockets=(\d),cores=(\d)')
                if not p.match(line):
                    return int(line)
                cpus = p.findall(line)
                if len(cpus) == 1:
                    sockets, cores = cpus[0]
                    return int(sockets) * int(cores)

            if line == '-smp':
                find = True
        return 0

    @staticmethod
    @xlogging.convert_exception_to_value(0)
    def get_type(ps_obj):
        find = False
        # 40000600-20170720-0-0-0 40000600-20170829-0-0-0
        p = re.compile('40000600-2017\d+-\w+-\w+-\w+')
        for line in ps_obj.cmdline():
            if find:
                if line == r'40000600-20160519-0-0-0':
                    return 1  # 还原用
                elif p.match(line):
                    return 2  # 接管用
                else:
                    return 0
            if line == '-cpuid':
                find = True
        return 0

    @staticmethod
    def format_to_mb(line):
        if str(line).upper().endswith('M'):
            return int(line[:-1])
        if str(line).upper().endswith('G'):
            return int(line[:-1]) * 1024
        return 0


if __name__ == "__main__":
    import logging
    import sys

    _logger.addHandler(logging.StreamHandler(sys.stdout))

    UsedKvmInfo.get_kvm_used_info()

    try_alloc = CAllocBigMM.try_alloc
    print(try_alloc(3000))
    print(try_alloc(6000))
    print(try_alloc(12000))
    print(try_alloc(24000))
