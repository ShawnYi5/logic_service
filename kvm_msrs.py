from net_common import get_info_from_syscmd
import logging


def ignore_kvm_msrs():
    # 启用ignore_msrs
    value, outs, errs = get_info_from_syscmd('echo 1 > /sys/module/kvm/parameters/ignore_msrs')
    # 查看ignore_msrs信息
    if value == 0:
        value, outs, errs = get_info_from_syscmd('cat /sys/module/kvm/parameters/ignore_msrs')
        if 'Y' in outs:
            logging.info('启用ignore_msrs成功'.format(outs))
        else:
            logging.warning('启用ignore_msrs失败'.format(errs))
    else:
        logging.warning('启用ignore_msrs失败'.format(errs))


if __name__ == "__main__":
    ignore_kvm_msrs()
