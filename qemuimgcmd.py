import net_common
import xlogging

_logger = xlogging.getLogger(__name__)


class QemuImgCmd(object):

    def __init__(self):
        pass

    def create_qcow2_file_empty(self, new_qcow_file, size):
        rev = net_common.get_info_from_syscmd('qemu-img create -f qcow2 {path} {size}'.
                                              format(path=new_qcow_file, size=size))
        return rev

    def create_qcow2_file_base_old(self, base_file, new_qcow_file):
        rev = net_common.get_info_from_syscmd('qemu-img create -b {path_base} -f qcow2 {path}'.
                                              format(path=new_qcow_file, path_base=base_file))
        return rev


if __name__ == "__main__":
    print("end!")

    pass
