import os
import subprocess

import xlogging

_logger = xlogging.getLogger(__name__)


class GetModFirmware(object):
    def __init__(self, kernel_version, root_path):
        self.kernel_version = kernel_version
        self.root_path = root_path

    def get_firmware(self, mod_path):
        cmd = "modinfo {modpath} -k {kernel_version} -b {root_path}".format(modpath=mod_path,
                                                                            kernel_version=self.kernel_version,
                                                                            root_path=self.root_path)
        info = self._exe_cmd(cmd)
        if info is None:
            return -1, []
        if info[0] != 0:
            _logger.error("GetModDep error ,cmd:{}, stdout:{}, error:{},".format(cmd, info[1], info[2]))
            return -1, []
        else:
            _logger.info("GetModDep success,info{}".format(info[1]))
            dep_list = list()
            self._get_firmware_info(info[1], dep_list)
            dep_list = list(map(lambda x: os.path.join(self.root_path, 'lib', 'firmware', x), dep_list))
            return 0, dep_list

    @staticmethod
    def _exe_cmd(cmd):
        _logger.info("GetModDep _exe_cmd cmd {}".format(cmd))
        with subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True,
                              universal_newlines=True) as p:
            try:
                stdout, stderr = p.communicate(timeout=120)
            except subprocess.TimeoutExpired:
                p.kill()
                stdout, stderr = p.communicate()
                _logger.error("GetModDep _exe_cmd timeout cmd:{}, stdout:{}, stderr:{},".format(cmd, stdout, stderr))
                return None
        return p.returncode, stdout, stderr

    @staticmethod
    def _get_firmware_info(content, dep_list):
        content_list = content.split("\n")
        for line in content_list:
            if line.strip().startswith("firmware"):
                dep_list.append(line.strip().split()[1].strip())


if __name__ == '__main__':
    mod_path0 = '/home/tmp/kvm_linux/129a1ccb03d44637828cb6a6c8c03973/lib/modules/3.10.0-229.el7.x86_64/kernel/drivers/net/ethernet/intel/e1000/e1000.ko'
    mod_path1 = '/home/tmp/kvm_linux/129a1ccb03d44637828cb6a6c8c03973/lib/modules/3.10.0-229.el7.x86_64/kernel/drivers/ata/ata_piix.ko'
    mod_path2 = '/home/tmp/kvm_linux/129a1ccb03d44637828cb6a6c8c03973/lib/modules/3.10.0-229.el7.x86_64/kernel/drivers/net/ethernet/broadcom/bnx2.ko'
    _root_path = '/home/tmp/kvm_linux/129a1ccb03d44637828cb6a6c8c03973'
    _kernel_version = "3.10.0-229.el7.x86_64"
    for path in [mod_path0, mod_path1, mod_path2]:
        path = os.path.join(_root_path, path)
        getmod = GetModFirmware(_kernel_version, _root_path)
        print(getmod.get_firmware(path))
