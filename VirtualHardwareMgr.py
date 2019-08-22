import xlogging

_logger = xlogging.getLogger(__name__)


class CVirtualHarddiskMgr(object):
    def __init__(self, disktype, bwritethrough):
        self.disktype = disktype
        self.bwritethrough = bwritethrough
        self.disk_count = 0
        if self.bwritethrough:
            self.writethrough = ",cache=writethrough"
        else:
            self.writethrough = ""

    def __del__(self):
        pass

    def get_disk_kvm_params(self, diskfile, wwid):
        kvm_params = None
        if self.disktype == 'scsi-hd':
            kvm_params = r" -drive file={file},if=none,id=drive-scsi0-0-{index}-0{writethrough}" \
                         r" -device scsi-hd,bus=scsi0.0,channel=0,scsi-id={index},lun=0,drive=drive-scsi0-0-{index}-0,serial={wwid}" \
                         r"".format(file=diskfile, writethrough=self.writethrough, index=self.disk_count + 1, wwid=wwid)
        elif self.disktype == 'IDE':
            if self.disk_count in (0, 1,):
                unit = self.disk_count
                kvm_params = r' -drive file={file},if=none,id=drive-ide{index}{writethrough}' \
                             r' -device ide-hd,bus=ide.0,unit={unit},drive=drive-ide{index},id=ide{index},serial={wwid}' \
                    .format(file=diskfile, index=self.disk_count, unit=unit, writethrough=self.writethrough, wwid=wwid)
            elif self.disk_count in (2, 3,):
                unit = self.disk_count - 2
                kvm_params = r' -drive file={file},if=none,id=drive-ide{index}{writethrough}' \
                             r' -device ide-hd,bus=ide.1,unit={unit},drive=drive-ide{index},id=ide{index},serial={wwid}' \
                    .format(file=diskfile, index=self.disk_count, unit=unit, writethrough=self.writethrough, wwid=wwid)
            else:
                _logger.error('get_disk_kvm_params IDE just suport 4 disk')
                kvm_params = ''

        elif self.disktype == 'virtio-blk':
            kvm_params = r" -drive file={file},if=none,id=drive-virtio-disk{index}{writethrough}" \
                         r" -device virtio-blk-pci,scsi=off,drive=drive-virtio-disk{index},serial={wwid}" \
                .format(file=diskfile, writethrough=self.writethrough, index=self.disk_count + 1, wwid=wwid)

        if self.disk_count == 0:
            kvm_params += ',bootindex=100'
        self.disk_count = self.disk_count + 1
        return kvm_params
