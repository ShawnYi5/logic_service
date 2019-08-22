from net_common import get_info_from_syscmd
import copy
import xlogging
import sys
import json
import time
import base64

try:
    import filelock
except ImportError:
    from . import filelock

_logger = xlogging.getLogger(__name__)

# 功能说明：
#
#
#
# 参考
#

'''
BOT	        The tape is positioned at the beginning of the first file.
EOT	        A tape operation has reached the physical End Of Tape.
EOF	        The tape is positioned just after a filemark.
WR_PROT     The tape (or drive) is write-protected. For some drives this can also mean that the drive does not 
                support writing on the current medium type.
ONLINE	    The drive has a tape in place and ready for operation.
DR_OPEN	    Door is open. Depending on the type of drive, this usually means that the drive does not have a tape in place.
IM_REP_EN	Immediate report mode. This bit is set if there are no guarantees that the data has been physically 
                written to the tape when the write call returns. It is set to zero only when the driver does not 
                buffer data and the drive is set not to buffer data.
SM	        The tape is currently positioned at a setmark. DDS specific.
EOD	        The tape is positioned at the end of recorded data. DDS specific.
D_6250
D_1600
D_800       This "generic" status information reports the current density setting for 9-track 1/2 inch tape drives only.

tapeinfo -f /dev/sg?
    Product Type: Tape Drive
    Vendor ID: 'IBM     '
    Product ID: 'ULT3580-TD4     '
    Revision: 'C7QH'
    Attached Changer API: No
    SerialNumber: '1310254051'
    MinBlock: 1
    MaxBlock: 16777215
    SCSI ID: 0
    SCSI LUN: 0
    Ready: no
tapeinfo -f /dev/nst?
    要多下面的信息：
    BufferedMode: yes
    Medium Type: 0x48
    Density Code: 0x46
    BlockSize: 65536
    DataCompEnabled: yes
    DataCompCapable: yes
    DataDeCompEnabled: yes
    CompType: 0x1
    DeCompType: 0x1
    BOP: yes
    Block Position: 0
    Partition 0 Remaining Kbytes: -1
    Partition 0 Size in Kbytes: -1
    ActivePartition: 0
    EarlyWarningSize: 0
'''
const_tape_drive_lockfile = r'/run/clerware_mc_tape_md_lock'

const_drv_ID = r"drv_ID"
const_status = r"status"
const_src_ID = r"src_ID"
const_VolumeTag = r"VolumeTag"
const_Full = r"Full"
const_Empty = r"Empty"
const_dr_open = r"dr_open"
const_wr_prot = r"wr_prot"
const_online = r"online"
const_SerialNumber = r"SerialNumber"
const_VendorID = r"VendorID"
const_ProductID = r"ProductID"
const_SCSI_ID = r"SCSI_ID"
const_SCSI_LUN = r"SCSI_LUN"
const_Ready = r"Ready"
const_BoxType = r"BoxType"
const_TapeBox = r"Tape"
const_SeBox = r"SeBox"
const_InoutBox = r"InoutBox"
const_EnumMC_Info = r"MCInfo"
const_yes = r"yes"

def get_tape_drive_lock():
    while True:
        tape_locker = filelock.file_ex_lock(const_tape_drive_lockfile)
        if tape_locker.try_lock():
            break
        _logger.info("lock_file_failed {}".format(const_tape_drive_lockfile))
        time.sleep(1)
    _logger.info("lock_file_success {}".format(const_tape_drive_lockfile))
    return tape_locker

def get_substr_from_string(allstr, keystr):
    valueStr = r""
    linelist = allstr.split('\n')
    for mstr in linelist:
        mstr = mstr.strip()
        snlist = mstr.split(keystr)
        if len(snlist) > 1:
            valueStr = snlist[1]
            valueStr = valueStr.strip()
            valueStr = valueStr.replace(r"'", r'_')
            _logger.info("key:{}, value:{}".format(keystr, valueStr))
            break
    return valueStr


def get_int_from_string(allstr, keystr):
    retv = -1
    substr = get_substr_from_string(allstr, keystr)
    if len(substr) > 0:
        retv = int(substr)
    _logger.info("{}={}".format(keystr, retv))
    return retv


def run_tape_cmd(cmd):
    _logger.info("runcmd {}".format(cmd))
    retval, outs, errinfo = get_info_from_syscmd(cmd)
    _logger.info("runcmd {} return:{} out:{} errorinfo:{}".format(retval, cmd, outs, errinfo))
    if retval != 0:
        str = "runcmd {} return:{} out:{} errorinfo:{}".format(retval, cmd, outs, errinfo)
        print(str)
        raise Exception(str)
    return retval, outs, errinfo


def run_tape_inf_cmd(devname):
    cmd = r'tapeinfo -f {}'.format(devname)
    retval, outs, errinfo = run_tape_cmd(cmd)
    return retval, outs, errinfo

def run_tape_inf_cmd_with_retry(devname,retry = 10):
    cmd = r'tapeinfo -f {}'.format(devname)
    for _ in range(retry):
        retval, outs, errinfo = run_tape_cmd(cmd)
        Ready = get_substr_from_string(outs, r'Ready:')
        if 'yes' == Ready:
            break
        _logger.info("retry tapeinfo {}".format(devname))
        time.sleep(1)
    return retval, outs, errinfo

def run_sn_inf_cmd(devname):
    cmd = r'/sbin/aio/sninfo -f {}'.format(devname)
    retval, outs, errinfo = run_tape_cmd(cmd)
    return retval, outs, errinfo

class tape_dev_mgr(object):
    def __init__(self, devname_nst_sg):
        self.__devname = copy.copy(devname_nst_sg[0])
        self.__devname_sg = copy.copy(devname_nst_sg[1])
        self.__retval = -1
        self.dr_open = True
        self.wr_prot = True
        self.online = False
        self.EOT = False
        self.EOD = False
        self.fileNo = -1
        self.blockNo = -1
        self.blksize = 0
        self.SerialNumber = r""
        self.BlockPosition = 0
        self.MaxBlock = 0
        self.VendorID = r""
        self.ProductID = r""
        self.SCSI_ID = -1
        self.SCSI_LUN = -1
        self.Ready = "no"

    def set_blksize(self, blksize):
        cmd = r'mt -f {} defblksize {}'.format(self.__devname, blksize)
        run_tape_cmd(cmd)
        self.update_tape_status()

    def tape_Forward_Backward(self, forward, count):
        cmd = r''
        if forward:
            cmd = r'mt -f {} fsf {}'.format(self.__devname, count)
        else:
            cmd = r'mt -f {} bsf {}'.format(self.__devname, count)
        run_tape_cmd(cmd)

    def tape_rewind(self):
        cmd = r'mt -f {} rewind'.format(self.__devname)
        run_tape_cmd(cmd)

    def seek_noretry(self, fileNO):
        self.update_tape_status()
        if 0 == fileNO or 1 == fileNO:
            #倒带到头或第一个文件：
            self.tape_rewind()
            if 1 == fileNO:
                self.tape_Forward_Backward(True, 1 )
            return
        if self.fileNo == fileNO:
            if self.blockNo == 0:
                #不需要移动。
                return
                # 居然不在文件的开始。倒车、再进一下。
            self.tape_Forward_Backward(False, 1)
            self.tape_Forward_Backward(True, 1)
            return

        if fileNO > self.fileNo:
            self.tape_Forward_Backward(True, fileNO - self.fileNo)
        else:
            #回退时，要多退一个文件，再fsf
            self.tape_Forward_Backward(False, 1 + self.fileNo - fileNO )
            self.tape_Forward_Backward(True, 1 )

    def seek(self, fileNO):
        _logger.info("{} seek file from {} to {})".format(self.__devname, self.fileNo, fileNO))
        try:
            for __ in range(3):
                try:
                    self.seek_noretry(fileNO)
                    break
                except:
                    continue
        except:
            pass
        self.update_tape_status()
        if self.fileNo != fileNO:
            _logger.info("{} seek file from {} to {} failed".format(self.__devname, self.fileNo, fileNO))
        return self.fileNo

    def update_TapeInfo(self,rewind=False):

        self.__retval, outs, errinfo = run_sn_inf_cmd(self.__devname_sg)
        self.SerialNumber = get_substr_from_string(outs, r'SerialNumber:')

        self.__retval, outs, errinfo = run_tape_inf_cmd(self.__devname_sg)
        self.VendorID = get_substr_from_string(outs, r'Vendor ID:')
        self.ProductID = get_substr_from_string(outs, r'Product ID:')
        self.SCSI_ID = get_int_from_string(outs, r'SCSI ID:')
        self.SCSI_LUN = get_int_from_string(outs, r'SCSI LUN:')
        self.MaxBlock = get_int_from_string(outs, r'MaxBlock:')
        self.Ready = get_substr_from_string(outs, r'Ready:')

        if self.Ready != const_yes:
            return
        if rewind:
            try:
                self.tape_rewind()
            except:
                pass

        try:
            self.__retval, outs, errinfo = run_tape_inf_cmd_with_retry(self.__devname)
        except:
            pass

        self.BlockPosition = get_int_from_string(outs, r'Block Position:')
        self.blksize = get_int_from_string(outs, r'BlockSize:')

    def in_string(self, allstr, substr):
        if substr in allstr:
            _logger.info("{}.{} ".format(self.__devname, substr))
            return True
        return False

    def update_tape_status(self,rewind=False):

        self.update_TapeInfo(rewind)

        try:
            cmd = r'mt -f {} status'.format(self.__devname)
            self.__retval, outs, errinfo = run_tape_cmd(cmd)
        except:
            return

        self.dr_open = self.in_string(outs, r'DR_OPEN')
        self.wr_prot = self.in_string(outs, r'WR_PROT')
        self.online = self.in_string(outs, r'ONLINE')
        self.EOT = self.in_string(outs, r'EOT')
        self.EOD = self.in_string(outs, r'EOD')

        linelist = outs.split('\n')
        for mstr in linelist:
            mstr = mstr.strip()
            fileNOlist = mstr.split(r'File number=')
            if len(fileNOlist) > 1:
                fileNOstr = fileNOlist[1]
                fileNOstr = fileNOstr.split(r',')[0]
                self.fileNo = int(fileNOstr)
                _logger.info("{} File number={}".format(self.__devname, self.fileNo))
            block_number_list = mstr.split(r'block number=')
            if len(block_number_list) > 1:
                block_number_NOstr = block_number_list[1]
                block_number_NOstr = block_number_NOstr.split(r',')[0]
                self.blockNo = int(block_number_NOstr)
                _logger.info("{} block number={}".format(self.__devname, self.blockNo))

        return


class Medium_Changer_devmgr(object):
    def __init__(self, devname):

        self.__devname = copy.copy(devname)
        self.__tape_drive_list = list()
        self.__storage_elmnt_list = list()
        self.__IMPORT_EXPORT_list = list()
        self.SerialNumber = 'Clerware'
        self.VendorID = 'Clerware'
        self.ProductID = 'Clerware'
        self.SCSI_ID = -1
        self.SCSI_LUN = -1
        self.Ready = 'no'
        xlogging.TraceDecorator([]).decorate()
        self.update_Medium_Changer()

    def get_tape_drive(self):
        return self.__tape_drive_list

    def get_storage_elmnt(self):
        return self.__storage_elmnt_list

    def get_IMPORT_EXPORT(self):
        return self.__IMPORT_EXPORT_list

    def update_DevInfo(self):

        self.__retval, outs, errinfo = run_sn_inf_cmd(self.__devname)
        self.SerialNumber = get_substr_from_string(outs, r'SerialNumber:')

        self.__retval, outs, errinfo = run_tape_inf_cmd(self.__devname)
        self.VendorID = get_substr_from_string(outs, r'Vendor ID:')
        self.ProductID = get_substr_from_string(outs, r'Product ID:')
        self.Ready = get_substr_from_string(outs, r'Ready:')
        self.SCSI_ID = get_int_from_string(outs, r'SCSI ID:')
        self.SCSI_LUN = get_int_from_string(outs, r'SCSI LUN:')

    '''
    Data Transfer Element 0:Full (Storage Element 1 Loaded):VolumeTag = DH1399L4                       
          Storage Element 1:Empty
          Storage Element 2:Full :VolumeTag=DH1397L4                       
          Storage Element 24 IMPORT/EXPORT:Empty
    '''

    def update_Medium_Changer(self):
        self.__tape_drive_list = list()
        self.__storage_elmnt_list = list()
        self.__IMPORT_EXPORT_list = list()
        self.update_DevInfo()
        cmd = r'mtx -f {} status'.format(self.__devname)
        self.__retval, outs, errinfo = run_tape_cmd(cmd)
        linelist = outs.split('\n')
        for mstr in linelist:
            mstr = mstr.strip()
            strlist = mstr.split(r':')
            if strlist is None or len(strlist) < 2:
                continue
            # Data Transfer Element 0:Full (Storage Element 1 Loaded):VolumeTag = DH1399L4
            strAA = strlist[0]
            strBB = strlist[1]

            elmnt_type = r""
            if r'Data Transfer Element' in strAA:
                elmnt_type = const_TapeBox
                strAA = strAA.replace(r'Data Transfer Element', r'')
            if r'Storage Element' in strAA:
                elmnt_type = const_SeBox
                strAA = strAA.replace(r'Storage Element', r'')
            if r'IMPORT/EXPORT' in strAA:
                elmnt_type = const_InoutBox
                strAA = strAA.replace(r'IMPORT/EXPORT', r'')
            if len(elmnt_type) <= 0:
                continue
            drv_info = dict()
            drv_NO = int(strAA.strip())
            drv_info[const_BoxType] = elmnt_type
            drv_info[const_drv_ID] = drv_NO
            VolumeTag = None
            if len(strlist) >= 3:
                VolumeTag = strlist[2]
                if r"AlternateVolumeTag" in VolumeTag:
                    _logger.warn("{} {}, unsupport AlternateVolumeTag".format(self.__devname, mstr))
                    continue
                VolumeTag = VolumeTag.replace(r'VolumeTag', r'')
                VolumeTag = VolumeTag.replace(r'=', r'')
                VolumeTag = VolumeTag.strip()

            drv_info[const_VolumeTag] = VolumeTag
            elmt_status = const_Full
            if const_Full in strBB:
                elmt_status = const_Full
                strBB = strBB.replace(const_Full, r'')
            if const_Empty in strBB:
                elmt_status = const_Empty
                strBB = strBB.replace(const_Empty, r'')
            drv_info[const_status] = elmt_status
            src_storage_elmnt = -1
            if not r'Unknown Storage Element Loaded' in strBB and r'Loaded' in strBB:
                strBB = strBB.replace(r'Storage Element', r'')
                strBB = strBB.replace(r'(', r'')
                strBB = strBB.replace(r')', r'')
                strBB = strBB.replace(r'Loaded', r'')
                src_storage_elmnt = int(strBB.strip())

            drv_info[const_src_ID] = src_storage_elmnt

            _logger.info(
                "{} append{},{},{},{},{}".format(self.__devname, elmnt_type, drv_NO, elmt_status, src_storage_elmnt,
                                                 VolumeTag))
            if const_TapeBox == elmnt_type:
                # drive
                self.__tape_drive_list.append(drv_info)
            elif const_SeBox == elmnt_type:
                # Storage Element
                self.__storage_elmnt_list.append(drv_info)
            elif const_InoutBox == elmnt_type:
                # IMPORT_EXPORT
                self.__IMPORT_EXPORT_list.append(drv_info)

    def load(self, src_storage_elmnt, dst_drive):
        cmd = r'mtx -f {} load {} {}'.format(self.__devname, src_storage_elmnt, dst_drive)
        self.__retval, outs, errinfo = run_tape_cmd(cmd)
        self.update_Medium_Changer()
        return

    def unload(self, src_drive, dst_storage_elmnt):
        cmd = r'mtx -f {} unload {} {} '.format(self.__devname, dst_storage_elmnt, src_drive)
        self.__retval, outs, errinfo = run_tape_cmd(cmd)
        self.update_Medium_Changer()
        return

    def get_drive_info(self, driveNO):
        for __drv in self.__tape_drive_list:
            if driveNO == __drv[const_drv_ID]:
                return __drv
        return None

    def get_free_storage_elmnt_ID(self):
        __freeID = list()
        for __drv in self.__storage_elmnt_list:
            if __drv[const_status] is const_Empty:
                __freeID.append(__drv[const_drv_ID])
        return __freeID

    def search_VolumeTag_from_list(self, __drvList, VolumeTag):
        for __drv in __drvList:
            if __drv[const_VolumeTag] == VolumeTag:
                return __drv
        return None

    def search_Volmue_form_all_Medium_Changer(self, VolumeTag):
        drv = self.search_VolumeTag_from_list(self.__tape_drive_list, VolumeTag)
        if drv != None:
            return drv
        drv = self.search_VolumeTag_from_list(self.__storage_elmnt_list, VolumeTag)
        if drv != None:
            return drv
        drv = self.search_VolumeTag_from_list(self.__IMPORT_EXPORT_list, VolumeTag)
        if drv != None:
            return drv
        return None

    def enum_all_box(self):
        allInfo = self.__tape_drive_list + \
                  self.__storage_elmnt_list + \
                  self.__IMPORT_EXPORT_list
        return allInfo

    def unload_drv_to_free(self, dst_drive):
        __freeIDs = list()
        __dstDrvInfo = self.get_drive_info(dst_drive)
        if const_Empty == __dstDrvInfo[const_status]:
            # 驱动器是空的。
            return

        __srcID = __dstDrvInfo[const_src_ID]
        if -1 != __srcID:
            __freeIDs.append(__srcID)  # 优先卸载到源来的盘位上。
        __freeIDs = __freeIDs + self.get_free_storage_elmnt_ID()
        for __crt_free in __freeIDs:
            try:
                try:
                    self.unload(dst_drive, __crt_free)
                    return
                except:
                    pass
                self.unload(dst_drive, __crt_free)
                return
            except:
                pass
        return

    def unload_all_drv_to_free(self):
        self.update_Medium_Changer()
        for __tmpdrv in self.__tape_drive_list:
            if const_Empty != __tmpdrv[const_status]:
                self.unload_drv_to_free(__tmpdrv[const_drv_ID])
        return

    def load_Volume(self, VolumeTag, dst_drive):
        _logger.info("{} load_Volume({},{})".format(self.__devname,VolumeTag,dst_drive))
        self.update_Medium_Changer()
        dstDrvInfo = self.get_drive_info(dst_drive)
        if VolumeTag == dstDrvInfo[const_VolumeTag]:
            return True,False
            # 当前磁带机中就是这个磁带。

        VolumeInfo = self.search_Volmue_form_all_Medium_Changer(VolumeTag)
        if VolumeInfo == None:
            str = "can not found {}!".format(VolumeTag)
            raise Exception(str)

        if VolumeInfo[const_BoxType] == const_TapeBox:
            # VolumeInfo可能还在别的Drive中，卸载到空的槽位。
            try:
                self.unload_drv_to_free(VolumeInfo[const_drv_ID])
            except:
                pass

        # 卷存在。
        # 先卸载之前的卷
        try:
            self.unload_drv_to_free(dst_drive)
        except:
            pass
        # 卸载完了，。

        dstDrvInfo = self.get_drive_info(dst_drive)
        if const_Empty != dstDrvInfo[const_status]:
            str = "unload drive failed!"
            raise Exception(str)

        # 卸载成功
        try:
            self.load(VolumeInfo[const_drv_ID], dst_drive)
        except:
            pass
        # 当前磁带机中就是这个磁带。
        dstDrvInfo = self.get_drive_info(dst_drive)
        if VolumeTag != dstDrvInfo[const_VolumeTag]:
            str = "unknow error ! load volume{}error,drv volume:{}!".format(VolumeTag, dstDrvInfo)
            _logger.error("add tape {}".format(str))
            raise Exception(str)
        return True,True

    def get_volume_list(self,drv_box):
        _volume_list = list()
        for __tmpVolTag in drv_box:
            if None != __tmpVolTag[const_VolumeTag]:
                _volume_list.append( __tmpVolTag[const_VolumeTag] )
        return _volume_list

    def get_first_VolumeTag_in_allbox(self):
        return self.get_volume_list(self.enum_all_box())

    def get_first_VolumeTag_no_in_drive(self):
        return self.get_volume_list(self.__storage_elmnt_list + self.__IMPORT_EXPORT_list)

    def load_any_Volume_2_all_drive(self):
        volume_list = self.get_first_VolumeTag_no_in_drive()

        for _one_drive in self.__tape_drive_list:
            if 0 == len(volume_list):
                return
            if const_Empty == _one_drive[const_status]:
                try:
                    self.load_Volume(volume_list.pop(0), _one_drive[const_drv_ID])
                except:
                    pass
        return

class mc_and_tape_mgr(object):
    def __init__(self):
        self.__tape_name_nst_sg__List = list()
        self.__mediumx_devList = list()
        self.scan_all_mc_tape_device()
        #self.load_any_volume_to_drive()

    def get_all_tape_name_sg_nst(self):
        return self.__tape_name_nst_sg__List

    def get_all_mediumx_dev(self):
        return self.__mediumx_devList

    def scan_all_mc_tape_device(self):
        self.__tape_name_nst_sg__List = list()
        self.__mediumx_devList = list()
        cmd = r'lsscsi -g'
        self.__retval, outs, errinfo = run_tape_cmd(cmd)
        __linelist = outs.split('\n')
        for __mstr in __linelist:
            __mstr = __mstr.strip()
            # [3:0:9:0]    tape    STK      T10000B          0105  /dev/st2
            for __n in range(20):
                __mstr = __mstr.replace(r'  ', r' ')

            strlist = __mstr.split(r' ')
            if strlist is None or len(strlist) < 4:
                continue
            if strlist[1] == 'tape':
                # tape
                tape_dev_name = strlist[len(strlist) - 2]
                # /dev/st2  -->  /dev/nst2
                tape_dev_name = tape_dev_name.replace(r'/dev/', r'/dev/n')

                tape_dev_name_sg = strlist[len(strlist) - 1]

                self.__tape_name_nst_sg__List.append([tape_dev_name,tape_dev_name_sg])
                _logger.info("add tape {}".format(tape_dev_name))

            if strlist[1] == 'mediumx':
                mediumx_sg_dev_name = strlist[len(strlist) - 1]
                self.__mediumx_devList.append(mediumx_sg_dev_name)
                _logger.info("add mediumx {}".format(mediumx_sg_dev_name))

    def load_any_volume_to_drive(self):
        for __mcdevName in self.get_all_mediumx_dev():
            try:
                __mcdev = Medium_Changer_devmgr(__mcdevName)
                __mcdev.update_Medium_Changer()
                __mcdev.load_any_Volume_2_all_drive()
            except:
                pass
        return

    def rewind_all_drive(self, tapeDevObjList):
        for _crtTapeDevObj in tapeDevObjList:
            _crtTapeDevObj.update_tape_status()
            if _crtTapeDevObj.Ready == const_yes:
                _crtTapeDevObj.tape_rewind()  # 有的设备要倒带后，才能查信息。
        return

    def get_all_tape_json(self):
        jsn_src = list()
        _tapeDevList = self.get_all_tape_name_sg_nst()
        for _TapedevName in _tapeDevList:
            tapedev = tape_dev_mgr(_TapedevName)
            tapedev.update_tape_status()
            one_Tape = dict()
            one_Tape[const_dr_open] = tapedev.dr_open
            one_Tape[const_wr_prot] = tapedev.wr_prot
            one_Tape[const_online] = tapedev.online
            one_Tape[const_SerialNumber] = tapedev.SerialNumber
            one_Tape[const_VendorID] = tapedev.VendorID
            one_Tape[const_ProductID] = tapedev.ProductID
            one_Tape[const_SCSI_ID] = tapedev.SCSI_ID
            one_Tape[const_SCSI_LUN] = tapedev.SCSI_LUN
            jsn_src.append(one_Tape)
        return json.dumps(jsn_src)

    def get_all_mediumx_json(self):
        mediumx_jsn_src = list()
        __mediumxDevList = self.get_all_mediumx_dev()
        for __mediumxName in __mediumxDevList:
            mcdev = Medium_Changer_devmgr(__mediumxName)
            one_mediumx = dict()
            one_mediumx[const_SerialNumber] = mcdev.SerialNumber
            one_mediumx[const_VendorID] = mcdev.VendorID
            one_mediumx[const_ProductID] = mcdev.ProductID
            one_mediumx[const_SCSI_ID] = mcdev.SCSI_ID
            one_mediumx[const_SCSI_LUN] = mcdev.SCSI_LUN
            one_mediumx[const_Ready] = mcdev.Ready

            ##加驱动器，槽位，进出口、磁带：
            one_mediumx[const_EnumMC_Info] = mcdev.enum_all_box()

            mediumx_jsn_src.append(one_mediumx)

        return json.dumps(mediumx_jsn_src)

    def unload_all_tape(self, mediumxDevList):
        for _onemc in mediumxDevList:
            _onemc.unload_all_drv_to_free()

    def is_all_tape_is_Offline(self, tapeDevObjList):
        for _crtTapeDevObj in tapeDevObjList:
            for t in range(2):
                _crtTapeDevObj.update_tape_status()
            if _crtTapeDevObj.online:
                return False
        return True

    def enum_all_online_tape(self, tapeDevObjList):
        _onlineTape = list()
        for _crtTapeDevObj in tapeDevObjList:
            for t in range(2):
                _crtTapeDevObj.update_tape_status(True)
            if _crtTapeDevObj.online:
                _onlineTape.append(_crtTapeDevObj)
        return _onlineTape

    # 这个函数很耗时，只扫描一次，手工扫描时才扫描一次。
    def enum_drive_to_mc_info_json(self):

        _tape_drive_locker = get_tape_drive_lock()

        # 开始枚举驱动器与 带库插槽关系：
        # 如果只有一个带库和插槽，也测试一下？
        tapeDevObjList = list()
        mcDevObjList = list()
        for _tapdevName in self.get_all_tape_name_sg_nst():
            tapeDevObjList.append(tape_dev_mgr(_tapdevName))
        for _mcdevName in self.get_all_mediumx_dev():
            mcDevObjList.append(Medium_Changer_devmgr(_mcdevName))

        try:
            self.load_any_volume_to_drive()
        except:
            pass
        try:
            self.rewind_all_drive(tapeDevObjList)
        except:
            pass

        _ret_DriveList = list()
        # 检查方法，将所有驱动弹出。
        # 一次只加载一个到驱动器中，找到对应关系。
        for _current_McDev in mcDevObjList:
            try:
                _current_driveList = _current_McDev.get_tape_drive()
                _testVolTagList = _current_McDev.get_first_VolumeTag_in_allbox()
                if 0 == len(_testVolTagList):
                    #没有一盘磁带。
                    _logger.error("need tapes > drives:{}")
                    continue # 忽略这个驱动器.
                _testVolTag = _testVolTagList[0]
                for _onedrv in _current_driveList:
                    try:
                        _testDrvID = _onedrv[const_drv_ID]
                        try:
                            self.unload_all_tape(mcDevObjList)
                        except:
                            _logger.error("unload_all_tape({}) failed.".format(mcDevObjList))
                        # 已经卸载了所有磁带。
                        tmpDrvInfo = _current_McDev.get_drive_info(_testDrvID)
                        if None != tmpDrvInfo[const_VolumeTag]:
                            _logger.error("unload all tape failed. VolumeTag.".format(tmpDrvInfo[const_VolumeTag]))
                            continue
                        if const_Empty != tmpDrvInfo[const_status]:
                            _logger.error("unload all tape failed. status.".format(tmpDrvInfo[const_status]))
                            continue
                        if not self.is_all_tape_is_Offline(tapeDevObjList):
                            _logger.error("is_all_tape_is_Offline false.")
                            continue
                        # 居然这个驱动器还有磁带。
                        # 加载一盘磁带到这个驱动器。
                        try:
                            _current_McDev.load_Volume(_testVolTag, _testDrvID)
                        except:
                            _logger.error("load_Volume({},{}) failed".format(_testVolTag, _testDrvID))
                            continue
                        try:
                            _current_McDev.update_Medium_Changer()
                        except:
                            _logger.error("update_Medium_Changer failed")

                        for _ in range(5):
                            try:
                                _onlineDevObjlist = self.enum_all_online_tape(tapeDevObjList)
                            except:
                                _logger.error("enum_all_online_tape failed")
                                continue
                            if len(_onlineDevObjlist) < 1:
                                continue
                            else:
                                break
                        if len(_onlineDevObjlist) == 1:
                            # 找到一个对应关系：
                            _ret_one_drv = dict()
                            _ret_one_drv['DriveSN'] = _onlineDevObjlist[0].SerialNumber
                            _ret_one_drv['MCSN'] = _current_McDev.SerialNumber
                            _ret_one_drv['MCBoxID'] = _testDrvID
                            _ret_DriveList.append(_ret_one_drv)
                        else:
                            _logger.error("len(_onlineDevObjlist):{}".format(len(_onlineDevObjlist)))
                    except:
                        pass
            except:
                pass
        _tape_drive_locker = None
        return { 'DriveList':_ret_DriveList }
        #return r'{"DriveList":[{"DriveSN":"_1310254051_","MCSN":"_00L2U78V9528_LL0_","MCBoxID": 0 }]}'

    def get_tape_devicename(self, sn):
        _tapeDevList = self.get_all_tape_name_sg_nst()
        for _tapdevName in _tapeDevList:
            try:
                _tapedev = tape_dev_mgr(_tapdevName)
                _tapedev.update_tape_status()
                if sn == _tapedev.SerialNumber:
                    return _tapdevName
            except:
                pass
        return None

    def get_one_link_info(self, tape_sn, drv_link_List):
        for _one in drv_link_List:
            if _one['DriveSN'] == tape_sn:
                return _one
        return None

    def get_mc_devicename(self, tape_sn, drv_link_List):

        _linkInfo = self.get_one_link_info(tape_sn, drv_link_List['DriveList'])

        _mc_sn = _linkInfo['MCSN']
        _mc_drv_id = _linkInfo['MCBoxID']

        for _mcdevName in self.get_all_mediumx_dev():
            try:
                _mcdev = Medium_Changer_devmgr(_mcdevName)
                _mcdev.update_Medium_Changer()
                if _mc_sn == _mcdev.SerialNumber:
                    return _mcdevName, _mc_drv_id
            except:
                pass
        return None


def enum_mc_hw_info(info):
    try:
        if info['fun'] == 'enum_tape':
            _logger.info("start enum_tape:")
            mc_tape = mc_and_tape_mgr()
            json_return = mc_tape.get_all_tape_json()
            _logger.info("enum_tape:{}".format(json_return))
            return json_return
        if info['fun'] == 'enum_mc':
            _logger.info("start enum_mc:")
            mc_tape = mc_and_tape_mgr()
            json_return = mc_tape.get_all_mediumx_json()
            _logger.info("enum_mc:{}".format(json_return))
            return json_return
        if info['fun'] == 'enum_link':
            _logger.info("start enum_link:")
            mc_tape = mc_and_tape_mgr()
            json_return = mc_tape.enum_drive_to_mc_info_json()
            _logger.info("enum_link:{}".format(json_return))
            return json_return
    except:
        return r"{}"


def print_mc_info(mcdev):
    print("file SerialNumber:{}".format(mcdev.SerialNumber))
    print("file VendorID:{}".format(mcdev.VendorID))
    print("file ProductID:{}".format(mcdev.ProductID))
    print("file SCSI_ID:{}".format(mcdev.SCSI_ID))
    print("file SCSI_LUN:{}".format(mcdev.SCSI_LUN))
    print("file Ready:{}".format(mcdev.Ready))

    drv_list = mcdev.get_tape_drive()
    for drv_info in drv_list:
        print("TapeDrive:{},{},{},{}".format(drv_info[const_drv_ID], drv_info[const_status], drv_info[const_src_ID],
                                             drv_info[const_VolumeTag]))

    drv_list = mcdev.get_storage_elmnt()
    for drv_info in drv_list:
        print("StoreElmnt:{},{},{},{}".format(drv_info[const_drv_ID], drv_info[const_status], drv_info[const_src_ID],
                                              drv_info[const_VolumeTag]))

    drv_list = mcdev.get_IMPORT_EXPORT()
    for drv_info in drv_list:
        print("IMPORT_EXPORT:{},{},{},{}".format(drv_info[const_drv_ID], drv_info[const_status], drv_info[const_src_ID],
                                                 drv_info[const_VolumeTag]))


if __name__ == "__main__":
    testfun = dict()

    testfun['fun'] = "enum_tape"
    print(enum_mc_hw_info(testfun))
    testfun['fun'] = "enum_mc"
    print(enum_mc_hw_info(testfun))
    for _ in range(3):
        testfun['fun'] = "enum_link"
        print(enum_mc_hw_info(testfun))

    '''
    mc_tape = mc_and_tape_mgr()
    str = mc_tape.get_all_tape_json()
    print(str)
    str = mc_tape.get_all_mediumx_json()
    print(str)
    mcdev = Medium_Changer_devmgr('/dev/sg2')
    mcdev.update_Medium_Changer()
    print_mc_info(mcdev)
    mcdev.load_Volume(r'DH1397L4', 0)
    mcdev.update_Medium_Changer()
    print_mc_info(mcdev)

    tapedev = tape_dev_mgr('/dev/nst0','/dev/sg1')

    tapedev.update_tape_status()

    print("file dr_open:{}".format(tapedev.dr_open))
    print("file wr_prot:{}".format(tapedev.wr_prot))
    print("file online:{}".format(tapedev.online))
    print("file EOT:{}".format(tapedev.EOT))
    print("file EOD:{}".format(tapedev.EOD))
    print("file fileNo:{}".format(tapedev.fileNo))
    print("file blksize:{}".format(tapedev.blksize))
    print("file SerialNumber:{}".format(tapedev.SerialNumber))
    print("file BlockPosition:{}".format(tapedev.BlockPosition))
    print("file MaxBlock:{}".format(tapedev.MaxBlock))
    print("file VendorID:{}".format(tapedev.VendorID))
    print("file ProductID:{}".format(tapedev.ProductID))
    print("file SCSI_ID:{}".format(tapedev.SCSI_ID))
    print("file SCSI_LUN:{}".format(tapedev.SCSI_LUN))
    print("file Ready:{}".format(tapedev.Ready))

    tapedev.seek(3)
    tapedev.seek(6)
    
    '''