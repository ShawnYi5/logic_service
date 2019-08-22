import json
import os
import struct
import array
import mmap

import xlogging
_logger = xlogging.getLogger(__name__)


# 功能说明：
# 1、枚举解析MBR分区。
#      枚举出所有已经存在的分区。
# 2、重新构造MBR分区。
#     添加、删除、扩大、缩小、移动等。
# 3、解析GPT分区。
#      枚举出所有已经存在的分区。
# 4、重新构造GPT分区。
#     添加、删除、扩大、缩小、移动等。
#
#

from enum import Enum

mbrPTEtype = Enum('mbrPTEtype', ('primary', 'ext_first', 'logic', 'ext_next'))

g_win2008_mbr = bytes([
    0x33, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C, 0x8E, 0xC0, 0x8E, 0xD8, 0xBE, 0x00, 0x7C, 0xBF, 0x00,
    0x06, 0xB9, 0x00, 0x02, 0xFC, 0xF3, 0xA4, 0x50, 0x68, 0x1C, 0x06, 0xCB, 0xFB, 0xB9, 0x04, 0x00,
    0xBD, 0xBE, 0x07, 0x80, 0x7E, 0x00, 0x00, 0x7C, 0x0B, 0x0F, 0x85, 0x0E, 0x01, 0x83, 0xC5, 0x10,
    0xE2, 0xF1, 0xCD, 0x18, 0x88, 0x56, 0x00, 0x55, 0xC6, 0x46, 0x11, 0x05, 0xC6, 0x46, 0x10, 0x00,
    0xB4, 0x41, 0xBB, 0xAA, 0x55, 0xCD, 0x13, 0x5D, 0x72, 0x0F, 0x81, 0xFB, 0x55, 0xAA, 0x75, 0x09,
    0xF7, 0xC1, 0x01, 0x00, 0x74, 0x03, 0xFE, 0x46, 0x10, 0x66, 0x60, 0x80, 0x7E, 0x10, 0x00, 0x74,
    0x26, 0x66, 0x68, 0x00, 0x00, 0x00, 0x00, 0x66, 0xFF, 0x76, 0x08, 0x68, 0x00, 0x00, 0x68, 0x00,
    0x7C, 0x68, 0x01, 0x00, 0x68, 0x10, 0x00, 0xB4, 0x42, 0x8A, 0x56, 0x00, 0x8B, 0xF4, 0xCD, 0x13,
    0x9F, 0x83, 0xC4, 0x10, 0x9E, 0xEB, 0x14, 0xB8, 0x01, 0x02, 0xBB, 0x00, 0x7C, 0x8A, 0x56, 0x00,
    0x8A, 0x76, 0x01, 0x8A, 0x4E, 0x02, 0x8A, 0x6E, 0x03, 0xCD, 0x13, 0x66, 0x61, 0x73, 0x1C, 0xFE,
    0x4E, 0x11, 0x75, 0x0C, 0x80, 0x7E, 0x00, 0x80, 0x0F, 0x84, 0x8A, 0x00, 0xB2, 0x80, 0xEB, 0x84,
    0x55, 0x32, 0xE4, 0x8A, 0x56, 0x00, 0xCD, 0x13, 0x5D, 0xEB, 0x9E, 0x81, 0x3E, 0xFE, 0x7D, 0x55,
    0xAA, 0x75, 0x6E, 0xFF, 0x76, 0x00, 0xE8, 0x8D, 0x00, 0x75, 0x17, 0xFA, 0xB0, 0xD1, 0xE6, 0x64,
    0xE8, 0x83, 0x00, 0xB0, 0xDF, 0xE6, 0x60, 0xE8, 0x7C, 0x00, 0xB0, 0xFF, 0xE6, 0x64, 0xE8, 0x75,
    0x00, 0xFB, 0xB8, 0x00, 0xBB, 0xCD, 0x1A, 0x66, 0x23, 0xC0, 0x75, 0x3B, 0x66, 0x81, 0xFB, 0x54,
    0x43, 0x50, 0x41, 0x75, 0x32, 0x81, 0xF9, 0x02, 0x01, 0x72, 0x2C, 0x66, 0x68, 0x07, 0xBB, 0x00,
    0x00, 0x66, 0x68, 0x00, 0x02, 0x00, 0x00, 0x66, 0x68, 0x08, 0x00, 0x00, 0x00, 0x66, 0x53, 0x66,
    0x53, 0x66, 0x55, 0x66, 0x68, 0x00, 0x00, 0x00, 0x00, 0x66, 0x68, 0x00, 0x7C, 0x00, 0x00, 0x66,
    0x61, 0x68, 0x00, 0x00, 0x07, 0xCD, 0x1A, 0x5A, 0x32, 0xF6, 0xEA, 0x00, 0x7C, 0x00, 0x00, 0xCD,
    0x18, 0xA0, 0xB7, 0x07, 0xEB, 0x08, 0xA0, 0xB6, 0x07, 0xEB, 0x03, 0xA0, 0xB5, 0x07, 0x32, 0xE4,
    0x05, 0x00, 0x07, 0x8B, 0xF0, 0xAC, 0x3C, 0x00, 0x74, 0x09, 0xBB, 0x07, 0x00, 0xB4, 0x0E, 0xCD,
    0x10, 0xEB, 0xF2, 0xF4, 0xEB, 0xFD, 0x2B, 0xC9, 0xE4, 0x64, 0xEB, 0x00, 0x24, 0x02, 0xE0, 0xF8,
    0x24, 0x02, 0xC3, 0x49, 0x6E, 0x76, 0x61, 0x6C, 0x69, 0x64, 0x20, 0x70, 0x61, 0x72, 0x74, 0x69,
    0x74, 0x69, 0x6F, 0x6E, 0x20, 0x74, 0x61, 0x62, 0x6C, 0x65, 0x00, 0x45, 0x72, 0x72, 0x6F, 0x72,
    0x20, 0x6C, 0x6F, 0x61, 0x64, 0x69, 0x6E, 0x67, 0x20, 0x6F, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69,
    0x6E, 0x67, 0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6D, 0x00, 0x4D, 0x69, 0x73, 0x73, 0x69, 0x6E,
    0x67, 0x20, 0x6F, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6E, 0x67, 0x20, 0x73, 0x79, 0x73, 0x74,
    0x65, 0x6D, 0x00, 0x00, 0x00, 0x63, 0x7B, 0x9A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0xAA
])

# 参考
# https://en.wikipedia.org/wiki/GUID_Partition_Table
# https://en.wikipedia.org/wiki/Master_boot_record#PTE
# https://en.wikipedia.org/wiki/Partition_type
# https://en.wikipedia.org/wiki/Cylinder-head-sector

def print_one_sector(sec_buf):
    for i in range(0,0x200,0x10):
        str = r"{:03x}:   ".format(i)
        for n in range(0x10):
            str += r"{:02x}".format(sec_buf[i+n])
            if n == 7:
                str += r"-"
            else:
                str += r" "
        _logger.info(str)

def bytes_cmp(a,b):
    if not len(a) == len(b):
        return False
    for i in range(len(a)):
        if not a[i] == b[i]:
            return False
    return True

EMPTY_PARTITION = 0x0
DOS_EXTENDED_PARTITION = 5
LINUX_EXTENDED_PARTITION = 0x85
WIN98_EXTENDED_PARTITION = 0x0f
EFI_PMBR_OSTYPE_EFI_GPT = 0xEE

# 主分区： pte中记录的是绝对位置。
# extend_first: LBA中记录的是整个扩展分区的大小。
#               CHS中记录的是整个扩展分区的大小。
# extend_second: LBA中记录的是基于extend_first的相对位置和大小。
#                CHS中记录的是绝对地址和偏移
# 逻辑分区：     LBA中记录的是扩展分区表中的相对位置。
#                CHS中记录的是绝对地址和偏移

def is_empty_partition(partitionType):
    if partitionType == EMPTY_PARTITION:
        return True
    return False

def is_extended_partition(partitionType):
    if partitionType == DOS_EXTENDED_PARTITION or partitionType == LINUX_EXTENDED_PARTITION or partitionType == WIN98_EXTENDED_PARTITION:
        return True
    return  False

def is_GPT_ee(partitionType):
    if partitionType == EFI_PMBR_OSTYPE_EFI_GPT:
        return True
    return False

class CHS_and_LBA(object):
    def __init__(self, max_c = 1023, max_h = 0xff,max_s=0x3f ):
        if  max_c == 0 or max_h == 0 or max_s == 0:
            raise Exception("error chs {},{},{}".format(max_c,max_h,max_s) )
        self.__max_cy = max_c
        self.__max_head = max_h
        self.__max_sector = max_s
        # c * max_h * max_s + h * max_s + s - 1
        self.__max_lba = self.chs_2_lba(max_c,max_h-1,max_s)

    def max_chs_lba(self,lba):
        return min(lba , self.__max_lba)

    def lba_2_chs(self,u32LBA):
        if u32LBA >= self.__max_lba:
            return self.__max_cy,self.__max_head - 1,self.__max_sector
        new_s = 1 + ( u32LBA % self.__max_sector )
        new_h = ((u32LBA//self.__max_sector) % self.__max_head)
        new_c = ((u32LBA//self.__max_sector) // self.__max_head)
        return new_c,new_h,new_s

    def lba_2_chs_bin(self,u32LBA):
        new_c,new_h,new_s = self.lba_2_chs(u32LBA)
        chs_bin = []
        chs_bin.append( new_h )
        chs_bin.append( new_s + ((new_c>>2) & 0xc0) )
        chs_bin.append( new_c&0xff )

        return bytes(chs_bin)

    def chs_2_lba(self,c,h,s):
        return c * self.__max_head * self.__max_sector + h * self.__max_sector + s - 1

    def bin_chs_2_lba(self, chs_bin):
        int0 = int(chs_bin[0])
        int1 = int(chs_bin[1])
        int2 = int(chs_bin[2])
        new_h = int0
        new_s = 0x3f & int1
        new_c = int2
        new_c |= (0xc0 & int1) << 2
        lba = self.chs_2_lba(new_c, new_h, new_s)
        return lba

class class_PartitionEntry(object):
    __partEntry_unpack = r'<B3sB3sII' # 00:bootIndi   01:startCHS   04:partitionType   05:endCHS   08:StartLBA   0c:endCHS
    def __init__(self, ext_startLBA,logic_startLBA, ptEntry_bin, mbrCHS ):
        self.__MBRBootIndicator, self.__StartCHS , self.__PartitionType,self.__EndCHS,self.__StartLBA,self.__SectorCount = \
            struct.unpack(self.__partEntry_unpack, ptEntry_bin)
        self.__mbrCHS = mbrCHS
        self.__ext_startLBA = ext_startLBA
        self.__logic_startLBA = logic_startLBA

    def clean_Entry(self):
        self.__MBRBootIndicator = self.__PartitionType = self.__StartLBA = self.__SectorCount = 0
        self.__EndCHS = self.__StartCHS = bytes("\x00\x00\x00")

    def get_org_StartLBA(self):
        return self.__StartLBA

    def get_hidden_Sectors(self):
        return self.__StartLBA

    def get_StartLBA(self):
        if  is_extended_partition(self.__PartitionType):
            return self.__StartLBA + self.__ext_startLBA
        else:
            return self.__StartLBA + self.__logic_startLBA

    def get_SectorCount(self):
        return self.__SectorCount

    def get_PartitionType(self):
        return self.__PartitionType

    def is_empty(self):
        return is_empty_partition(self.__PartitionType)

    def set_partition(self,BootIndicator,PartitionType,StartLba,SecCount):
        if not self.is_empty():
            return False

        self.__MBRBootIndicator = BootIndicator
        self.__PartitionType = PartitionType

        if  is_extended_partition(self.__PartitionType):
            self.__StartLBA = StartLba - self.__ext_startLBA
        else:
            self.__StartLBA = StartLba - self.__logic_startLBA

        self.__StartCHS = self.__mbrCHS.lba_2_chs_bin(StartLba)
        self.__EndCHS = self.__mbrCHS.lba_2_chs_bin(StartLba+SecCount-1)

    def get_bytes(self):
        return struct.pack(self.__partEntry_unpack, self.__MBRBootIndicator, self.__StartCHS , self.__PartitionType,self.__EndCHS,self.__StartLBA,self.__SectorCount )

    def test_partition_chs(self):
        if self.is_empty():
            return True
        max_chs_lba = self.__mbrCHS.max_chs_lba(self.get_StartLBA())
        chs_2_lba = self.__mbrCHS.bin_chs_2_lba(self.__StartCHS)
        if not max_chs_lba == chs_2_lba:
            _logger.warning("lba:{:x} != chs:{:x}({:02x}-{:02x}-{:02x})".format(max_chs_lba,chs_2_lba,self.__StartCHS[0],self.__StartCHS[1],self.__StartCHS[2]))
            return False
        if not bytes_cmp( self.__StartCHS , self.__mbrCHS.lba_2_chs_bin(max_chs_lba) ) :
            _logger.warning("chs != LBA 2")
            return False

        max_chs_lba = self.__mbrCHS.max_chs_lba(self.get_StartLBA() + self.__SectorCount - 1)
        if not max_chs_lba == self.__mbrCHS.bin_chs_2_lba(self.__EndCHS):
            _logger.warning("chs != LBA 3")
            return False
        if not bytes_cmp( self.__EndCHS , self.__mbrCHS.lba_2_chs_bin(max_chs_lba) ):
            _logger.warning("chs != LBA 4")
            return False

        return True

class partitionTable_mbr(object):
    __mbr_unpack = r'<440sI2s64sH'   # 0x1b8:diskid   0x1bc:unused  0x1be:dps 0x1fe: 55aa
    def __init__(self, lba_chs, ext_startLBA , logic_startLBA,secBuf = bytes( [ 0 for n in range(0x200) ] ) ):
        self.__partitiontable = []
        self.__lba_chs = lba_chs
        self.__ext_startLBA = ext_startLBA
        self.__logic_startLBA = logic_startLBA

        if len(secBuf) != 0x200:
            raise Exception( "error secBuf.len():{}".format(len(secBuf)) )
        self.__bootcode,self.__diskid,self.unused,tmp_dsp,self.__bootflag = struct.unpack(self.__mbr_unpack,secBuf)
        for i in range(4):
            ptEntry = class_PartitionEntry( self.__ext_startLBA ,self.__logic_startLBA,tmp_dsp[i*16:(i+1)*16],self.__lba_chs )
            if not ptEntry.test_partition_chs():
                _logger.warning("error chs != LBA.")
            self.__partitiontable.append(ptEntry)

    def is_ValidDisk(self):
        if( self.__bootflag == 0xaa55 ):
            return True
        return False

    def is_gptDisk(self):
        if not self.is_ValidDisk():
            return False

        for i in range(4):
            if is_GPT_ee(self.__partitiontable[i].get_PartitionType()):
                return True
        return False

    def get_extend_partition(self):
        for i in range(4):
            if is_extended_partition(self.__partitiontable[i].get_PartitionType()):
                return self.__partitiontable[i]
        return None

    def get_all_primary(self):
        all_primary = []
        for i in range(4):
            ptype = self.__partitiontable[i].get_PartitionType()
            if is_empty_partition(ptype):
                continue
            if is_GPT_ee(ptype) or is_extended_partition(ptype):
                continue
            all_primary.append(self.__partitiontable[i])
        return all_primary

    def get_ptEntry(self,index):
        return self.__partitiontable[index]

    def del_ptEntry(self,index):
        self.__partitiontable[index].clean_Entry()

    def init_bootflag(self,use_2008_mbr = True):
        self.__bootflag = 0xaa55
        if use_2008_mbr:
            self.bootcode = g_win2008_mbr[0:440]

    def init_diskid(self,diskid,use_2008_mbr = True):
        self.__diskid = diskid

    def append_ptEntry(self,BootIndicator, type, StartLba, SecCount):
        for i in range(4):
            if self.__partitiontable[i].is_empty():
                self.__partitiontable[i].set_partition(BootIndicator, type, StartLba, SecCount)
                return True
        return False

    def get_sector_bytes(self):
        tmp_dsp = [ 0 for n in range(0x40) ]
        for i in range(4):
            tmp_dsp[i * 16:(i + 1) * 16] = self.__partitiontable[i].get_bytes()
        sec_buf = struct.pack(self.__mbr_unpack,self.__bootcode,self.__diskid,self.unused,bytes(tmp_dsp),self.__bootflag )
        return sec_buf


class disk_part_mbr(object):
    def __init__(self, lba_chs, devfilename ):
        self.__diskfd = open(devfilename, 'rb')
        self.__diskfd.seek(0, os.SEEK_END)
        self.__disk_size = self.__diskfd.tell()
        self.__disk_size = ( self.__disk_size + 511 ) // 512 * 512

        self.__mbr = partitionTable_mbr(lba_chs,0,0,self.get_one_sector(0))

        self.__primary = self.__mbr.get_all_primary()
        for i in range( len (self.__primary) ):
            _logger.warning(r'primary_parititon: {:x} : {:x} - {:x}'.format(self.__primary[i].get_PartitionType(), self.__primary[i].get_StartLBA(), self.__primary[i].get_SectorCount()))

        self.__base_extend = self.__mbr.get_extend_partition()
        if self.__base_extend is None:
            return

        '''
        from HrFSTable sub
    '''

        self.__ext_base = self.__base_extend.get_StartLBA()
        self.__ext_SectorCount = self.__base_extend.get_SectorCount()

        _logger.warning(r'extPartition {:x}: {:x} - {:x}'.format(self.__base_extend.get_PartitionType(),self.__ext_base, self.__ext_SectorCount ))

        part_start = 512*self.__ext_base
        part_end = 512*(self.__ext_base + self.__ext_SectorCount)

        self.check_partition_valid(0,part_start,part_end )
        next_lba = 0
        next_type = self.__base_extend.get_PartitionType()
        self.__logic = []
        while True:
            _logger.warning(r'Next Partition({:x}) {:x} + {:x} = {:x} '.format(next_type,self.__ext_base , next_lba ,self.__ext_base + next_lba ))
            logic = partitionTable_mbr(lba_chs, self.__ext_base, self.__ext_base + next_lba  ,self.get_one_sector(self.__ext_base + next_lba))
            if not logic.is_ValidDisk():
                break

            logicPart = logic.get_all_primary()
            for i in range(len(logicPart)):
                _logger.warning(r'logic_parititon: {:x}: {:x} - {:x}'.format(logicPart[i].get_PartitionType(), logicPart[i].get_StartLBA(),logicPart[i].get_SectorCount()))
            self.__logic.append(logic)
            next = logic.get_extend_partition()
            if next is None:
                break
            next_type = next.get_PartitionType()
            next_lba = next.get_org_StartLBA()

    def __del__(self):
        self.__diskfd.close()
        pass

    def get_one_sector(self,lba):
        bs = bytes()
        try:
            self.__diskfd.seek(0x200 * lba,os.SEEK_SET)
            bs = self.__diskfd.read(0x200)
        except Exception as e:
            _logger.error(r'read mbr error {}'.format(e))
            raise Exception("read mbr error")
        return bs

    def is_GPT(self):
        return self.__mbr.is_gptDisk()

    def check_partition_valid(self,base,start,end):
        if start > self.__disk_size:
            _logger.warning(r'{} partition lba:{:x} > disk size:{:x}'.format(base, start , self.__disk_size))
        if end >= self.__disk_size:
            _logger.warning(r'{} partition lba:{:x} > disk size:{:x}'.format(base, end , self.__disk_size))
        return
    def get_all_primary(self):
        return self.__primary

    def get_all_logic(self):
        return self.__logic


#class Extended_partition(object):
#    def __init__(self, mbrCHS, LBA, secBuf=bytes([0 for n in range(0x200)])):
#        self.__lba_chs = mbrCHS
#        self.__extpart_LBA = LBA
#        self.__extPart = mbr_partitionTable(self.__lba_chs, LBA, secBuf)
#        self.__extPart.get_all_primary()

if __name__ == '__main__':
    __lba_chs = CHS_and_LBA(0x3ff,0xff,0x3f)

    disk_part_mbr(__lba_chs,"/dev/nbd0")
'''
    mbr_new = partitionTable_mbr(__lba_chs)
    mbr_new.init_bootflag()
    mbr_new.init_diskid(0x11223344)
    mbr_new.append_ptEntry(0x80,0x7,0x800,0x32000)
    mbr_new.append_ptEntry(0x0, 0x7, 0x32800, 0xe095800 )
    mbr_new.append_ptEntry(0x0, 0x7, 0xe0c8000, 0x61bb9800)

    bs = mbr_new.get_sector_bytes()
    print_one_sector(bs)

    print(mbr_new.is_ValidDisk())
    # print(mbr.is_gptDisk())
'''
