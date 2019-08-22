import os, struct
import time
from datetime import datetime

try:
    import xlogging
except:
    import logging as xlogging

_logger = xlogging.getLogger(__name__)

'''
磁盘文件结构
0扇区
flag[32] 6fc3c575b2de4da886f69b126b4d5ffa
syn[32] 多进程同步
reserve[448]
1扇区
head[8] 11111111（在用）或44444444（删除）
next_head_offset[8]
filename[168]
filesize[8]
文件内容
'''


class CMyFileSystem():
    def __init__(self, binfile):
        self.logger = _logger
        self.data_offset = 10240
        self.binfile = binfile

    def ReadBuffer(self, offset, length):
        file_object = open(self.binfile, 'rb')
        try:
            file_object.seek(offset, os.SEEK_SET)
            ret_byte = file_object.read(length)
        finally:
            file_object.close()
        return ret_byte

    def _isSynFlag(self, flag):
        # 如果为时间格式，则时间大于60S，则认为Flag无效
        try:
            flag = flag.decode('utf-8')
        except:
            pass
        return False

    def _findOffset(self):
        # 查找第一个可写的offset
        i = 0
        offset = self.data_offset + 512
        while True:
            i = i + 1
            if offset > 0x7FFFFE00:
                return -1
            head = self.ReadBuffer(offset, 16)
            if head[0:8] == b'\x01\x01\x01\x01\x01\x01\x01\x01' or head[0:8] == b'\x04\x04\x04\x04\x04\x04\x04\x04':
                offset = struct.unpack('Q', head[8:16])[0]
                continue
            return offset
        return -1

    def getFileList(self):
        '''
        head[8] 11111111（在用）或44444444（删除）
        next_head_offset[8]
        filename[168]
        filesize[8]
        文件内容
        '''
        filelist = list()
        offset = self.data_offset + 512
        sector = self.ReadBuffer(offset, 512)
        while True:
            if sector[0:8] == b'\x01\x01\x01\x01\x01\x01\x01\x01' or sector[0:8] == b'\x04\x04\x04\x04\x04\x04\x04\x04':
                next_head_offset = struct.unpack('Q', sector[8:16])[0]
                filename = sector[16:184]
                filesize = struct.unpack('Q', sector[184:192])[0]
                onefile = dict()
                onefile['filename'] = filename.decode('utf-8').replace('\x00', '')
                onefile['filesize'] = filesize
                onefile['offset'] = offset
                filelist.append(onefile)
                sector = self.ReadBuffer(next_head_offset, 512)
                offset = next_head_offset
                if len(sector) == 0:
                    self.logger.info('getFileList Failed.len(sector) == 0')
                    break
            else:
                break
        return filelist

    def getOneFile(self, onefile, filePath):
        writesize = 0
        offset = onefile["offset"] + 192
        filesize = onefile["filesize"]
        with open(filePath, 'ab') as binfile:
            buffersize = 50 * 1024
            while True:
                if filesize > writesize:
                    if buffersize + writesize > filesize:
                        buffersize = filesize - writesize
                    file_bytes = self.ReadBuffer(offset, buffersize)
                    if len(file_bytes) > 0:
                        binfile.write(file_bytes)
                        writesize += buffersize
                        offset += buffersize
                    else:
                        break
                else:
                    break


def getRawDiskFiles(binpath, destpath):
    if not os.path.isfile(binpath):
        return 2
    if not os.path.isdir(destpath):
        return 2
    myFileSystem = CMyFileSystem(binpath)
    filelist = myFileSystem.getFileList()
    for one in filelist:
        tmppath = os.path.join(destpath, one['filename'])
        while os.path.isfile(tmppath):
            filename = datetime.now().strftime('%Y_%m_%dT%H_%M_%S.f') + one['filename']
            tmppath = os.path.join(destpath, filename)
        myFileSystem.getOneFile(one, tmppath)
    return 0


if __name__ == "__main__":
    if False:
        getRawDiskFiles(r'D:\test\test.vhd', r'D:\test\re')
