# coding=utf-8
# !/usr/bin/python
# from net_common import get_info_from_syscmd

import os
import signal
import subprocess
import tempfile
import traceback
import tarfile
import io
import threading
import struct
import xlogging
import time
import copy

NUL = b"\0"

_logger = xlogging.getLogger(__name__)

# 功能说明：
#
#
#
# 参考
#

class TapeFileobj(object):
    def __init__(self,tar_out_devname):
        self.__tar_out_devname = tar_out_devname
        self.__fd = 0
        try:
            mode = os.O_WRONLY | os.O_APPEND
            self.__fd = os.open(tar_out_devname, mode, 0o666)
        except Exception as e:
            str ="os.open{} error:{}".format(tar_out_devname, e)
            _logger.error(str)
            raise Exception(str)
        _logger.info("os.open{} success fd:{}".format(tar_out_devname,self.__fd ))

    def close(self):
        if self.__fd != 0:
            os.close(self.__fd)
            self.__fd = 0
`
    def tell(self):
        return 0

    def read(self,size):
        return bytearray([0 for n in range(size)])

    def write(self,bs):
        os.write(self.__fd,bs)

class tar_tapefs(object):
    def __init__(self,tar_out_devname):
        self.__current_filename = None
        self.__locker = threading.RLock()
        self.__tar_out_devname = tar_out_devname
        self.__tapeFobj = TapeFileobj(self.__tar_out_devname)
        self.__tarclass = tarfile.TarFile(fileobj=self.__tapeFobj,mode='w')
        self.__bufcache = b''

    def add_file(self,filename,filesize):
        _logger.info("tar_tapefs.add_file{},size:{}".format(filename,filesize))
        if self.__current_filename is not None:
            _logger.info("tar_tapefs.add_file{} error! close {} first!".format(filename,self.__current_filename))
            raise Exception("tar_tapefs.add_file{} error! close {} first!".format(filename,self.__current_filename))
        self.__current_filename = filename
        self.__filesize = filesize
        self.__donesize = 0

    def write(self,bs):
        if self.__current_filename is None:
            raise Exception("write error: no file add!")

        if len(bs) == 0:
            return
        blocks, remainder = divmod(len(bs), tarfile.BLOCKSIZE)
        if remainder !=0 :
            raise Exception("write error: bs size error: {},Must be a multiple of 512".format(len(bs)))

        with self.__locker:
            if self.__donesize == 0:
                self.__tarinfo = tarfile.TarInfo(self.__current_filename)
                self.__tarinfo.size = self.__filesize
                self.__tarinfo.mtime = int(time.time())
                buf = self.__tarinfo.tobuf(self.__tarclass.format, self.__tarclass.encoding, self.__tarclass.errors)
                self.__tarclass.fileobj.write(buf)
                self.__tarclass.offset += len(buf)

            self.__tarclass.fileobj.write(bs)
            self.__tarclass.offset += blocks * tarfile.BLOCKSIZE
            self.__donesize += len(bs)
            if self.__donesize > self.__filesize:
                _logger.info("file{} overwrite done:{} > filesize{}!".format(self.__current_filename,self.__donesize,self.__filesize))
                raise Exception("file{} overwrite done:{} > filesize{}!".format(self.__current_filename,self.__donesize,self.__filesize))

    def end_file(self):

        if self.__current_filename is None:
            raise Exception("end_file error: no file add!")
        self.__current_filename = None

        if self.__donesize != self.__filesize:
            raise Exception("end_file error: file done:{} != size:{}".format(self.__donesize , self.__filesize))

        self.__tarclass.members.append(self.__tarinfo)
        self.__tarinfo = None

    def close(self):
        if self.__current_filename is not None:
            raise Exception("end_file must call before close!")
        if self.__tarclass is not None:
            self.__tarclass.close()
        if self.__tapeFobj is not None:
            self.__tapeFobj.close()
        self.__tarclass = None
        self.__tapeFobj = None

class test_tape_dev(object):

    def __init__(self,tapeDevName):

        #self.write_file(tapeDevName)
        #return

        tarfs = tar_tapefs(tapeDevName)

        size_of_buf = 1024*1024
        count_of_blk = 1024
        tarfs.add_file("abc",count_of_blk*size_of_buf)

        #secBuf = bytearray([0 for n in range(size_of_buf)])
        secBuf = bytearray(size_of_buf)

        for ii in range(size_of_buf):
            secBuf[ii] = ii%256
            #    struct.pack(r"B", ii%256 )

        for count in range(count_of_blk):
            try:
                tarfs.write(secBuf)
            except Exception as e:
                _logger.info("e{}!".format(e))
        tarfs.end_file()

        """
        tarfs.add_file("ccc", 20)
        tarfs.write(b"0123456789")
        tarfs.write(b"0123456789")
        tarfs.end_file()
        """
        tarfs.close()

        #self.write_file(tapeDevName)
        #self.write_file(tapeDevName)

    def write_file(self,tapeDevName):
        mode = os.O_WRONLY | os.O_APPEND
        self.fd = os.open(tapeDevName, mode, 0o666)
        size_of_buf = 1024*1024
        secBuf = bytearray([0 for n in range(size_of_buf)])
        for ii in range(size_of_buf):
            secBuf[ii] = struct.pack(r"B", ii%256 )
            pass
        os.write(self.fd , secBuf )
        os.close(self.fd)


if __name__ == "__main__":

    test_tape_dev('/dev/nst0')

    '''
    tar = tarfile.TarFile("./ffff/ffff.tar","w")
    
    string = io.StringIO()
    string.write("hello")
    string.seek(0)

    content = "test write tar"
    data = content.encode('utf-8')
    f = io.BytesIO(data)
    info = tarfile.TarInfo(name="foo")
    info.size = len(data)
    tar.addfile(tarinfo=info, fileobj=f)
    tar.close()
    '''