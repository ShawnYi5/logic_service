import os
import copy
import fcntl

class file_ex_lock(object):
    def __init__(self, filename):
        self.__filename = copy.copy(filename)
        self.__fd = 0

    def __del__(self):
        if self.__fd > 0 :
            # print("unlock")
            os.close(self.__fd)
            self.__fd = 0

    def try_lock(self):
        mode = os.O_RDWR | os.O_CREAT
        self.__fd = os.open(self.__filename, mode, 0o666)
        if self.__fd <= 0:
            return False
        try:
            fcntl.flock(self.__fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except:
            pass
        os.close(self.__fd)
        self.__fd = 0
        return False

if __name__ == "__main__":
    xlock = file_ex_lock(r'/run/clware_test_lock')
    print("try_lock{}".format(xlock.try_lock()))
    print("try_lock{}".format(xlock.try_lock()))
