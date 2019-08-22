from net_common import get_info_from_syscmd
import tarfile
import io
# from io import StringIO
# from io import BytesIO
import xlogging
_logger = xlogging.getLogger(__name__)

# 功能说明：
#
#
#
# 参考
#

class aaa(object):
    def __init__(self, str):
        self.a = 'a'

class bbb(aaa):
    def __init__(self,str):
        super(bbb, self).__init__(str)

    def print_info(self):
        print(self.a)


if __name__ == "__main__":

    xx = bbb('ffff')

    xx.print_info()


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