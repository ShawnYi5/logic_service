import net_common
import xlogging
import json
import shlex
import subprocess
_logger = xlogging.getLogger(__name__)


def set_root_passwd(passwdinfo):
    cmdline = 'mount -no remount, rw /boot'
    retval = net_common.get_info_from_syscmd(cmdline)
    _logger.debug('remount /boot {} {}'.format(retval[0],retval[1]))
    tmpfile = '/dev/shm/tempstr'
    mpasswd = json.loads(passwdinfo)
    _logger.debug("set root pwd info {}       {}".format(passwdinfo,mpasswd))
    retval  = net_common.set_info_to_file(tmpfile,mpasswd,'w')
    if retval != 0:
        _logger.error('set passwd write file failed,ret {}'.format(retval))
        xlogging.raise_system_error('set passwd failed,{}'.format(retval),
                                    'set passwd failed,{}'.format(retval), -1, _logger)
    cmdline = 'set_passwd -f {}'.format(tmpfile)
    retval = net_common.get_info_from_syscmd(cmdline)
    if retval[0] != 0:
        _logger.error('set passwd failed,ret {} {}'.format(retval[0],retval[1]))
        xlogging.raise_system_error('set passwd failed,{}'.format(retval[0]),
                                    'set passwd failed,{}'.format(retval[0]), -1, _logger)
    else:
        _logger.debug('set passwd success')

    cmdline = 'umount /boot'
    retval = net_common.get_info_from_syscmd(cmdline)
    _logger.debug('umount /boot {} {}'.format(retval[0],retval[1]))

    cmdline = 'mount -o ro /dev/mapper/boot /boot'
    retval = net_common.get_info_from_syscmd(cmdline)
    _logger.debug('mount /dev/mapper/boot /boot {} {}'.format(retval[0],retval[1]))
    
def get_root_passwd():
    retval = net_common.get_info_from_file('/etc/aio/lock.rsa')
    if retval[0] != 0:
        _logger.error('get pwd info failed {},{}'.format(retval[0],retval[1]))
        xlogging.raise_system_error('get passwd failed,{}'.format(retval[0]),
                                    'get passwd failed,{}'.format(retval[0]), -1, _logger)
    else:
        passwdinfo = retval[1]
        _logger.debug('get pwd info {}', format(passwdinfo))
        return json.dumps(passwdinfo)
if __name__ == "__main__":
    mpasswd = "~!@#$%&*()_+|:\\<>?,.;[]`=-"
    # mpasswd = "test"
    set_root_passwd(json.dumps(mpasswd))