import json
import os
import threading
import uuid

import nbd
import xlogging

_logger = xlogging.getLogger(__name__)

_threading_op_locker = threading.Lock()
_threading_pools = dict()


class MountSnapshot(object):
    @staticmethod
    def mount_snapshot(json_args):
        _logger.info("MountSnapshot mount_snapshot json_args:{}".format(json_args))
        result_mount_snapshot = dict()
        j_args = json.loads(json_args)
        snapshots = j_args.get('snapshots', None)
        not_need_nbd = j_args.get('not_need_nbd', False)
        if snapshots and (not not_need_nbd):
            # 初始化一个 nbd 对象
            nbd_object = nbd.nbd_wrapper(
                nbd.nbd_wrapper_disable_lvm_allocator(nbd.nbd_wrapper_local_device_allocator()))
            device_path = nbd_object.device_path
            device_name = nbd_object.device_name
            # 挂载  (线程)
            nbd_thread = nbd.nbd_direct_images(device_name, nbd_object, snapshots)
            nbd_thread.start()
            nbd.nbd_wrapper.wait_nbd_read_ok(nbd_object)
            nbd_indet = uuid.uuid4().hex
            result_mount_snapshot['nbd_device_path'] = device_path
            result_mount_snapshot['nbd_object_uuid'] = nbd_indet
            with _threading_op_locker:
                _threading_pools[nbd_indet] = nbd_object
        else:
            result_mount_snapshot['nbd_device_path'] = None
            result_mount_snapshot['nbd_object_uuid'] = None
        _logger.info("MountSnapshot mount_snapshot result_mount_snapshot:{}".format(result_mount_snapshot))
        return result_mount_snapshot

    @staticmethod
    def unmount_snapshot(json_args):
        j_args = json.loads(json_args)
        for stop_optimize in j_args:
            device_path_uuid = stop_optimize['nbd_object_uuid']
            with _threading_op_locker:
                device_object = _threading_pools.pop(device_path_uuid, None)
            if device_object:
                device_object.unmount()
                device_object.wait_no_mounting()
                device_object.set_no_longer_used()
            if 'hash_file_path' in stop_optimize and os.path.exists(stop_optimize['hash_file_path']) and \
                    stop_optimize.get('delete_hash', True):
                os.remove(stop_optimize['hash_file_path'])
        return True
