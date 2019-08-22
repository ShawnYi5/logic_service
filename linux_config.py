import configparser
import itertools
import os
import time

import xlogging

_logger = xlogging.getLogger(__name__)


class ModifyConfig(object):
    def __init__(self, agent_app_path, restore_config):
        self.path = agent_app_path
        self.config = restore_config

        self.ini_file_path = os.path.join(self.path, "AgentService.ini")
        if not os.path.exists(self.ini_file_path):
            xlogging.raise_system_error("无法定位关键文件", "ModifyConfig AgentService.ini is not exists", 0)

        self.cfg_file_path = os.path.join(self.path, "AgentService.config")
        if not os.path.exists(self.cfg_file_path):
            xlogging.raise_system_error("无法定位关键文件", "ModifyConfig AgentService.config is not exists", 0)

    def modify_ini(self):
        if not self.config['user_info']:
            _logger.debug("not find user info, {}".format(self.config))
            return None
        self._start_modify(self.config, self.ini_file_path)

    def modify_cfg(self):
        if not self.config['aio_ip']:
            _logger.debug("not find aio ip info, {}".format(self.config))
            return None
        self._modify_cfg(self.config['aio_ip'], self.cfg_file_path)

    @staticmethod
    def _start_modify(source_content, path):
        us_info = source_content['user_info'].split('|')
        config = configparser.ConfigParser()
        with open(path, 'rt') as f:
            config.read_file(f)
        config.has_section('client') or config.add_section('client')
        config.set('client', 'userid', us_info[0])
        config.set('client', 'username', us_info[1])
        config.set('client', 'timestamp', str(time.time()))
        if source_content['aio_ip'] == '127.0.0.1':
            tunnel_ip = source_content['tunnel_ip']
            tunnel_port = source_content['tunnel_port']
            config.has_section('tunnel') or config.add_section('tunnel')
            config.set('tunnel', 'tunnelIP', tunnel_ip)
            config.set('tunnel', 'tunnelPort', tunnel_port)
            config.set('tunnel', 'proxy_listen', '20010|20011|20002|20003')
        else:
            config.remove_section('tunnel')

        config.has_section('restore') or config.add_section('restore')
        if source_content.get('restore_target', ''):
            config.set('restore', 'restore_target', source_content['restore_target'])
        else:
            pass
        if source_content.get('htb_task_uuid', ''):
            config.set('restore', 'htb_task_uuid', source_content['htb_task_uuid'])
        else:
            pass

        with open(path, 'wt') as f1:
            config.write(f1)

    @staticmethod
    def _modify_cfg(ip, path):
        config = configparser.ConfigParser()
        config.optionxform = str
        with  open(path, 'rt') as f:
            config.read_file(itertools.chain(['[fake_name] \n'], f))
        config.set('fake_name', 'Ice.Default.Host', ip)
        config.set('fake_name', 'SessionFactory.Proxy', 'agent:ssl -p 20011 -t 30000')
        config.set('fake_name', 'SessionFactoryTcp.Proxy', 'agent:tcp -p 20010 -t 30000')
        with open(path, 'w') as p1:
            for key, value in config.items('fake_name'):
                if ip != '127.0.0.1' and key in ('SessionFactory.Proxy', 'SessionFactoryTcp.Proxy'):
                    continue
                p1.write('{} = {}\n'.format(key, value))


if __name__ == '__main__':
    test_path = "/tmp/test"
    _content = {"user_info": "3|test", "aio_ip": "172.16.1.1"}
    modify_handle = ModifyConfig(test_path, _content)
    modify_handle.modify_ini()
    modify_handle.modify_cfg()
