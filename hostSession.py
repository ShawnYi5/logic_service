import json
import logging

import requests

import authCookies
import http_status
import xlogging

logging.getLogger("requests").setLevel(logging.WARNING)

_logger = xlogging.getLogger(__name__)


def http_query_host_name(ident, host_name, user_ident, sysinfo):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/hosts/')

    json_body = json.dumps(
        {'user_ident': user_ident, 'macs': ident.Hardware, 'host_name': host_name, 'sysinfo': sysinfo})

    r = requests.post(f_url,
                      headers={'content-type': 'application/json; charset=utf-8', 'x-csrftoken': csrf_token},
                      data=json_body,
                      cookies=secure_cookie)
    if http_status.is_success(r.status_code):
        return r.json()['ident']
    else:
        error_description = '获取客户端标识号失败：{}'.format(r.status_code)
        error_debug = 'http_query_host_name call web api failed. [{}] :{}'.format(f_url, r.status_code)
        xlogging.raise_system_error(error_description, error_debug, r.status_code, _logger)


def http_login(host_name, host_ip, local_ip, tunnel_index):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/hosts/sessions/')

    json_body = json.dumps(
        {'host_ident': host_name, 'host_ip': host_ip, 'local_ip': local_ip, 'tunnel_index': tunnel_index})
    response = requests.post(f_url,
                             headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                             data=json_body,
                             cookies=secure_cookie)

    if http_status.is_success(response.status_code):
        return True
    elif response.status_code == http_status.HTTP_429_TOO_MANY_REQUESTS:
        return False
    else:
        error_description = r'客户端登陆失败：{}'.format(response.status_code)
        error_debug = r'http_login call web api failed. [{}] :{}'.format(f_url, response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_logout(host_name):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/hosts/sessions/{}/'.format(host_name))
    response = requests.delete(f_url,
                               headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                               cookies=secure_cookie)

    if http_status.is_success(response.status_code):
        return
    else:
        error_description = r'客户端注销失败：{}'.format(response.status_code)
        error_debug = r'http_logout call web api failed. [{}] :{}'.format(f_url, response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_query_host_soft_ident(host_name):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/hosts/{}'.format(host_name))

    r = requests.get(f_url,
                     headers={'content-type': 'application/json; charset=utf-8', 'x-csrftoken': csrf_token},
                     data='',
                     cookies=secure_cookie)
    if http_status.is_success(r.status_code):
        soft_ident = r.json().get('soft_ident', '')
        if soft_ident:
            return soft_ident
        else:
            xlogging.raise_system_error(r'无效的客户端标识', r'http_query_host_soft_ident empty', 0, _logger)
    else:
        error_description = '获取客户端标识失败：{}'.format(r.status_code)
        error_debug = 'http_query_host_soft_ident call web api failed. [{}] :{}'.format(f_url, r.status_code)
        xlogging.raise_system_error(error_description, error_debug, r.status_code, _logger)


def http_clear_all():
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/hosts/sessions/')
    response = requests.delete(f_url,
                               headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                               cookies=secure_cookie)

    if http_status.is_success(response.status_code):
        return
    else:
        error_description = r'注销所有客户端失败：{}'.format(response.status_code)
        error_debug = r'http_clear_all call web api failed. [{}] :{}'.format(f_url, response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_report_agent_module_error(host_name, ame):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/hosts/sessions/{}/'.format(host_name))
    response = requests.put(f_url,
                            data=json.dumps(ame.__dict__),
                            headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                            cookies=secure_cookie)
    if http_status.is_success(response.status_code):
        return
    else:
        error_description = r'提交Agent初始化错误失败：{}'.format(response.status_code)
        error_debug = r'http_report_agent_module_error call web api failed. [{}] :{}'.format(f_url,
                                                                                             response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_report_backup_progress(host_name, progress):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/hosts/sessions/{}/backup/'.format(host_name))
    response = requests.put(f_url,
                            data=json.dumps({'code': progress.code.value, 'progressIndex': progress.progressIndex,
                                             'progressTotal': progress.progressTotal}),
                            headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                            cookies=secure_cookie)
    if http_status.is_success(response.status_code):
        return
    else:
        error_description = r'提交备份进度失败：{}'.format(response.status_code)
        error_debug = r'http_report_backup_progress call web api failed. [{}] :{}'.format(f_url,
                                                                                          response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_report_backup_finish(host_name, code):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(
        r'apiv1/hosts/sessions/{}/backup/?code={}'.format(host_name, code.value))
    response = requests.delete(f_url,
                               headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                               cookies=secure_cookie)
    if http_status.is_success(response.status_code):
        return
    else:
        error_description = r'提交备份完成失败：{}'.format(response.status_code)
        error_debug = r'http_report_backup_finish call web api failed. [{}] :{}'.format(f_url,
                                                                                        response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_pe_host_clear_all():
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/pe_hosts/sessions/')
    response = requests.delete(f_url,
                               headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                               cookies=secure_cookie)

    if http_status.is_success(response.status_code):
        return
    else:
        error_description = r'注销所有还原目标客户端失败：{}'.format(response.status_code)
        error_debug = r'http_pe_host_clear_all call web api failed. [{}] :{}'.format(f_url, response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_pe_host_login(disk_info_list, remoteAddress, localAddress, boot_disk_id, login_type, tunnel_index, more_info):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/pe_hosts/sessions/')

    disks = list()
    for disk in disk_info_list:
        disks.append(disk.__dict__)
    json_body = json.dumps(
        {'disks': disks, 'remote_ip': remoteAddress, 'local_ip': localAddress, 'boot_disk_id': boot_disk_id,
         'login_type': login_type, 'tunnel_index': tunnel_index, 'more_info': more_info, })

    response = requests.post(f_url,
                             headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                             data=json_body,
                             cookies=secure_cookie)

    if http_status.is_success(response.status_code):
        return response.json()['ident']
    else:
        error_description = r'还原目标客户端登陆失败：{}'.format(response.status_code)
        error_debug = r'http_pe_host_login call web api failed. [{}] :{}'.format(f_url, response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_pe_host_logout(host_ident):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/pe_hosts/sessions/{}/'.format(host_ident))
    response = requests.delete(f_url,
                               headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                               cookies=secure_cookie)

    if http_status.is_success(response.status_code):
        return
    else:
        error_description = r'还原目标客户端注销失败：{}'.format(response.status_code)
        error_debug = r'http_pe_host_logout call web api failed. [{}] :{}'.format(f_url, response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_get_cdp_new_name(token, last_file_path):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/cdps/{}/?last_path={}'.format(token, last_file_path))

    response = requests.get(f_url,
                            headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                            cookies=secure_cookie)

    if http_status.is_success(response.status_code):
        pass
    else:
        error_description = r'更新CDP Token失败，错误代码：{}'.format(response.status_code)
        error_debug = r'http_get_cdp_new_name failed. [{}] :{}'.format(f_url, response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_close_cdp_token(token):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/cdps/{}/'.format(token))

    response = requests.delete(f_url,
                               headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                               cookies=secure_cookie)

    if http_status.is_success(response.status_code):
        return
    else:
        error_description = r'关闭CDP Token失败，错误代码：{}'.format(response.status_code)
        error_debug = r'http_close_cdp_token failed. [{}] :{}'.format(f_url, response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_refresh_token(token):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/tokens/{}/'.format(token))

    response = requests.get(f_url,
                            headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                            cookies=secure_cookie)

    if http_status.is_success(response.status_code):
        pass
    else:
        error_description = r'获取Token信息失败，错误代码：{}'.format(response.status_code)
        error_debug = r'http_refresh_token failed. [{}] :{}'.format(f_url, response.status_code)
        if xlogging.logger_traffic_control.is_logger_print('http_refresh_token__error', token):
            xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)
        else:
            xlogging.raise_system_error_without_logger(error_description, error_debug, response.status_code)

    if xlogging.logger_traffic_control.is_logger_print('http_refresh_token__debug', token):
        _logger.debug('http_refresh_token, input args: {}'.format(token))


def http_report_restore_status(token, progress, finished, host_ident=None):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/tokens/{}/'.format(token))

    json_body = json.dumps({'remainingBytes': progress.remainingBytes, 'totalBytes': progress.totalBytes,
                            'finished': finished, 'successful': True, 'host_ident': host_ident})

    response = requests.put(f_url,
                            headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                            data=json_body,
                            cookies=secure_cookie)

    if http_status.is_success(response.status_code):
        return
    else:
        error_description = r'更新还原进度失败，错误代码：{}'.format(response.status_code)
        error_debug = r'http_report_restore_status failed. [{}] :{}'.format(f_url, response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_update_restore_token(token):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/tokens/{}/'.format(token))
    response = requests.post(f_url, headers={'x-csrftoken': csrf_token}, cookies=secure_cookie)
    if http_status.is_success(response.status_code):
        return 0
    else:
        error_description = r'目标客户端已经重启并成功连接, 但上报给一体机失败, 错误代码：{}'.format(response.status_code)
        error_debug = r'http_update_restore_token failed. [{}] :{}'.format(f_url, response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_start_kvm(pe_ident):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/pe_hosts/sessions/{}/restore/'.format(pe_ident))
    response = requests.put(f_url,
                            headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                            cookies=secure_cookie)
    if http_status.is_success(response.status_code):
        return
    else:
        error_description = r'启动KVM失败，错误代码：{}'.format(response.status_code)
        error_debug = r'http_start_kvm failed. [{}] :{}'.format(f_url, response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_update_traffic_control(token, io_session):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/cdps/{}/tc/?io_session={}'.format(token, io_session))
    response = requests.get(f_url,
                            headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                            cookies=secure_cookie)

    if http_status.is_success(response.status_code):
        pass
    else:
        error_description = r'获取流量限制配置失败，错误代码：{}'.format(response.status_code)
        error_debug = r'http_update_traffic_control failed. [{}] :{}'.format(f_url, response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_fetch_proxy_endpoints():
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/tunnels_manage/')
    response = requests.head(f_url, headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                             cookies=secure_cookie)
    if http_status.is_success(response.status_code):
        pass
    else:
        error_description = r'fetch proxy endpoints failed, code：{}'.format(response.status_code)
        error_debug = r'http_fetch_proxy_endpoints failed. [{}] :{}'.format(f_url, response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_query_last_cdp_detail_by_restore_token(token):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/tokens/{}/detail/'.format(token))
    response = requests.get(f_url, headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                            cookies=secure_cookie)
    if http_status.is_success(response.status_code):
        return response.json()
    else:
        error_description = r'query last cdp detail by restore token failed, code：{}'.format(response.status_code)
        error_debug = r'http_query_last_cdp_detail_by_restore_token failed. [{}]:{}'.format(f_url, response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_query_last_cdp_detail_by_cdp_token(token, host_name, schedule_id):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(
        r'apiv1/tokens/{}/detailByCdp/?host_name={}&schedule_id={}'.format(
            token, host_name, schedule_id))
    response = requests.get(f_url, headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                            cookies=secure_cookie)
    if http_status.is_success(response.status_code):
        rs = response.json()
        return rs.pop('returned'), rs
    else:
        error_description = r'query last cdp detail by cdp token failed, code：{}'.format(response.status_code)
        error_debug = r'http_query_last_cdp_detail_by_cdp_token failed. [{}]:{}'.format(f_url, response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_query_network_transmission_type(user_ident):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/hosts/{}'.format(user_ident))

    r = requests.get(f_url,
                     headers={'content-type': 'application/json; charset=utf-8', 'x-csrftoken': csrf_token},
                     data='',
                     cookies=secure_cookie)
    if http_status.is_success(r.status_code):
        return str(r.json()['network_transmission_type'])
    else:
        error_description = '获取客户端网络传输加密配置失败：{}'.format(r.status_code)
        error_debug = 'http_query_network_transmission_type call web api failed. [{}] :{}'.format(f_url, r.status_code)
        xlogging.raise_system_error(error_description, error_debug, r.status_code, _logger)


def http_report_volume_restore(pe_host, code, msg, debug):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/pe_hosts/sessions/{}/volume_restore/'.format(pe_host))
    response = requests.put(f_url,
                            data=json.dumps({'code': code.value, 'msg': msg,
                                             'debug': debug}),
                            headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                            cookies=secure_cookie)
    if http_status.is_success(response.status_code):
        return True
    else:
        error_description = r'上报卷还原状态失败，错误代码：{}'.format(response.status_code)
        error_debug = r'http_report_volume_restore failed. [{}] :{}'.format(f_url, response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_data_queuing_report(content):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/data_queuing_report/')
    response = requests.post(f_url,
                             data=content,
                             headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                             cookies=secure_cookie)
    if http_status.is_success(response.status_code):
        return 0
    else:
        error_description = r'上报推送快照数据状态失败，错误代码：{}'.format(response.status_code)
        error_debug = r'http_data_queuing_report failed. [{}] :{}'.format(f_url, response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_vmware_agent_report(content):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/vmware_agent_report/')
    response = requests.post(f_url,
                             data=content,
                             headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                             cookies=secure_cookie)
    if http_status.is_success(response.status_code):
        return 0
    else:
        error_description = r'上报关键数据失败，错误代码：{}'.format(response.status_code)
        error_debug = r'http_vmware_agent_report failed. [{}] :{}'.format(f_url, response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_get_hash_file_path_by_restore_token(token):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/token/{}/hashfile'.format(token))
    response = requests.get(f_url, headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                            cookies=secure_cookie)
    if http_status.is_success(response.status_code):
        _logger.info('http_get_hash_file_path_by_restore_token token:{} path:{}'.format(token, response.json()['path']))
        return response.json()['path']
    else:
        error_description = r'获取还原磁盘哈希文件失败，错误代码：{}'.format(response.status_code)
        error_debug = r'http_get_hash_file_path_by_restore_token failed. [{}] :{}'.format(f_url, response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_post_query_json_data(ident, jsonContent):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/hosts/sessions/{}/'.format(ident))
    response = requests.post(f_url, headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                             cookies=secure_cookie, data=jsonContent)
    if http_status.is_success(response.status_code):
        _logger.info('http_post_query_json_data ident:{} jsonContent:{}'.format(ident, jsonContent))
        return response.json()
    else:
        error_description = r'获取主机信息失败，错误代码：{}'.format(response.status_code)
        error_debug = r'http_post_query_json_data failed. [{}] :{}'.format(f_url, response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_report_task_status(task_type, task_uuid, payload):
    secure_cookie, csrf_token, f_url = authCookies.get(r'apiv1/task/progress/')
    data = {'task_type': task_type, 'task_uuid': task_uuid,
            'payload': payload if isinstance(payload, str) else json.dumps(payload)}
    response = requests.post(f_url, headers={'Content-Type': 'application/json', 'x-csrftoken': csrf_token},
                             cookies=secure_cookie, data=json.dumps(data))
    if http_status.is_success(response.status_code):
        return response.json()
    else:
        error_description = r'上传任务状态失败：{}'.format(response.status_code)
        error_debug = r'http_report_task_status failed. [{}] :{}'.format(f_url, response.status_code)
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)


def http_common_post(url, dict_data):
    global _logger
    secure_cookie, csrf_token, f_url = authCookies.get(url)
    response = requests.post(f_url,
                             headers={'Content-Type': 'application/x-www-form-urlencoded', 'x-csrftoken': csrf_token},
                             data=dict_data,
                             cookies=secure_cookie)
    if http_status.is_success(response.status_code):
        return response.json()
    else:
        error_description = r'http_common_host Failed.url={},status_code={}'.format(url, response.status_code)
        error_debug = error_description
        xlogging.raise_system_error(error_description, error_debug, response.status_code, _logger)
