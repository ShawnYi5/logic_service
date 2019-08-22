import requests
import xlogging
import http_status

_logger = xlogging.getLogger(__name__)

__all__ = [r'init', 'get', 'refresh']

_url = None
_username = None
_password = None
_cookies = None


def init(url, username, password):
    global _url, _username, _password, _logger
    _url = url
    _username = username
    _password = password
    _logger.info(r'web url : {}'.format(_url))


# 确保cookie 是可用状态
def get(url):
    global _cookies
    if _cookies is None:
        refresh()
    for cookie in _cookies:
        if cookie.is_expired():  # 以时间戳的方式，检测cookie的有效期
            _logger.info('finding cookie out of time, start reacquiring it.')
            refresh()
            break
    return _cookies, _cookies['csrftoken'], _url + url


def refresh(self_call=False):
    global _cookies, _username, _password, _csrftoken, _logger
    _logger.info(r'refresh cookies ...')
    url_login = _url + r'api-auth/login/'
    web_login_get = requests.get(url_login)
    if web_login_get.status_code == http_status.HTTP_200_OK:
        csrftoken = web_login_get.cookies['csrftoken']
        login_data = {'username': _username, 'password': _password, 'csrfmiddlewaretoken': csrftoken}
        login_cookies = dict(csrftoken=web_login_get.cookies['csrftoken'])
        web_login_post = requests.post(url_login, allow_redirects=False, data=login_data, cookies=login_cookies)
        if web_login_post.status_code == http_status.HTTP_302_FOUND:
            _cookies = web_login_post.cookies
            _logger.info('refresh cookies ok')
        elif web_login_post.status_code == http_status.HTTP_200_OK and not self_call:
            _logger.error('refresh cookies failed. super user Not exist!')
            refresh(True)
        else:
            xlogging.raise_system_error('无法通过Web组件验证', 'refresh cookies post failed', web_login_post.status_code,
                                        _logger)
    else:
        xlogging.raise_system_error('无法连接到Web组件', 'refresh cookies get failed', web_login_get.status_code, _logger)
