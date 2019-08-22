# coding:utf-8
import datetime
import functools
import inspect
import logging
import logging.config
import os
import threading
import sys

import Ice

import loadIce

__all__ = [r'raise_system_error', r'getLogger']

config_path = os.path.join(loadIce.current_dir, 'logging.config')
logging.config.fileConfig(config_path)

import Utils


def _get_front_back_function_info():
    class_name = ''

    frame = inspect.currentframe().f_back.f_back  # 需要回溯两层
    arg_values = inspect.getargvalues(frame)
    args, _, _, value_dict = arg_values
    # we check the first parameter for the frame function is
    # named 'self'
    if len(args) and args[0] == 'self':
        # in that case, 'self' will be referenced in value_dict
        instance = value_dict.get('self', None)
        if instance:
            class_name = getattr(instance, '__class__', None).__name__
            class_name += '.'

    module_name = inspect.getmodule(frame).__name__

    return class_name + frame.f_code.co_name, frame.f_lineno, module_name, arg_values


def raise_system_error_without_logger(description, debug, code):
    se = Utils.SystemError()
    se.description = description
    se.debug = debug
    se.rawCode = code
    raise se


def _print_dict_exclude_many_binary(info, obj):
    if obj:
        for k, v in obj.items():
            if isinstance(v, (bytearray, bytes)):
                info += r'"{}":{}。。。 '.format(k, v[:32])
            else:
                info += r'"{}":{} '.format(k, v)
    else:
        info += r'None '
    return info


def raise_system_error(description, debug, code, logger=None, print_args=True, function_name=None, file_line=None):
    """
    :param description: 一系列的描述信息，给使用者看
    :param debug: 上下文
    :param code: 错误码
    :param logger:
    :param print_args:
    :param function_name:
    :param file_line:
    :return:
    """
    function_info = None
    if (function_name is None) or (file_line is None) or print_args or (logger is None):
        function_info = _get_front_back_function_info()
        if function_name is None:
            function_name = function_info[0]
        if file_line is None:
            file_line = function_info[1]
        if logger is None:
            logger = logging.getLogger(function_info[2])

    err_log = r'{function_name}({file_line}):{msg} debug:{debug}' \
        .format(function_name=function_name, file_line=file_line, msg=description, debug=debug)

    if sys.exc_info()[0]:  # 如果当前线程不存在异常，使用 logger.error(xxx, exc_info=True) 会抛异常
        exc_info = True
    else:
        exc_info = False

    if print_args:
        args_info = r' args:args={} varargs={} keywords='.format(function_info[3].args, function_info[3].varargs)
        args_info = _print_dict_exclude_many_binary(args_info, function_info[3].keywords)
        args_info += 'locals='
        args_info = _print_dict_exclude_many_binary(args_info, function_info[3].locals)
        logger.error(err_log + args_info, exc_info=exc_info)
    else:
        logger.error(err_log, exc_info=exc_info)

    se = Utils.SystemError()
    se.description = description
    se.debug = debug
    se.rawCode = code
    raise se


def getLogger(name):
    return logging.getLogger(name)


def _get_front_back_instance():
    frame = inspect.currentframe().f_back.f_back  # 需要回溯两层
    _, _, _, value_dict = inspect.getargvalues(frame)
    return value_dict.get('self')  # 不做容错，调用者保证


def LockDecorator(locker):
    def _real_decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kv):
            with locker:
                return fn(*args, **kv)

        return wrapper

    return _real_decorator


# 为类方法添加装饰器的基类
class DecorateClass(object):
    def decorate(self):
        for name, fn in self.iter():
            if callable(fn):
                self.operate(name, fn)


# 自动为公共方法加入异常
class ExceptionHandlerDecorator(DecorateClass):
    # obj：对象实例，建议直接使用需要添加装饰器的对象的self
    # logger：日志对象，建议使用logging.getLogger(__name__)，当不传入时，将通过方法自动获取
    def __init__(self, obj=None, logger=None):
        self.obj = _get_front_back_instance() if obj is None else obj
        self.logger = logger

    def iter(self):
        return [(name, getattr(self.obj, name)) for name in dir(self.obj) if not name.startswith('_')]

    def getLogger(self, module_name):
        if self.logger is not None:
            return self.logger
        else:
            return logging.getLogger(module_name)

    def operate(self, name, fn):
        @functools.wraps(fn)
        def handler(*args, **kv):
            try:
                return fn(*args, **kv)
            except Utils.SystemError:
                raise
            except Exception as e:
                error_string = r'{fn_name} Exception:{e}'.format(fn_name=fn.__qualname__, e=e)
                self.getLogger(fn.__module__).error(error_string, exc_info=True)
                se = Utils.SystemError()
                se.description = '内部异常，代码12321'
                se.debug = error_string
                se.rawCode = 12321
                raise se

        setattr(self.obj, name, handler)


# 自动为公共方法加入异常
class IceExceptionToSystemErrorDecorator(DecorateClass):
    # obj：对象实例，建议直接使用需要添加装饰器的对象的self
    # logger：日志对象，建议使用logging.getLogger(__name__)，当不传入时，将通过方法自动获取
    def __init__(self, msg_map, obj=None, logger=None):
        self.obj = _get_front_back_instance() if obj is None else obj
        self.logger = logger
        self.msg_map = msg_map

    def iter(self):
        return [(name, getattr(self.obj, name)) for name in dir(self.obj) if name in self.msg_map]

    def getLogger(self, module_name):
        if self.logger is not None:
            return self.logger
        else:
            return logging.getLogger(module_name)

    def operate(self, name, fn):
        @functools.wraps(fn)
        def handler(*args, **kv):
            try:
                return fn(*args, **kv)
            except Utils.SystemError:
                raise
            except Ice.Exception as ie:
                error_string = r'{fn_name} Ice.Exception:{e}'.format(fn_name=fn.__qualname__, e=ie)
                self.getLogger(fn.__module__).error(error_string, exc_info=True)
                se = Utils.SystemError()
                se.description = self.msg_map.get(fn.__name__, '内部异常，模块间通信失败')
                se.debug = error_string
                se.rawCode = 12421
                raise se

        setattr(self.obj, name, handler)


# 自动为“类的公共方法”加上跟踪装饰器
# remark：公共方法”是指不是由“_”打头的类方法
class TraceDecorator(DecorateClass):
    # ignore 忽略列表，可忽略额外的方法
    # obj：对象实例，建议直接使用需要添加装饰器的对象的self，当在__init__中被调用时可不传入，内部将通过调用栈自动获取
    def __init__(self, ignore=None, obj=None, logger=None):
        self.ignore = list() if ignore is None else ignore
        self.obj = _get_front_back_instance() if obj is None else obj
        self.index = 0
        self.logger = logger

    def iter(self):
        return [(name, getattr(self.obj, name)) for name in dir(self.obj) if
                ((not name.startswith('_')) and (name not in self.ignore) and (not name.startswith('ice_')))]

    def operate(self, name, fn):
        @functools.wraps(fn)
        def trace(*args, **kv):
            logger = self.logger if self.logger else logging.getLogger(fn.__module__)
            index = self.index  # 仅仅用于打印调试无需同步
            self.index += 1

            args_exclude_bytearray = tuple(x for x in args if
                                           not isinstance(x, (bytearray, bytes)) and x is not Ice.Unset)

            kv_exclude_bytearray = {
                key: value for key, value in kv.items() if
                not isinstance(value, (bytearray, bytes)) and value is not Ice.Unset
            }

            logger.debug(
                r'{index}:{fn_name} input args:{args} kv:{kv}'.format(
                    index=index, fn_name=fn.__qualname__, args=args_exclude_bytearray, kv=kv_exclude_bytearray))

            returned = fn(*args, **kv)

            logger.debug(
                r'{index}:{fn_name} return:{returned}'.format(index=index, fn_name=fn.__qualname__, returned=returned))

            return returned

        setattr(self.obj, name, trace)


# 当方法内发生异常时，返回 value
def convert_exception_to_value(value):
    def _real_decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kv):
            try:
                return fn(*args, **kv)
            except Utils.SystemError as se:
                logging.getLogger(fn.__module__).warning(
                    r'{fn_name} raise SystemError need convert to {value} :{msg} debug:{debug}'.format(
                        fn_name=fn.__qualname__, msg=se.description, debug=se.debug, value=value))
                return value
            except Exception as e:
                logging.getLogger(fn.__module__).error(
                    r'{fn_name} raise Exception need convert to {value} :{e}'.format(
                        fn_name=fn.__qualname__, e=e, value=value), exc_info=True)
                return value

        return wrapper

    return _real_decorator


logger_traffic_control_locker = threading.Lock()
logger_traffic_control_content = dict()


class logger_traffic_control(object):
    @staticmethod
    @LockDecorator(logger_traffic_control_locker)
    def is_logger_print(slot, content, seconds=300):
        now = datetime.datetime.now()
        entry = logger_traffic_control_content.get(slot, None)
        if entry is None:
            logger_traffic_control_content[slot] = {content: now}
            result = True
        else:
            last_time = entry.get(content, None)
            if last_time is None:
                entry[content] = now
                result = True
            else:
                if (now - last_time).total_seconds() > seconds:
                    entry[content] = now
                    result = True
                else:
                    result = False

        logger_traffic_control._clean_expires(now)

        return result

    @staticmethod
    def _clean_expires(now, seconds=300):
        for _, entry in logger_traffic_control_content.items():
            content_expires = list()
            for content, last_time in entry.items():
                if abs((now - last_time).total_seconds()) > seconds:
                    content_expires.append(content)
            for c in content_expires:
                del entry[c]


# 当发生Ice通信异常时，抛出指定内容的异常
def convert_ice_exception_to_clw_exception(description, debug=None, code=1):
    def _real_decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kv):
            try:
                return fn(*args, **kv)
            except Utils.SystemError:
                raise
            except Ice.Exception as ie:
                __logger = logging.getLogger(fn.__module__)
                _debug = 'convert_ice_exception_to_clw_exception {} ice failed : {}'.format(
                    debug if debug else fn.__qualname__, ie)
                raise_system_error(description, _debug, code, __logger)
            except Exception:
                raise

        return wrapper

    return _real_decorator


class DataHolder(object):
    def __init__(self, value=None):
        self.value = value

    def set(self, value):
        self.value = value
        return value

    def get(self):
        return self.value
