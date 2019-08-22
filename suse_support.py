import os
import xlogging
import subprocess
import platform

_logger = xlogging.getLogger(__name__)

g_suse_id_fmt = "SUSE Linux Enterprise Server"


def log_message(msg):
    str_msg = "[suse_udev] " + msg
    _logger.info(str_msg)


def execute_command(cmd, curr_dir=None):
    log_message('[execute_command] cmd={}'.format(cmd))
    log_message('[execute_command] dir={}'.format(curr_dir))

    std_out = []
    std_err = []
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True, shell=True, cwd=curr_dir,
                         stderr=subprocess.PIPE)
    p.wait()

    for line in p.stdout:
        std_out.append(line.rstrip())

    for line in p.stderr:
        std_err.append(line.rstrip())

    if p.returncode != 0:
        log_message("[execute_command] retcode={} out={} err={}".format(p.returncode, std_out, std_err))

    return p.returncode


def is_net_rule(rule):
    patterns = ["SUBSYSTEM", "==", "net", "ACTION", "add", "address"]
    left = rule

    index = left.find("#")
    if index >= 0:
        return False

    for p in patterns:
        index = left.find(p)
        if index < 0:
            return False
        sub_str = left[index:]
        left = sub_str

    for i in range(5):
        index = left.find(":")
        if index < 0:
            return False
        sub_str = left[index:]
        left = sub_str

    return True


def is_mac_address(mac):
    # print("[is_mac_address] mac=" + mac)
    count = len(mac)
    if count < 17:
        # print("[is_mac_address] invalid count={}".format(count))
        return False

    index = 2
    for i in range(5):
        if mac[index] != ":":
            # print("[is_mac_address] check failed index={}".format(index))
            return False
        index += 3

    return True


def get_mac_from_rule(rule):
    start = 0
    # print("[get_mac_from_rule] rule=" + rule)

    while True:
        # print("[get_mac_from_rule] left=" + left)
        index = rule.find(":", start)
        if index < 0:
            return None
        if index < 2:
            start = index + 1
            continue

        sub_str = rule[index - 2:]
        retval = is_mac_address(sub_str)
        if retval:
            mac = sub_str[:17]
            return mac
        start = index + 1

    return None


def get_suse11_name(rule):
    find_str = rule

    # print("[get_suse11_name] find_str={}".format(find_str))
    index = find_str.find("NAME")
    if index < 0:
        return None

    sub_str = find_str[index + 1:].strip()
    find_str = sub_str
    # print("[get_suse11_name] find_str={}".format(find_str))

    index = find_str.find("=")
    if index < 0:
        return None

    sub_str = find_str[index + 1:].strip()
    find_str = sub_str
    # print("[get_suse11_name] find_str={}".format(find_str))

    index = find_str.find("\"")
    if index < 0:
        return None

    name_str = find_str[index + 1:].strip()
    # print("[get_suse11_name] name_str={}".format(name_str))

    index = name_str.find("\"")
    if index < 0:
        return None
    name = name_str[0:index]

    # print("[get_suse11_name] name={}".format(name))
    return name


def get_suse10_name(rule):
    index = rule.find("/lib/udev/rename_netiface")
    if index < 0:
        return None

    sub_str = rule[index:].replace("\"", "").replace("\'", "")
    items = sub_str.split()
    if len(items) != 3:
        return None

    return items[2]


def define_new_rule(rule, name, mac, version):
    org_mac = get_mac_from_rule(rule)
    if not org_mac:
        return None

    tmp_rule = rule.replace(org_mac, mac)

    if version == "10":
        org_name = get_suse10_name(tmp_rule)
    elif version == "11":
        org_name = get_suse11_name(tmp_rule)
    else:
        org_name = None

    if not org_name:
        return None

    new_rule = tmp_rule.replace(org_name, name)

    return new_rule


def get_suse_issue(root_path):
    issue = os.path.join(root_path, "etc", "issue")
    if not os.path.exists(issue):
        log_message("[get_suse_issue] not exist = {}".format(issue))
        return None

    with open(issue) as file:
        for line in file:
            fmt = line.strip()
            index = fmt.find(g_suse_id_fmt)
            if index >= 0:
                return fmt

    return None


def get_suse_version(root_path):
    if root_path == '/':
        issue = get_suse_version_new()
        log_message("[get_suse_version] issue = {}".format(issue))
        return issue
    else:
        issue = get_suse_issue(root_path)
    log_message("[get_suse_version] issue = {}".format(issue))
    if not issue:
        return None

    index = issue.find(g_suse_id_fmt)
    if index < 0:
        return None

    count = len(g_suse_id_fmt)
    items = issue[index + count:].split()

    if len(items) < 1:
        return None
    version = items[0]
    return version


def get_suse_version_new():
    try:
        info = platform.linux_distribution()
        version = info[1].strip()[:2]
    except Exception as e:
        log_message("[get_suse_version_new] exception={}".format(e))
        return None
    log_message("[get_suse_version_new] version={}".format(version))
    return version


def format_mac(mac_in):
    mac = mac_in.replace(' ', '').replace('-', '').replace(':', '').lower()

    if len(mac) != 12:
        return None

    mac_new = ''
    for index, value in enumerate(mac, 1):
        if index % 2 == 0:
            mac_new += '{}:'.format(value)
        else:
            mac_new += value
    return mac_new.rstrip(':')


def get_config_info(config, index):
    name = config.get("name")
    mac = config.get("mac")
    if not mac:
        return None, None

    if not name:
        new_name = "eth{}".format(index)
    else:
        new_name = name

    new_mac = format_mac(mac)
    if not new_mac:
        return None, None

    return new_mac, new_name


def modify_rule_config(path, version, configs):
    log_message("[modify_rule_config] path={}".format(path))
    log_message("[modify_rule_config] version={}".format(version))

    if len(configs) <= 0:
        log_message("[modify_rule_config] no configs")
        return False

    data = list()
    rule_fmt = None
    with open(path) as file:
        for rule in file:
            retval = is_net_rule(rule)
            if not retval:
                data.append(rule)
                continue
            log_message("[modify_rule_config] rule={}".format(rule))
            rule_fmt = rule
            content = "#" + rule

            data.append(content)

    if not rule_fmt:
        log_message("[modify_rule_config] not find rule")
        return False

    log_message("[modify_rule_config] rule_fmt={}".format(rule_fmt))

    index = 0
    for cfg in configs:
        new_mac, new_name = get_config_info(cfg, index)
        if not new_mac:
            log_message("[modify_rule_config] get_config_info failed, cfg={}".format(cfg))
            continue

        new_rule = define_new_rule(rule_fmt, new_name, new_mac, version)
        if not new_rule:
            log_message("[modify_rule_config] get new failed, name={}, mac={}".format(new_name, new_mac))
            continue

        log_message("[modify_rule_config] new_rule={}".format(new_rule))
        data.append(new_rule)

    # log_message("[modify_rule_config] data={}".format(data))
    with open(path, "wt") as new_file:
        for line in data:
            new_file.write(line)

    return True


def get_version_and_cfgfile(root_path):
    version = get_suse_version(root_path)
    if not version:
        log_message("[get_version_and_cfgfile] can not get version")
        return None, None

    log_message("[get_version_and_cfgfile] version={}".format(version))

    if version == "10":
        name = "30-net_persistent_names.rules"
    elif version == "11":
        name = "70-persistent-net.rules"
    else:
        log_message("[get_version_and_cfgfile] invalid version")
        return None, None

    cfgpath = os.path.join(root_path, "etc", "udev", "rules.d", name)
    if not os.path.exists(cfgpath):
        log_message("[get_version_and_cfgfile] not exist file={}".format(cfgpath))
        return None, None

    return version, cfgpath


def modify_suse_udev_rules(root_path, ip_configs):
    try:

        log_message("[modify_suse_udev_rules] ip_configs={}".format(ip_configs))

        version, cfgpath = get_version_and_cfgfile(root_path)
        if (not version) or (not cfgpath):
            log_message("[modify_suse_udev_rules] get_version_and_cfgfile failed")
            return

        retval = modify_rule_config(cfgpath, version, ip_configs)
        log_message("[modify_suse_udev_rules] modify rule={}".format(retval))

    except Exception as e:
        log_message("[modify_suse_udev_rules] Exception={}".format(e))

    return


def is_rule_mac_match(rule, ipconfigs):
    mac = get_mac_from_rule(rule)
    if not mac:
        return None, None

    index = 0
    for cfg in ipconfigs:
        cfg_mac, cfg_name = get_config_info(cfg, index)
        if not cfg_mac:
            index += 1
            log_message("[is_rule_mac_match] get_config_info failed, cfg={}".format(cfg))
            continue

        if mac.lower() == cfg_mac.lower():
            return mac.lower(), index
        index += 1

    return None, None


def remove_from_list(content, item):
    index = content.index(item)
    if index < 0:
        log_message("[remove_from_list] not find {}".format(item))
        return False

    line = content[index]
    new_line = "# " + line
    content[index] = new_line

    log_message("[remove_from_list] remove item = {}".format(item))

    return True


def del_rule_from_content(content, hitrule, ipconfigs):
    log_message("[del_rule_from_content] hitrule={}".format(hitrule))

    count = len(hitrule)
    if count <= 1:
        return False

    index = 0
    remove = False

    while index < count:
        item = hitrule[index]
        rule = item["rule"]
        cfgidx = item["index"]

        mac, name = get_config_info(ipconfigs[cfgidx], cfgidx)
        findidx = rule.find(name)
        if findidx >= 0:
            log_message("[del_rule_from_content] use rule = {}".format(rule))
            index += 1
            continue

        retval = remove_from_list(content, rule)
        if retval:
            remove = True
        index += 1

    return remove


def del_rule_from_config(cfgfile, ipconfigs):
    hit_rules = dict()
    content = list()
    with open(cfgfile) as file:
        for org_line in file:
            line = org_line
            content.append(org_line)
            index = org_line.find("#")
            if index >= 0:
                continue

            mac, cfgidx = is_rule_mac_match(line, ipconfigs)
            if not mac:
                continue

            item = dict()
            item["index"] = cfgidx
            item["rule"] = org_line

            getrules = hit_rules.get(mac)
            if getrules:
                getrules.append(item)
            else:
                getrules = list()
                getrules.append(item)

            hit_rules[mac] = getrules

    log_message("[del_rule_from_config] content={}".format(content))
    log_message("[del_rule_from_config] hit_rules={}".format(hit_rules))

    remove = False
    for item in hit_rules:
        retval = del_rule_from_content(content, hit_rules[item], ipconfigs)
        if retval:
            remove = True

    if not remove:
        log_message("[del_rule_from_config] no change")
        return False

    log_message("[del_rule_from_config] content={}".format(content))

    with open(cfgfile, "wt") as new_file:
        for line in content:
            new_file.write(line)

    return True


def del_redundant_udev_rule(root_path, ip_configs):
    try:
        log_message("[del_redundant_udev_rule] ip_configs={}".format(ip_configs))

        version, cfgpath = get_version_and_cfgfile(root_path)
        if (not version) or (not cfgpath):
            log_message("[del_redundant_udev_rule] get_version_and_cfgfile failed")
            return

        retval = del_rule_from_config(cfgpath, ip_configs)
        log_message("[del_redundant_udev_rule] delete rule={}".format(retval))

    except Exception as e:
        log_message("[del_redundant_udev_rule] Exception={}".format(e))

    return


if __name__ == '__main__':
    xconfigs = [{"name": None, "mac": "00505695e7d1"}, {"name": "xxxx", "mac": "0050569563d4"}]
    # root = "D:\\Users\\Fang\\Desktop\\debug\\20180316\\suse11"
    # del_redundant_udev_rule(root, xconfigs)

    root = "D:\\Users\\Fang\\Desktop\\debug\\20180316\\suse10"
    del_redundant_udev_rule(root, xconfigs)
