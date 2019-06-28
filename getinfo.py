#!/usr/bin/env python
# -*- coding: utf8 -*-
#
# from lib.utils.config import ConfigFileParser
# from lib.core.data import  logger

import os
import json
import socket
import platform
import psutil
import ctypes
import re
import requests
requests.packages.urllib3.disable_warnings()

info_dict = {}
ip = socket.gethostbyname(socket.getfqdn(socket.gethostname()))
sysstr = platform.system()

if sysstr == 'Windows':
    import wmi
    import winreg

    c = wmi.WMI()


def get_bios_info():
    bios_dict = {}
    bios_dict['OBJ_IP'] = ip
    bios_dict['BIOS_INFO'] = []
    if sysstr == "Windows":
        bios = c.Win32_BIOS()[0]
        for key in bios.properties:
            info_dict = {}
            info_dict['BIOS_ATTRIBUTE_NAME'] = key
            value = 'bios.%s' % key
            info_dict['BIOS_ATTRIBUTE_VAULE'] = eval(value)
            bios_dict['BIOS_INFO'].append(info_dict)
    elif sysstr == 'Linux':
        with os.popen('dmidecode -t 0') as output:
            flag = 0
            character = []
            # info_dict = {}
            bios_info = output.read().strip().split('BIOS Information')[1].strip()
            for line in bios_info.splitlines():
                info_dict = {}
                data = line.strip().split(':')
                if data[0] == 'Characteristics':
                    flag = 1
                    continue
                elif len(data) == 2:
                    info_dict['BIOS_ATTRIBUTE_NAME'] = data[0]
                    info_dict['BIOS_ATTRIBUTE_VAULE'] = data[1]
                    bios_dict['BIOS_INFO'].append(info_dict)
                    info_dict = {}
                elif line.strip().find(':') < 0 and flag == 1:
                    character.append(line.strip())
                    continue
            info_dict['BIOS_ATTRIBUTE_NAME'] = 'Characteristics'
            info_dict['BIOS_ATTRIBUTE_VAULE'] = character
            bios_dict['BIOS_INFO'].append(info_dict)
    # print(json.dumps(bios_dict, indent=4))
    return bios_dict

def get_cpu_info():
    hardware = {}
    if sysstr == 'Windows':
        for cpu in c.Win32_Processor():
            hardware['HARDWARE_NAME'] = 'CPU'
            # hardware['HARDWARE_NAME'] = cpu.Name
            hardware['HARDWARE_DESC'] = cpu.Caption
            hardware['HARDWARE_UUID'] = cpu.ProcessorId #不是唯一的
            hardware['HARDWARE_TYPE"'] = cpu.ProcessorType
            hardware['HARDWARE_POSITION'] = ''
            hardware['HARDWARE_VENDOR'] = cpu.Name.split(' ')[0]
            hardware['HARDWARE_STATUS'] = cpu.Status
        return hardware
    else:
        cpu_list = []
        i = 0
        with os.popen('dmidecode -t 4') as output:
            info = output.read().strip().split('Processor Information')
            for cpu in info:
            #     info[0]无用信息
                hardware = {}
                if i > 0:
                    for line in cpu.strip().splitlines():
                        line = line.strip()
                        data = line.split(':')
                        if data[0].strip() == 'Socket Designation':
                            hardware['HARDWARE_NAME'] = data[1].strip()
                        elif data[0].strip() == 'Manufacturer':
                            hardware['HARDWARE_VENDOR'] = data[1].strip()
                        elif data[0].strip() == 'Version': #把型号放在了描述里
                            hardware['HARDWARE_DESC'] = data[1].strip()
                        elif data[0].strip() == 'ID':
                            hardware['HARDWARE_UUID'] = data[1].strip()
                        elif data[0].strip() == 'Type':
                            hardware['HARDWARE_TYPE'] = data[1].strip()
                        elif data[0].strip() == '':
                            hardware['HARDWARE_POSITION'] = ''
                        elif data[0].strip() == 'Status':
                            hardware['HARDWARE_STATUS'] = data[1].strip()
                    cpu_list.append(hardware)
                i += 1
        return cpu_list


def get_mem_info():
    pass

def get_cdrom_info():
    # cat /proc/sys/dev/cdrom/info
    pass

def get_usb_info():
    usb_dict = []
    # usb hub
    with os.popen('lsusb -v') as output:
        usb = output.read().strip().split('\n\n')
        for data in usb:
            usb = {}
            for line in data.splitlines():
                info = line.strip().split(':')

                if len(info) == 3 and info[0].startswith('Bus'):
                    usb['HARDWARE_NAME'] = info[2].strip()
                    usb['HARDWARE_POSITION'] = info[0].strip()
                    usb['HARDWARE_TYPE'] = 'USB Hub'
                elif len(info) == 2 and info[0].strip() == 'Device Status':
                    usb['HARDWARE_STATUS'] = info[1].strip()
                elif info[0].startswith('iSerial'):
                    index = len('iSerial')
                    usb['HARDWARE_UUID'] = info[0][index:].strip()
                    i = 0
                    for num in info:
                        if i > 0:
                            usb['HARDWARE_UUID'] = usb['HARDWARE_UUID'] + ':' + num.strip()
                        i += 1
                elif info[0].startswith('idVendor'):
                    index = len('idVendor')
                    usb['HARDWARE_VENDOR'] = info[0][index:].strip()
                elif info[0].startswith('Device Status'):
                    usb['HARDWARE_STATUS'] = info[1].strip()
                elif info[0].startswith('bcdUSB'):
                    index = len('bcdUSB')
                    usb['HARDWARE_DESC'] = 'USB' + info[0][index:].strip()
                # elif info[0].startswith('idProduct'):
                #     index = len('idProduct')
                #     usb['HARDWARE_TYPE'] = info[0][index:].strip()
            usb_dict.append(usb)

    with os.popen('lspci -vvv') as output:
        data = output.read().strip().split('\n\n')
        for each in data:
            # usb controller
            if each.find('USB controller') > 0:
                usb = {}
                for line in each.splitlines():
                    line = line.split(':')
                    if line[1].find('USB controller') > 0:
                        vendor,name = line[2].strip().split(' ', 1)
                        usb['HARDWARE_NAME'] = name.strip()
                        usb['HARDWARE_POSITION'] = ''
                        usb['HARDWARE_TYPE'] = 'USB Controller'
                        usb['HARDWARE_UUID'] = ''
                        usb['HARDWARE_VENDOR'] = vendor
                    elif line[0].strip() == 'Status':
                        usb['HARDWARE_STATUS'] = line[1].strip()
                    elif line[0].strip() == 'Kernel driver in use':
                        usb['HARDWARE_DESC'] = line[0].strip() + ':' +line[1]
                usb_dict.append(usb)
            elif each.find('Ethernet controller'):
                pass

    # print(json.dumps(usb_dict,indent=4))
    return usb_dict

def get_mainboard_info():
    info = {}
    with os.popen('dmidecode -t 2') as output:
        for line in output.readlines():
            data = line.strip().split(':')
            if len(data) > 1:
                if data[0].strip() == 'Product Name':
                    info['HARDWARE_NAME'] = data[1].strip()
                elif data[0].strip() == 'Serial Number':
                    info['HARDWARE_UUID'] = data[1].strip()
                elif data[0].strip() == 'Type':
                    info['HARDWARE_TYPE'] = data[1].strip()
                elif data[0].strip() == 'Location In Chassis':
                    info['HARDWARE_POSITION'] = data[1].strip()
                elif data[0].strip() == 'Manufacturer':
                    info['HARDWARE_VENDOR'] = data[1].strip()
                else:
                    info['HARDWARE_STATUS'] = ''
            else:
                # index = len(data[0].strip()) - len('Information') - 1
                # info['HARDWARE_DESC'] = data[0][:index].strip()
                info['HARDWARE_DESC'] = 'Base Board'
        # print(json.dumps(info, indent=4))
    return info


def get_other_info():
    info = []
    i = 0
    # 显卡信息
    with os.popen('dmidecode -t 10') as output:
        tmp = output.read().split('On Board')
        for each in tmp:
            other_dict = {}
            if i > 0:
                for line in each.splitlines():
                    data = line.strip().split(':')
                    pos = data[0].strip().find('Information')
                    if pos > 0:
                        other_dict['HARDWARE_NAME'] = data[0][:pos-1].strip()
                    elif data[0].strip() == 'Description':
                        other_dict['HARDWARE_DESC'] = data[1].strip()
                    elif data[0].strip() == 'Type':
                        other_dict['HARDWARE_TYPE'] = data[1].strip()
                    elif data[0].strip() == 'Status':
                        other_dict['HARDWARE_STATUS'] = data[1].strip()
                    else:
                        other_dict['HARDWARE_UUID'] = ''
                        other_dict['HARDWARE_POSITION'] = ''
                        other_dict['HARDWARE_VENDOR'] = ''
                info.append(other_dict)
            i += 1
        # scsi
        with os.popen('cat /proc/scsi/scsi') as output:
            tmp = output.read().split('Host')
            for scsi in tmp:
                other_dict = {}
                for line in scsi.splitlines():
                    line = re.sub(r'\s+', ' ', line.strip())
                    line = re.sub(r':\s+', ':', line)
                    print(line)
                    if line.startswith('Attached'):
                        continue
                    if line.startswith('Vendor'):
                        data = line.split(' ', 1)
                        print(data)
                        other_dict['HARDWARE_VENDOR'] = data[0].split(':')[1].strip()
                        other_dict['HARDWARE_DESC'] = data[1].split('Rev')[0].split(':')[1].strip()
                        other_dict['HARDWARE_POSITION'] = ''
                        other_dict['HARDWARE_STATUS'] = ''
                    else:
                        data = line.strip().split(' ')
                        print(data)
                        key, value = data[0].split(':')
                        if key == '':
                            other_dict['HARDWARE_NAME'] = value
                            other_dict['HARDWARE_UUID'] = data[2].split(':')[1].strip()
                        elif key == 'Type':
                            other_dict['HARDWARE_TYPE'] = value
                info.append(other_dict)

            print(json.dumps(info, indent=4))
        return info


def get_hardware_info():
    hardware_dict = {}
    hardware_dict['OBJ_IP'] = ip
    hardware_dict['HARDWARS'] = []
    cpu = get_cpu_info()
    if type(cpu) == list:
        for info in cpu:
            hardware_dict['HARDWARS'].append(info)
    else:
        hardware_dict['HARDWARS'].append(cpu)
    cdrom = get_cdrom_info()
    usb = get_usb_info()
    for info in usb:
        hardware_dict['HARDWARS'].append(info)

    mainboard = get_mainboard_info()
    hardware_dict['HARDWARS'].append(mainboard)

    other = get_other_info()
    for info in other:
        hardware_dict['HARDWARS'].append(info)
    return hardware_dict


def get_os_info():
    os_dict = {}
    res = platform.uname()
    os_dict['OS_NAME'] = res[0]
    os_dict['OBJ_IP'] = ip
    os_dict['OS_VERSION'] = res[3]

    os_dict['OS_IDENTIFICATION'] = ''
    os_dict['CPU_INFO'] = platform.processor()
    mem = '%.1f' % (psutil.virtual_memory().total / (1024*1024*1024))
    os_dict['MEMORY_INFO'] = str(mem) + 'G'  #物理内存
    partition = psutil.disk_partitions()
    total = 0
    for disk in partition:
        print('%s %s' % (disk.mountpoint, psutil.disk_usage(disk.mountpoint)))
        total += psutil.disk_usage(disk.mountpoint).total
    total = '%.1f' % (total /1024/1024/1024)
    os_dict['DISK_INFO'] = str(total) + 'G' # 磁盘分区信息
    os_dict['COMPUTER_NAME'] = res[1]
    if sysstr == 'Linux':
        # Subprocess
        output = os.popen('groups')
        os_dict['WORK_GROUP'] = output.read().strip()
        with os.popen('lsb_release -a') as output:
            for line in output.readlines():
                data = line.strip().split(':')
                if data[0].strip() == 'Distributor ID':
                    os_dict['OS_IDENTIFICATION'] = data[1].strip()
                elif data[0].strip() == 'Description':
                    os_dict['OS_DESC'] = data[1].strip()
                else:
                    continue

    else:
        group = c.Win32_GroupInDomain()
        print(group)
        # print(c.Win32_GroupUser)
        # print(group)
    # print(json.dumps(os_dict, indent=4))
    return os_dict


def get_software_info_linux():
    i = 0
    software_dict = {}
    software_dict['OBJ_IP'] = ip
    software_dict['SOFTS'] = []

    with os.popen('rpm -qai') as output:
        info = output.read().strip().split('Name        :')
        for j in info:
            if i > 0:
                software = {}

                data = j.strip().split('Description :')
                software['SOFTWARE_DESC'] = data[1].strip()
                for line in data[0].splitlines():
                    data1 = line.strip().split(':')
                    if len(data1) == 1:
                        software['SOFTWARE_NAME'] = data1[0].strip()
                    elif data1[0].strip() == 'Vendor':
                        software['SOFTWARE_VENDOR'] = data1[1].strip()
                    elif data1[0].strip() == 'Version':
                        software['SOFTWARE_VERSION'] = data1[1].strip()
                    elif data1[0].strip() == 'Signature':
                        software['IDENTIFY_NUMBER'] = data1[1].strip()
                    elif data1[0].strip() == 'Install Date':
                        time = re.sub(r'\D', '-', data1[1].strip().split(' ')[0])
                        software['INSTALL_DATE'] = time
                    elif data1[0].strip() == '':
                        software['INSTALL_POSITION'] = ''
                software_dict['SOFTS'].append(software)
            i += 1
        print(len(software_dict['SOFTS']))
        # print(json.dumps(software_dict,indent=4))
        return software_dict


def get_software_info_windows():

    sub_key = [r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
               r'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall']

    # 32位程序列表对应注册表键值  HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall
    # 64位程序列表对应注册表键值  HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\
    # keyPath = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"

    software_name = []
    for i in sub_key:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, i, 0, winreg.KEY_ALL_ACCESS)
        listKeys = winreg.QueryInfoKey(key)
        print(listKeys)
        for j in range(0, listKeys[0] - 1):
            key_name_list = winreg.EnumKey(key, j)
            each_key_path = i + '\\' + key_name_list
            try:
                each_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, each_key_path, 0, winreg.KEY_READ)
                # DisplayName, REG_SZ = winreg.QueryValueEx(each_key, "DisplayName")
                path, REG_SZ = winreg.QueryValueEx(each_key, "DisplayName")
                print(path)
                DisplayName = DisplayName.encode('utf-8')
                software_name.append(DisplayName)
                # fInfo = CommMethod.getFileInfo(fpath)
                # list.append(fInfo)
            except:
                pass
    #去重排序
    software_name = list(set(software_name))
    software_name = sorted(software_name)
    print(software_name)


if __name__ == '__main__':
    # get_bios_info()
    get_hardware_info()
    # get_software_info_linux()
    # get_cpu_info()
    # get_mem_info()
    # get_os_info()
    # 上传os信息
    # url = ConfigFileParser().OsUrl()
    os_url = 'https://10.77.0.190/secops/servlet/OSScript'
    bios_url = 'https://10.77.0.190/secops/servlet/BiosScript'
    sft_url = 'https://10.77.0.190/secops/servlet/SoftwareScript'
    hd_url = 'https://10.77.0.190/secops/servlet/HardwareScript'
    patch_url = 'https://10.77.0.190/secops/servlet/PatchUpload'
    url = sft_url
    # data = json.dumps(get_software_info_linux())
    # try:
    #     response = requests.post(url, data.encode('utf-8'), verify=False)
    #     print(response.status_code)
    #     if response.status_code == 200:
    #         print('200',response.text)
    #         # logger.info(response.text)
    #         # return True
    #     else:
    #         print(response.text)
    #
    #         # logger.error(response.text)
    #     print(response.text)
    #         # return False
    # except Exception as e:
    #     pass
    #     # logger.error(e)
    #     # return False
