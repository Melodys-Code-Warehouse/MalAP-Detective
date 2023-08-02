import requests
import json
import urllib.request
# hex_str = '7777772E6769746875622E636F6D0A00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
# domain_parts = []
# label = ''
# for i in range(0, len(hex_str), 2):
#     if hex_str[i:i+2] == '00':
#         if label:
#             domain_parts.append(label)
#             label = ''
#     else:
#         label += chr(int(hex_str[i:i+2], 16))
# domain = '.'.join(domain_parts).rstrip('\n')
# print(domain)
# print(len(domain))
# print(type(domain))
# print(type(hex_str))
# url = "https://cloudflare-dns.com/dns-query"
# params = {"name": 'github.com', "type": "A"}
# headers = {"accept": "application/dns-json"}
#
# response_cloudflare = requests.get(url, params=params, headers=headers)
# data_cloudflare_json = json.loads(response_cloudflare.text)
# data_cloudflare = [a['data'] for a in data_cloudflare_json['Answer'] if a['type'] == 1]
# print(data_cloudflare)
# DomainName = "github.com"
#
# # Google DNS Request API
# url = "https://dns.google/resolve?name=" + DomainName + "&type=1"
# response_google = urllib.request.urlopen(url)
# ret_DNS_json_google = response_google.read().decode('utf-8')
# json_str = ret_DNS_json_google
# data_google = json.loads(json_str)
# data_google = [answer['data'] for answer in data_google['Answer'] if answer['type'] == 1]
#
# # CloudFlare DNS Request API
# url = "https://cloudflare-dns.com/dns-query"
# params = {"name": DomainName, "type": "A"}
# headers = {"accept": "application/dns-json"}
# response_cloudflare = requests.get(url, params=params, headers=headers)
# data_cloudflare_json = json.loads(response_cloudflare.text)
# data_cloudflare = [a['data'] for a in data_cloudflare_json['Answer'] if a['type'] == 1]

# Alibaba DNS Request API
# url = "https://dns.alidns.com/resolve?name=" + DomainName + "&type=1"
# response_alibaba = urllib.request.urlopen(url)
# ret_DNS_json_alibaba = response_alibaba.read().decode('utf-8')
# data_alibaba_json = json.loads(ret_DNS_json_alibaba)
# data_alibaba = [a['data'] for a in data_alibaba_json['Answer'] if a['type'] == 1]
#
# # 9.9.9.9 DNS Request API
# url = "https://9.9.9.9:5053/dns-query?name=" + DomainName + "&type=1"
# response_quadnine = urllib.request.urlopen(url)
# ret_DNS_json_quadnine = response_quadnine.read().decode('utf-8')
# data_quadnine_json = json.loads(ret_DNS_json_quadnine)
# data_quadnine = [a['data'] for a in data_quadnine_json['Answer'] if a['type'] == 1]
#
# # quadnine DNS Request API
# url = "https://dns.quad9.net:5053/dns-query?name=" + DomainName + "&type=1"
# response_quadnine_sec = urllib.request.urlopen(url)
# ret_DNS_json_quadnine_sec = response_quadnine_sec.read().decode('utf-8')
# data_quadnine_json_sec = json.loads(ret_DNS_json_quadnine_sec)
# data_quadnine_sec = [a['data'] for a in data_quadnine_json_sec['Answer'] if a['type'] == 1]
#
# # Integration
# authed_list_IPAddress = list(set(data_cloudflare + data_quadnine + data_google + data_quadnine_sec))
#
# print(authed_list_IPAddress)





# import requests
# import json
# import ipaddress
#
# # 从URL获取JSON数据
# url = "https://www.gstatic.com/ipranges/goog.json"
# response = requests.get(url)
# data = json.loads(response.text)
#
# # 提取IPv4前缀列表
# ipv4_prefixes = []
# for prefix in data["prefixes"]:
#     if "ipv4Prefix" in prefix:
#         ipv4_prefixes.append(prefix["ipv4Prefix"])
#
# # 查询IP地址
# def is_ip_in_prefixes(ip, prefixes):
#     for prefix in prefixes:
#         if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(prefix):
#             return True
#     return False
#
# # 测试查询
# ip = "64.233.170.132"
# result = is_ip_in_prefixes(ip, ipv4_prefixes)
# print(ip, "存在于IPv4前缀列表中：", result)


#
# import csv
#
# prefixes = []
#
# with open('msft-public-ips.csv', newline='') as csvfile:
#     reader = csv.DictReader(csvfile)
#     for row in reader:
#         prefixes.append(row['Prefix'])
#
# print(prefixes)


#
# import json
# import re
#
# # 读取github.txt文件中的JSON数据
# with open('github.txt', 'r') as f:
#     data = json.load(f)
#
# # 匹配IPv4地址的正则表达式
# ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
#
# # 用于存储IPv4地址的列表
# ipv4_list = []
#
# # 遍历所有的键和值，查找IPv4地址
# for key, value in data.items():
#     # 如果值是一个列表，遍历列表中的每个元素
#     if isinstance(value, list):
#         for item in value:
#             # 在列表元素中查找IPv4地址
#             matches = re.findall(ipv4_pattern, item)
#             ipv4_list.extend(matches)
#     # 如果值是一个字符串，查找其中的IPv4地址
#     elif isinstance(value, str):
#         matches = re.findall(ipv4_pattern, value)
#         ipv4_list.extend(matches)
#
# # 去重并排序
# ipv4_list = sorted(list(set(ipv4_list)))
#
# # 输出结果
# print(ipv4_list)

# import json
# import ipaddress
#
# # 读取JSON文件
# with open('github.txt', 'r') as f:
#     data = json.load(f)
#
# ipv4_addresses = []
#
# # 遍历所有的键值对
# for key, value in data.items():
#     # 判断键是否为IP地址段
#     if key in ['hooks', 'web', 'api', 'git', 'packages', 'pages', 'importer', 'actions']:
#         # 遍历IP地址段列表
#         for ip_range in value:
#             # 将IP地址段转换成IPv4Network对象
#             network = ipaddress.ip_network(ip_range, strict=False)
#             # 遍历该网络中的所有IP地址
#             for ip_address in network.hosts():
#                 # 将IPv4地址及其前缀加入列表
#                 ipv4_addresses.append(str(ip_address) + '/' + str(network.prefixlen))
#
# # 打印所有的IPv4地址及其前缀
# print(ipv4_addresses)

# import re
# import ipaddress
#
# # 读取文件内容
# with open('github.txt', 'r') as f:
#     data = f.read()
#
# ipv4_addresses = []
#
# # 定义IPv4地址的正则表达式
# ipv4_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b'
#
# # 使用正则表达式搜索IPv4地址
# for match in re.findall(ipv4_regex, data):
#     # 将IP地址段转换成IPv4Network对象
#     network = ipaddress.ip_network(match, strict=False)
#     # 遍历该网络中的所有IP地址
#     for ip_address in network.hosts():
#         # 将IPv4地址及其前缀加入列表
#         ipv4_addresses.append(str(ip_address) + '/' + str(network.prefixlen))
#
# # 打印所有的IPv4地址及其前缀
# print(ipv4_addresses)

# import re
# import json
#
# # 读取json文件
# with open('github.txt', 'r') as f:
#     data = json.load(f)
#
# # 提取所有IPv4前缀
# ipv4_prefixes = []
# for key in data:
#     if isinstance(data[key], list):
#         for item in data[key]:
#             match = re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', item)
#             if match:
#                 ipv4_prefixes.append(match.group())
#
# # 打印结果
# print(ipv4_prefixes)

#
# import re
# import json
#
# # 读取json文件
# with open('github.txt', 'r') as f:
#     data = json.load(f)
#
# # 提取所有IPv4前缀及子网掩码
# ipv4_prefixes = []
# for key in data:
#     if isinstance(data[key], list):
#         for item in data[key]:
#             match = re.search(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})', item)
#             if match:
#                 ipv4_prefixes.append(match.group())
#
# # 打印结果
# print(ipv4_prefixes)

import requests
import json

# 发送HTTP请求获取Fastly的公共IP列表
# response = requests.get('https://api.fastly.com/public-ip-list')
#
# # 解析响应，提取所有的address字段
# addresses = []
# if response.status_code == 200:
#     data = json.loads(response.content)
#     print(data['addresses'])


# import requests
#
# # 发送HTTP请求获取Cloudflare的IPv4地址列表
# response = requests.get('https://www.cloudflare.com/ips-v4')
#
# # 将响应文本按行拆分，保存到一个列表中
# addresses = []
# if response.status_code == 200:
#     data = response.text.strip()
#     addresses = data.split('\n')
#
# # 打印结果
# print(addresses)
# import requests
# import json
#
# # 发送HTTP请求获取Fastly的公共IP列表
# response = requests.get('https://api.fastly.com/public-ip-list')
#
# # 解析响应，提取所有的address字段
# addresses = []
# if response.status_code == 200:
#     data = json.loads(response.text)
#     if isinstance(data, list):
#         for item in data:
#             if isinstance(item, dict) and 'address' in item:
#                 addresses.append(item['address'])
#
# # 打印结果
# print(addresses)

import json
import requests
import csv
import re
import ipaddress

import ipaddress

address_list = []

# 打开文件并逐行读取
with open('facebook.txt', 'r') as f:
    for line in f:
        # 删除行末尾的换行符
        line = line.strip()
        # 将行添加到地址列表中
        address_list.append(line)
def is_ip_in_prefixes(ip, prefixes):
    for prefix in prefixes:
        if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(prefix):
            return True
    return False


def are_ips_in_prefixes(ip_list, prefixes):
    for ip in ip_list:
        if not is_ip_in_prefixes(ip, prefixes):
            return False
    return True

# 打印结果
print(address_list)
# address_list = []
#
# # 打开文件并逐行读取
# with open('facebook.txt', 'r') as f:
#     for line in f:
#         # 删除行末尾的换行符
#         line = line.strip()
#         # 如果行包含地址块，则将其拆分为单独的地址
#         if '/' in line:
#             # 将地址块解析为IPv4Network对象
#             network = ipaddress.IPv4Network(line)
#             # 将地址块拆分为单独的IP地址
#             for ip in network:
#                 address_list.append(str(ip))
#         else:
#             address_list.append(line)
#
# # 打印结果
# print(address_list)
# def is_ip_in_prefixes(ip, prefixes):
#     for prefix in prefixes:
#         if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(prefix):
#             return True
#     return False
#
#
# def are_ips_in_prefixes(ip_list, prefixes):
#     for ip in ip_list:
#         if not is_ip_in_prefixes(ip, prefixes):
#             return False
#     return True
#
#
# # Google Open IP List
# url = "https://www.gstatic.com/ipranges/goog.json"
# response = requests.get(url)
# data = json.loads(response.text)
# ipv4_prefixes = []
# for prefix in data["prefixes"]:
#     if "ipv4Prefix" in prefix:
#         ipv4_prefixes.append(prefix["ipv4Prefix"])
#
# # Microsoft Open IP List
# with open('msft-public-ips.csv', newline='') as csvfile:
#     reader = csv.DictReader(csvfile)
#     for row in reader:
#         ipv4_prefixes.append(row['Prefix'])
#
# # GitHub Open IP List
# with open('github.txt', 'r') as f:
#     data = json.load(f)
# for key in data:
#     if isinstance(data[key], list):
#         for item in data[key]:
#             match = re.search(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})', item)
#             if match:
#                 ipv4_prefixes.append(match.group())
#
# # Fastly Open IP List
# response = requests.get('https://api.fastly.com/public-ip-list')
# if response.status_code == 200:
#     data = json.loads(response.content)
#     ipv4_prefixes.append(data['addresses'])
#
# # Cloud Flare Open IP List
# response = requests.get('https://www.cloudflare.com/ips-v4')
# if response.status_code == 200:
#     data = response.text.strip()
#     ipv4_prefixes += data.split('\n')
#
# print(ipv4_prefixes)

list_IPAddress = ['1.1.1.1', '8.8.8.8']
if not are_ips_in_prefixes(list_IPAddress, address_list):
    print("error1")
else:
    print("error2")
#
# print(type(ipv4_prefixes))