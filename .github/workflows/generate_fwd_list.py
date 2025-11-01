#!/usr/bin/env python3
import urllib.request
import base64
import re
import os
import socket
import sys

# --- 配置 (CONFIGURATION) ---
# 远程数据源 URL (指向 GFWList 的实际链接)
REMOTE_DATA_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
OUTPUT_FILE = "fwd_list_mikrotik_dns.rsc"

# 默认转发 DNS 服务器 (Google Public DNS)
DEFAULT_DNS = "8.8.8.8"
DEFAULT_DNS_SECONDARY = "8.8.4.4"

# 使用 Google 的 DoH 服务器 IP
# Mikrotik FWD (转发) 类型需要指定 IP 地址
FWD_SERVER_IP_1 = "8.8.8.8"      
FWD_SERVER_IP_2 = "8.8.4.4"     
FWD_COMMENT = "Domain_FwdList"   # 用于 Mikrotik 条目的注释

# --- 函数定义 ---

def extract_domains(data_content):
    """从 Base64 解码后的内容中提取域名"""
    domains = set()
    
    # 规则解析 (简化版，提取常见的域名格式)
    for line in data_content.splitlines():
        line = line.strip()
        if not line or line.startswith('!') or line.startswith('['):
            continue

        # 匹配 ||.domain.com, |https://domain.com, |http://domain.com
        # 匹配以 . 或 || 开头，后面跟着域名的部分
        match_domain = re.search(r'(?:\|\||\.(?:\*))?([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+|[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)', line)
        
        if match_domain:
            domain = match_domain.group(1).lower().strip()

            # 过滤掉 IP 地址
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
                continue
            
            # 提取有效的域名部分
            if domain.startswith('.'):
                 domain = domain[1:]
            
            # 确保是有效的域名格式
            if domain and '.' in domain:
                 domains.add(domain)

    return sorted(list(domains))

def fetch_and_decode_data():
    """下载并解码远程数据"""
    print(f"🌐 正在从 {REMOTE_DATA_URL} 获取数据...")
    try:
        with urllib.request.urlopen(REMOTE_DATA_URL, timeout=30) as response:
            b64_content = response.read().decode('utf-8')
            # 移除头部注释
            raw_content = re.sub(r'!.*\n', '', b64_content)
            decoded_content = base64.b64decode(raw_content).decode('utf-8')
            return decoded_content
    except Exception as e:
        print(f"❌ 错误: 无法获取或解码远程数据: {e}", file=sys.stderr)
        return None

def generate_mikrotik_rsc(domains):
    """生成 Mikrotik .rsc 配置内容"""
    rsc_content = f"# Domain FwdList DNS Static Entries for Mikrotik\n"
    rsc_content += f"# Generated at: {os.popen('date -u').read().strip()}\n"
    rsc_content += f"# Source: {REMOTE_DATA_URL} (Used as data source)\n\n"
    rsc_content += "/ip dns static\n"

    # 使用 DoH 转发策略的 IP 地址
    target_ip = f"{FWD_SERVER_IP_1},{FWD_SERVER_IP_2}"
    comment = FWD_COMMENT
    
    rsc_content += f"# 导入前建议在 Mikrotik 终端清理旧条目: \n"
    rsc_content += f"# /ip dns static remove [find comment~\"{comment}\"]\n\n"
    
    count = 0
    for domain in domains:
        # 使用 type=FWD (转发)，match-subdomain=yes 匹配所有子域名
        rsc_content += (
            f"add name=\"{domain}\" "
            f"type=FWD match-subdomain=yes "
            f"forward-to={target_ip} "
            f"comment=\"{comment}\"\n"
        )
        count += 1
        
    print(f"✅ 成功生成 {count} 条目。目标转发地址: {target_ip}")
    return rsc_content

def main():
    decoded_content = fetch_and_decode_data()
    if not decoded_content:
        sys.exit(1)

    domains = extract_domains(decoded_content)
    if not domains:
        print("❌ 未提取到任何有效域名。", file=sys.stderr)
        sys.exit(1)

    rsc_data = generate_mikrotik_rsc(domains)
    
    # 写入文件
    try:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write(rsc_data)
        print(f"✅ 成功将 Mikrotik 脚本写入 {OUTPUT_FILE}")
        
    except Exception as e:
        print(f"❌ 写入文件失败: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
