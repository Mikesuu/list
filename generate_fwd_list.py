#!/usr/bin/env python3
import requests
import base64
import re
import os
import socket
import sys

# --- 配置 (CONFIGURATION) ---
# 远程数据源 URL (指向 GFWList 的实际链接)
REMOTE_DATA_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"

# --- 输出配置 (OUTPUT CONFIGURATION) ---
OUTPUT_FILE = "fwd-ip-list.rsc"     # Mikrotik将下载的新文件
ADDRESS_LIST_NAME = "ProxyList"    # 供 Mangle 规则使用的地址列表名称
COMMENT_PREFIX = "ProxyIP-"       # 地址列表条目的注释前缀

# --- 函数定义 ---

def extract_domains(data_content):
    """从 Base64 解码后的内容中提取域名"""
    domains = set()
    
    # 规则解析 (提取域名)
    for line in data_content.splitlines():
        line = line.strip()
        if not line or line.startswith('!') or line.startswith('['):
            continue

        # 匹配常见的域名格式
        match_domain = re.search(r'(?:\|\||\.(?:\*))?([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+|[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)', line)
        
        if match_domain:
            domain = match_domain.group(1).lower().strip()

            # 过滤掉 IP 地址
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
                continue
                
            if domain.startswith('.'):
                 domain = domain[1:]
                
            if domain and '.' in domain:
                 domains.add(domain)

    return sorted(list(domains))

def fetch_and_decode_data():
    """下载并解码远程数据"""
    print(f"🌐 正在从 {REMOTE_DATA_URL} 获取数据...")
    try:
        response = requests.get(REMOTE_DATA_URL, timeout=30)
        response.raise_for_status() # 检查HTTP错误
        
        b64_content = response.text
        raw_content = re.sub(r'!.*\n', '', b64_content)
        decoded_content = base64.b64decode(raw_content).decode('utf-8')
        return decoded_content
    except Exception as e:
        print(f"❌ 错误: 无法获取或解码远程数据: {e}", file=sys.stderr)
        return None

def generate_mikrotik_rsc(domains):
    """生成 Mikrotik Address List (.rsc) 配置内容"""
    rsc_content = f"# IP Address List for Proxy Policy Routing\n"
    rsc_content += f"# Generated at: {os.popen('date -u').read().strip()}\n"
    rsc_content += f"# Source: {REMOTE_DATA_URL} (Domain list source)\n\n"
    
    # 强制清除旧列表，确保每次导入都是最新的，并从 /ip firewall address-list 开始
    rsc_content += f"/ip firewall address-list\n"
    rsc_content += f"remove [find list={ADDRESS_LIST_NAME}]\n\n"

    print("--- 正在进行 DNS 解析 (可能耗时较久)... ---")
    
    count = 0
    resolved_ips = set() # 用于去重IP地址
    
    for domain in domains:
        try:
            # 尝试获取 IPv4 地址
            addr_info = socket.getaddrinfo(domain, 80, socket.AF_INET, socket.SOCK_STREAM)
            
            # 提取所有唯一的 IPv4 地址
            ips = [info[4][0] for info in addr_info]
            
            for ip in ips:
                if ip not in resolved_ips:
                    # 格式化成 Address List 导入命令
                    safe_comment = (COMMENT_PREFIX + domain)[:63] 
                    rsc_command = (
                        f'add address="{ip}" '
                        f'list="{ADDRESS_LIST_NAME}" '
                        f'comment="{safe_comment}"\n'
                    )
                    rsc_content += rsc_command
                    resolved_ips.add(ip)
                    count += 1
            
        except socket.gaierror:
            continue
        except Exception:
            continue

    print(f"✅ 成功解析并生成 {count} 条 IP 地址条目。")
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
        print(f"✅ 成功将 Mikrotik IP 地址脚本写入 {OUTPUT_FILE}")
        
    except Exception as e:
        print(f"❌ 写入文件失败: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
