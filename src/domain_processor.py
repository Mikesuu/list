import requests
import base64 
import re
import os
import sys
import json
import socket 
import datetime

REMOTE_DATA_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"

DOH_IP = "8.8.8.8" 
DOH_HOSTNAME = "dns.google" 
TIMEOUT_SECONDS = 20 

OUTPUT_FILE = "fwd-ip-list.rsc"     
ADDRESS_LIST_NAME = "ProxyRouteIPs" 
COMMENT_PREFIX = "RouteIP-"       

def doh_resolve(domain):
    url = f"https://{DOH_IP}/resolve" 
    
    headers = {
        'accept': 'application/json',
        'Host': DOH_HOSTNAME 
    }
    params = {
        'name': domain,
        'type': 'A' 
    }
    
    try:
        response = requests.get(url, params=params, headers=headers, timeout=TIMEOUT_SECONDS)
        response.raise_for_status()
        data = response.json()
        
        ips = []
        if 'Answer' in data:
            for answer in data['Answer']:
                if answer['type'] == 1: 
                    ips.append(answer['data']) 
        return ips
        
    except requests.exceptions.RequestException as e:
        return []
    except json.JSONDecodeError:
        return []

def extract_domains(data_content):
    domains = set()
    for line in data_content.splitlines():
        line = line.strip()
        if not line or line.startswith('!') or line.startswith('[') or line.startswith('@'):
            continue

        match_domain = re.search(r'(?:\|\||\.(?:\*))?([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+|[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)', line)
        
        if match_domain:
            domain = match_domain.group(1).lower().strip()

            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain) or 'localhost' in domain:
                continue
            if domain.startswith('.'):
                 domain = domain[1:]
            if domain and '.' in domain:
                 domains.add(domain)

    return sorted(list(domains))

def fetch_and_decode_data():
    print(f"🌐 正在获取数据...")
    try:
        response = requests.get(REMOTE_DATA_URL, timeout=30)
        response.raise_for_status() 
        
        b64_content = response.text
        raw_content = re.sub(r'!.*\n', '', b64_content)
        decoded_content = base64.b64decode(raw_content).decode('utf-8') 
        return decoded_content
    except Exception as e:
        print(f"❌ 错误: 无法获取或解码远程数据: {e}", file=sys.stderr)
        return None

def generate_mikrotik_rsc(domains):
    
    rsc_content = f"# Mikrotik Policy IP List\n" 
    # 关键修复：使用完整路径和双引号
    rsc_content += f'/ip firewall address-list remove [find list="{ADDRESS_LIST_NAME}"]\n\n'
    
    print("--- 正在进行 DOH 解析 (预计需要 15-30 分钟)... ---")
    
    count = 0
    resolved_ips = set() 
    
    for domain in domains:
        ips = doh_resolve(domain) 
        
        for ip in ips:
            if ip not in resolved_ips:
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip): 
                    safe_comment = (COMMENT_PREFIX + domain)[:63] 
                    rsc_command = (
                        # 关键修复：使用完整路径和双引号
                        f'/ip firewall address-list add address="{ip}" ' 
                        f'list="{ADDRESS_LIST_NAME}" '
                        f'comment="{safe_comment}"\n'
                    )
                    rsc_content += rsc_command
                    resolved_ips.add(ip)
                    count += 1

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
    
    try:
        output_path = os.path.join(os.path.dirname(__file__), '..', OUTPUT_FILE)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(rsc_data)
        print(f"✅ 成功将 Mikrotik IP 地址脚本写入 {output_path}")
        
    except Exception as e:
        print(f"❌ 写入文件失败: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    main()
