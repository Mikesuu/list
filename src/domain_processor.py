import requests
import base64 # 修复：确保 base64 库被导入
import re
import os
import sys
import json
import socket # 仍保留，以防万一

# --- 配置 (CONFIGURATION) ---
REMOTE_DATA_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"

# --- DOH 配置 ---
DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query" # 使用 Cloudflare DOH Endpoint
TIMEOUT_SECONDS = 10 # 增加超时时间，以应对 Cloudflare 的限速

# --- 输出配置 (OUTPUT CONFIGURATION) ---
OUTPUT_FILE = "fwd-ip-list.rsc"     
ADDRESS_LIST_NAME = "ProxyRouteIPs" 
COMMENT_PREFIX = "RouteIP-"       

# --- 函数定义 (Functions) ---

def doh_resolve(domain):
    """使用 Cloudflare DOH API 解析域名并返回 IPv4 地址列表"""
    headers = {
        'accept': 'application/dns-json'
    }
    params = {
        'name': domain,
        'type': 'A' # 请求 IPv4 地址
    }
    
    try:
        # 使用更大的超时时间
        response = requests.get(DOH_ENDPOINT, params=params, headers=headers, timeout=TIMEOUT_SECONDS)
        response.raise_for_status()
        data = response.json()
        
        ips = []
        if 'Answer' in data:
            for answer in data['Answer']:
                if answer['type'] == 1: # A record type
                    ips.append(answer['data'])
        return ips
        
    except requests.exceptions.RequestException:
        return []
    except json.JSONDecodeError:
        return []

def extract_domains(data_content):
    """从 Base64 解码后的内容中提取域名"""
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
    """下载并解码远程数据"""
    print(f"🌐 正在获取数据...")
    try:
        response = requests.get(REMOTE_DATA_URL, timeout=30)
        response.raise_for_status() 
        
        b64_content = response.text
        raw_content = re.sub(r'!.*\n', '', b64_content)
        # GFWList 数据经过 Base64 编码，所以需要 base64.b64decode
        decoded_content = base64.b64decode(raw_content).decode('utf-8') 
        return decoded_content
    except Exception as e:
        print(f"❌ 错误: 无法获取或解码远程数据: {e}", file=sys.stderr)
        return None

def generate_mikrotik_rsc(domains):
    """生成 Mikrotik Address List (.rsc) 配置内容"""
    rsc_content = f"# IP Address List for Policy Routing\n"
    rsc_content += f"# Generated at: {os.popen('date -u').read().strip()}\n"
    rsc_content += f"# Source: Remote Domain List via DOH\n\n"
    
    rsc_content += f"/ip firewall address-list\n"
    rsc_content += f"remove [find list={ADDRESS_LIST_NAME}]\n\n"

    print("--- 正在进行 DOH 解析 (预计需要 10-20 分钟)... ---")
    
    count = 0
    resolved_ips = set() 
    
    for domain in domains:
        ips = doh_resolve(domain) # 使用 DOH 解析
        
        for ip in ips:
            if ip not in resolved_ips:
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip): 
                    safe_comment = (COMMENT_PREFIX + domain)[:63] 
                    rsc_command = (
                        f'add address="{ip}" '
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
