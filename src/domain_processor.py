import requests
import base64 
import re
import os
import sys
import json
import socket 
import datetime # <<< 修复：用于安全生成日期注释

# --- 配置 (CONFIGURATION) ---
REMOTE_DATA_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"

# --- DOH 配置 ---
# *** 切换到 Google DOH IP，以尝试绕过 Cloudflare 限速 ***
DOH_IP = "8.8.8.8" 
DOH_HOSTNAME = "dns.google" 
TIMEOUT_SECONDS = 20 # 增加到 20 秒

# --- 输出配置 (OUTPUT CONFIGURATION) ---
OUTPUT_FILE = "fwd-ip-list.rsc"     
ADDRESS_LIST_NAME = "ProxyRouteIPs" 
COMMENT_PREFIX = "RouteIP-"       

# --- 函数定义 (Functions) ---

def doh_resolve(domain):
    """使用 Google DOH API 解析域名并返回 IPv4 地址列表 (通过 IP 直连)"""
    
    # 使用 IP 地址直连 Google DOH API
    url = f"https://{DOH_IP}/resolve" 
    
    headers = {
        'accept': 'application/json',
        # 关键：显式设置 Host 头部，确保 SSL 证书验证
        'Host': DOH_HOSTNAME 
    }
    params = {
        'name': domain,
        'type': 'A' # 请求 IPv4 地址
    }
    
    try:
        response = requests.get(url, params=params, headers=headers, timeout=TIMEOUT_SECONDS)
        response.raise_for_status()
        data = response.json()
        
        ips = []
        if 'Answer' in data:
            for answer in data['Answer']:
                if answer['type'] == 1: # A record type
                    # Google DOH 响应中，IP 地址在 'data' 字段
                    ips.append(answer['data']) 
        return ips
        
    except requests.exceptions.RequestException as e:
        # 打印信息，帮助分析是否仍是限速或连接问题
        print(f"DOH Connection/Resolution failed for {domain} (Google DOH)")
        return []
    except json.JSONDecodeError:
        return []

def extract_domains(data_content):
    # ... (保持不变) ...
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
    # ... (保持不变) ...
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
    """生成 Mikrotik Address List (.rsc) 配置内容"""
    
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    rsc_content = f"# IP Address List for Policy Routing\n"
    rsc_content += f"# Generated at: {current_time}\n"
    rsc_content += f"# Source: Remote Domain List via DOH (Google IP)\n\n"
    
    rsc_content += f"/ip firewall address-list\n"
    rsc_content += f"remove [find list={ADDRESS_LIST_NAME}]\n\n"

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
