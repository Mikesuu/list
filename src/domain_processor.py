import requests
import base64
import re
import os
import sys
from dns.resolver import Resolver, LifetimeTimeout
from dns.exception import DNSException

# --- 配置 (CONFIGURATION) ---
# 远程数据源 URL (指向 Base64 编码的域名列表)
REMOTE_DATA_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"

# --- 输出配置 (OUTPUT CONFIGURATION) ---
OUTPUT_FILE = "fwd-ip-list.rsc"     # Mikrotik将下载的新文件
ADDRESS_LIST_NAME = "ProxyRouteIPs" # 供 Mangle 规则使用的地址列表名称
COMMENT_PREFIX = "RouteIP-"       # 地址列表条目的注释前缀

# DOH 配置 (使用 Cloudflare DOH 服务器 IP)
DOH_SERVER_IP = "1.1.1.1" 
TIMEOUT_SECONDS = 5
MAX_RETRIES = 2

def setup_doh_resolver():
    """配置使用 DOH 服务器的解析器"""
    resolver = Resolver(configure=False)
    # 使用 DOH 服务器的 IP 地址
    resolver.nameservers = [DOH_SERVER_IP]
    resolver.timeout = TIMEOUT_SECONDS
    resolver.lifetime = TIMEOUT_SECONDS * MAX_RETRIES
    return resolver

def extract_domains(data_content):
    """从 Base64 解码后的内容中提取域名"""
    domains = set()
    for line in data_content.splitlines():
        line = line.strip()
        if not line or line.startswith('!') or line.startswith('[') or line.startswith('@'):
            continue

        # 匹配常见的域名格式
        match_domain = re.search(r'(?:\|\||\.(?:\*))?([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+|[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)', line)
        
        if match_domain:
            domain = match_domain.group(1).lower().strip()

            # 过滤掉 IP 地址和无效格式
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
        # GFWList 数据经过 Base64 编码
        decoded_content = base64.b64decode(raw_content).decode('utf-8')
        return decoded_content
    except Exception as e:
        print(f"❌ 错误: 无法获取或解码远程数据: {e}", file=sys.stderr)
        return None

def generate_mikrotik_rsc(domains, resolver):
    """生成 Mikrotik Address List (.rsc) 配置内容"""
    rsc_content = f"# IP Address List for Policy Routing\n"
    rsc_content += f"# Generated at: {os.popen('date -u').read().strip()}\n"
    rsc_content += f"# Source: Remote Domain List\n\n"
    
    # 强制清除旧列表，确保每次导入都是最新的
    rsc_content += f"/ip firewall address-list\n"
    rsc_content += f"remove [find list={ADDRESS_LIST_NAME}]\n\n"

    print("--- 正在进行 DOH 解析 (可能耗时较久)... ---")
    
    count = 0
    resolved_ips = set() # 用于去重IP地址
    
    for domain in domains:
        try:
            # 尝试解析 A 记录 (IPv4)
            answers = resolver.resolve(domain, 'A')
            
            for rdata in answers:
                ip = str(rdata)
                
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
            
        except (DNSException, LifetimeTimeout):
            # 解析失败或超时，跳过该域名
            continue
        except Exception as e:
            # print(f"Error processing {domain}: {e}")
            continue

    print(f"✅ 成功解析并生成 {count} 条 IP 地址条目。")
    return rsc_content

def main():
    # 确保 dnspython 已安装
    try:
        import dnspython
    except ImportError:
        print("❌ 错误: 缺少 dnspython 库。请在 actions 中安装：pip install dnspython requests", file=sys.stderr)
        sys.exit(1)
        
    decoded_content = fetch_and_decode_data()
    if not decoded_content:
        sys.exit(1)

    domains = extract_domains(decoded_content)
    if not domains:
        print("❌ 未提取到任何有效域名。", file=sys.stderr)
        sys.exit(1)

    resolver = setup_doh_resolver()
    rsc_data = generate_mikrotik_rsc(domains, resolver)
    
    # 写入文件到项目根目录
    try:
        output_path = os.path.join(os.path.dirname(__file__), '..', OUTPUT_FILE)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(rsc_data)
        print(f"✅ 成功将 Mikrotik IP 地址脚本写入 {output_path}")
        
    except Exception as e:
        print(f"❌ 写入文件失败: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    # 切换到脚本所在目录，方便处理相对路径
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    main()
