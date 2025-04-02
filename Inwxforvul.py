import logging
import os
import re
import json
import time
import requests
import subprocess
import platform
from datetime import datetime
from typing import List, Dict, Optional
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type # type: ignore
from xml.etree import ElementTree as ET

# 常量配置
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
}
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "doc", datetime.now().strftime("%Y-%m-%d"))
DATA_FILE = os.path.join(BASE_DIR, "data.json")

def setup_logging() -> None:
    """配置日志系统"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler("wechat_parser.log"),
            logging.StreamHandler()
        ]
    )

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type(requests.RequestException)
)
def get_brucefeIix_url() -> List[str]:
    """从BruceFeIix仓库获取当日安全文章链接"""
    try:
        current_date = datetime.now().strftime("%Y-%m-%d")
        url = f"https://raw.githubusercontent.com/BruceFeIix/picker/master/archive/daily/{current_date[:4]}/{current_date}.md"
        print(url)
        logging.info(f"Fetching BruceFeIix articles from: {url}")
        
        response = requests.get(url, headers=HEADERS, timeout=15)
        response.raise_for_status()
        
        
        # 改进的正则表达式匹配
        pattern = r"(?:漏洞|CVE-\d+|复现|POC|EXP|RCE|CNVD|0day|1day|nday|getshell)[^\)]*?(https://mp\.weixin\.qq\.com/s/[a-zA-Z0-9_-]+)"
        urls = re.findall(pattern, response.text, re.I)
        return list(set(urls))  # 去重
    
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            logging.warning(f"当日文章尚未更新: {url}")
            return []
        raise

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type(requests.RequestException)
)
def get_doonsec_url() -> List[str]:
    """从Doonsec RSS源获取安全文章链接"""
    try:
        url = "https://wechat.doonsec.com/rss.xml"
        logging.info("Fetching Doonsec RSS feed")
        
        response = requests.get(url, headers=HEADERS, timeout=15)
        response.raise_for_status()
        
        root = ET.fromstring(response.content)
        urls = []
        
        for item in root.findall('.//item'):
            title = item.find('title').text # type: ignore
            link = item.find('link').text # type: ignore
            
            # 关键词匹配逻辑
            if re.search(r'(漏洞|CVE-\d+|复现|POC|RCE|0day|CNVD|EXP|0day|1day|nday|getshell)', title, re.I): # type: ignore
                urls.append(link)
        
        return list(set(urls))  # 去重
    
    except ET.ParseError as e:
        logging.error(f"XML解析失败: {e}")
        return []
    except Exception as e:
        logging.error(f"获取Doonsec源失败: {e}")
        return []

def get_executable_path() -> str:
    """获取转换工具的可执行路径"""
    system = platform.system()
    executable_map = {
        "Windows": "wechatmp2markdown-v1.1.9_win64.exe",
        "Darwin": "wechatmp2markdown-v1.1.10_ox_arm64",
        "Linux": "wechatmp2markdown-v1.1.10_linux_amd64"
    }
    
    if system not in executable_map:
        raise OSError(f"Unsupported platform: {system}")
    
    executable_path = os.path.join(BASE_DIR, "bin", executable_map[system])
    
    if not os.path.exists(executable_path):
        raise FileNotFoundError(f"可执行文件不存在: {executable_path}")
    
    # 设置执行权限（非Windows系统）
    if system != "Windows":
        try:
            os.chmod(executable_path, 0o755)
        except PermissionError:
            logging.error("需要管理员权限来设置可执行权限")
            raise
    
    return executable_path

def convert_wechat_article(url: str) -> Optional[str]:
    """转换微信文章到Markdown"""
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        executable = get_executable_path()
        
        # 记录转换前的文件状态
        original_files = set(os.listdir(OUTPUT_DIR))
        
        # 执行转换命令
        result = subprocess.run(
            [executable, url, OUTPUT_DIR],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120
        )
        
        # 检查命令执行结果
        if result.returncode != 0:
            logging.error(f"转换失败[exit code {result.returncode}]: {result.stderr}")
            return None
        
        # 检测新生成的文件
        new_files = set(os.listdir(OUTPUT_DIR)) - original_files
        
        # 查找 Markdown 文件
        md_files = []
        for f in new_files:
            file_path = os.path.join(OUTPUT_DIR, f)
            if os.path.isdir(file_path):
                # 如果是目录，查找其中的 Markdown 文件
                for root, _, files in os.walk(file_path):
                    for file in files:
                        if file.endswith(".md"):
                            md_files.append(os.path.join(root, file))
            elif f.endswith(".md"):
                # 如果是直接生成的 Markdown 文件
                md_files.append(file_path)
        
        if not md_files:
            logging.warning("未检测到生成的Markdown文件")
            return None
            
        # 获取最新文件
        latest_file = max(
            md_files,
            key=lambda f: os.path.getctime(f)
        )
        return latest_file
    
    except subprocess.TimeoutExpired:
        logging.error("转换超时（120秒）")
    except Exception as e:
        logging.error(f"转换异常: {str(e)}")
    
    return None

def load_data() -> Dict[str, str]:
    """加载数据文件"""
    try:
        if not os.path.exists(DATA_FILE):
            logging.info("创建新的数据文件")
            return {}
            
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip()
            return json.loads(content) if content else {}
    
    except json.JSONDecodeError:
        logging.error("数据文件损坏，重置为空")
        return {}
    except Exception as e:
        logging.error(f"加载数据失败: {e}")
        return {}

def save_data(data: Dict[str, str]) -> bool:
    """保存数据文件"""
    try:
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        logging.error(f"保存数据失败: {e}")
        return False

def sanitize_filename(filename: str) -> str:
    """清理文件名中的非法字符"""
    return re.sub(r'[\\/*?:"<>|]', "_", filename)

def main():
    """主处理流程"""
    setup_logging()
    logging.info("===== 开始处理 =====")
    
    # 初始化数据
    processed_data = load_data()
    total_processed = 0    
    try:
        # 获取所有待处理URL
        sources = [
            ("BruceFeIix", get_brucefeIix_url()),
            ("Doonsec", get_doonsec_url())
        ]
        
        all_urls = []
        for source_name, urls in sources:
            logging.info(f"从 {source_name} 获取到 {len(urls)} 个URL")
            all_urls.extend(urls)
        
        unique_urls = list(set(all_urls))
        logging.info(f"去重后待处理URL总数: {len(unique_urls)}")
        
        # 处理每个URL
        for idx, url in enumerate(unique_urls, 1):
            if url in processed_data:
                logging.info(f"跳过已处理 [{idx}/{len(unique_urls)}]: {url}")
                continue
            
            logging.info(f"开始处理 [{idx}/{len(unique_urls)}]: {url}")
            start_time = time.time()
            
            md_path = convert_wechat_article(url)
            if md_path:
                # 提取文章标题
                filename = os.path.basename(md_path).replace(".md", "")
                processed_data[url] = sanitize_filename(filename)
                total_processed += 1
                logging.info(f"转换成功: {filename} (耗时 {time.time()-start_time:.1f}s)")
            else:
                logging.warning(f"转换失败: {url}")
            
            time.sleep(1.5)  # 请求间隔
        
        # 保存数据
        if save_data(processed_data):
            logging.info(f"成功保存数据，总计 {len(processed_data)} 条记录")
        
        logging.info(f"本次处理完成，新增 {total_processed} 篇文章")
    
    except KeyboardInterrupt:
        logging.warning("用户中断操作，尝试保存当前进度...")
        save_data(processed_data)
    except Exception as e:
        logging.error(f"主流程异常: {str(e)}")
        raise
    
    logging.info("===== 处理结束 =====")

if __name__ == "__main__":
    main()
