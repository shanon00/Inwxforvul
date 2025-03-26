import logging
import os
import re
import json
import time
import requests
import subprocess
import platform
from datetime import datetime, timedelta
import sys
from typing import List, Dict, Optional
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type # type: ignore

# 常量配置
HEADERS = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
}
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "doc", datetime.now().strftime("%Y-%m-%d"))
DATA_FILE = os.path.join(BASE_DIR, "data.json")


def setup_logging() -> None:
    """配置日志"""
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler("script.log"), logging.StreamHandler()],
    )


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10),
    retry=retry_if_exception_type(requests.RequestException)
)
def get_brucefeIix_url() -> List[str]:
    """获取BruceFeIix的每日文章URL"""
    current_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    url = f"https://raw.githubusercontent.com/BruceFeIix/picker/refs/heads/master/archive/daily/{current_date[:4]}/{current_date}.md"
    response = requests.get(url, headers=HEADERS, timeout=10)
    response.raise_for_status()
    urls = re.findall(
        r"(?:复现|漏洞|CVE-\d+|CNVD|POC|EXP|0day|1day|nday|RCE|getshell).*?(https://mp.weixin.qq.com/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)",
        response.text,
        re.I
    )
    return [url.rstrip(")") for url in urls]


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10),
    retry=retry_if_exception_type(requests.RequestException)
)
def get_doonsec_url() -> List[str]:
    """获取Doonsec的文章URL"""
    url = "https://wechat.doonsec.com/rss.xml"
    response = requests.get(url, headers=HEADERS, timeout=10)
    response.raise_for_status()
    urls = re.findall(
        r"<title>.*?(?:复现|漏洞|CVE-\d+|CNVD|POC|EXP|0day|1day|nday|RCE|getshell).*?</title><link>(https://mp.weixin.qq.com/.*?)</link>",
        response.text,
        re.I
    )
    return [url.rstrip(")") for url in urls]


def get_executable_path() -> str:
    """根据平台获取可执行文件路径并确保其可执行"""
    system = platform.system()
    executable_name = (
        "wechatmp2markdown-v1.1.9_win64.exe" if system == "Windows" 
        else "wechatmp2markdown-v1.1.10_ox_arm64"
    )
    executable_path = os.path.join(BASE_DIR, "bin", executable_name)
    
    if not os.path.exists(executable_path):
        raise FileNotFoundError(f"可执行文件不存在: {executable_path}")
    
    if system != "Windows":
        try:
            os.chmod(executable_path, 0o755)
        except PermissionError as e:
            logging.error(f"无法设置执行权限: {e}")
    
    return executable_path


def get_md_path(url: str) -> Optional[str]:
    """将微信文章转换为Markdown并返回文件路径"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    try:
        executable_path = get_executable_path()
        result = subprocess.run(
            [executable_path, url, OUTPUT_DIR],
            capture_output=True,
            text=True,
            check=True,
            timeout=60
        )
        output_lines = result.stdout.strip().split("\n")
        for line in output_lines:
            if line.endswith(".md") and os.path.exists(line):
                return line
        logging.warning(f"转换 {url} 失败: 未找到生成的Markdown文件，输出: {result.stdout}")
        return None
    except subprocess.CalledProcessError as e:
        logging.error(f"转换 {url} 失败: {e.stderr}")
        return None
    except FileNotFoundError as e:
        logging.error(f"可执行文件错误: {e}")
        return None
    except subprocess.TimeoutExpired:
        logging.error(f"处理 {url} 超时，超过60秒")
        return None
    except Exception as e:
        logging.error(f"处理 {url} 时出错: {e}")
        return None


def read_json() -> Dict[str, str]:
    """读取JSON文件"""
    if not os.path.exists(DATA_FILE):
        logging.info(f"{DATA_FILE} 不存在，将创建新文件")
        return {}
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                logging.warning(f"{DATA_FILE} 为空，返回空字典")
                return {}
            return json.loads(content)
    except json.JSONDecodeError as e:
        logging.error(f"解析 {DATA_FILE} 失败: {e}，返回空字典")
        return {}
    except Exception as e:
        logging.error(f"读取 {DATA_FILE} 失败: {e}")
        return {}


def write_json(data: Dict[str, str]) -> None:
    """写入JSON文件"""
    try:
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        logging.info(f"成功写入 {DATA_FILE}")
    except Exception as e:
        logging.error(f"写入 {DATA_FILE} 失败: {e}")


def sanitize_filename(filename: str) -> str:
    """清理文件名中的非法字符"""
    return re.sub(r'[<>:"/\\|?*]', "", filename)


def main() -> None:
    """主函数"""
    setup_logging()
    data = read_json()
    
    # 支持命令行参数 'today'（逻辑未变）
    urls = get_brucefeIix_url() + get_doonsec_url()  # 默认获取昨天的数据
    
    for url in urls:
        if url not in data:
            md_path = get_md_path(url)
            if md_path:
                title = sanitize_filename(os.path.basename(md_path).replace(".md", ""))
                data[url] = title
                logging.info(f"已处理: {url} -> {md_path}")
            else:
                logging.warning(f"跳过 {url}，转换失败")
            time.sleep(1)  # 防止请求过频
    
    write_json(data)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"程序运行出错: {e}")
