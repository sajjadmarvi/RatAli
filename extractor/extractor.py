import os
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import urlparse, parse_qs

# تابع برای دانلود فایل‌های SVG
def download_svg(url, folder):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            file_path = os.path.join(folder, url.split("/")[-1])
            with open(file_path, 'wb') as file:
                file.write(response.content)
            print(f"Downloaded: {url} -> {file_path}")
        else:
            print(f"Failed to download: {url} (Status Code: {response.status_code})")
    except Exception as e:
        print(f"Error downloading {url}: {e}")

# تابع برای ایجاد پوشه‌ها
def create_folder(folder_name):
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
        print(f"Created folder: {folder_name}")
    else:
        print(f"Folder already exists: {folder_name}")

# تابع برای استخراج لینک‌های SVG از یک صفحه
def scrape_page(url, log_file):
    print(f"Scraping page: {url}")
    response = requests.get(url)
    if response.status_code != 200:
        print(f"Failed to fetch URL: {url} (Status Code: {response.status_code})")
        return
    
    soup = BeautifulSoup(response.content, 'html.parser')
    
    # پیدا کردن تمام لینک‌های SVG
    svg_links = soup.find_all('a', href=True)
    print(f"Found {len(svg_links)} links on the page.")
    
    for link in svg_links:
        href = link['href']
        if href.endswith('.svg'):
            full_url = href if href.startswith('http') else f"{url}/{href}"  # ساخت URL کامل
            
            # تجزیه URL برای حذف query string
            parsed_url = urlparse(url)
            category_name = parsed_url.path.split("/")[-1] or "default"  # اگر path خالی بود، از "default" استفاده کن
            
            # حذف کاراکترهای غیرمجاز از نام دسته‌بندی
            invalid_chars = '<>:"/\\|?*'
            for char in invalid_chars:
                category_name = category_name.replace(char, "_")
            
            folder_path = os.path.join("downloads", category_name)
            create_folder(folder_path)
            download_svg(full_url, folder_path)
    
    # ذخیره URL فعلی در فایل لاگ
    with open(log_file, 'a') as log:
        log.write(url + "\n")
    
    # پیدا کردن لینک‌های صفحه بعد (اگر وجود دارد)
    next_page = soup.find('a', string='Next')
    if next_page:
        next_page_url = next_page['href'] if next_page['href'].startswith('http') else f"{url}/{next_page['href']}"
        print(f"Found next page: {next_page_url}")
        scrape_page(next_page_url, log_file)  # بازگشت به تابع برای پیمایش صفحه بعد
    else:
        print(f"No more pages found in: {url}")

# تابع برای خواندن URL‌ها از فایل txt
def read_urls_from_file(file_path):
    with open(file_path, 'r') as file:
        urls = file.read().splitlines()  # خواندن خطوط و حذف کاراکترهای جدید
    return urls

# تابع برای خواندن آخرین URL از فایل لاگ
def read_last_url_from_log(log_file):
    if os.path.exists(log_file):
        with open(log_file, 'r') as log:
            lines = log.read().splitlines()
            if lines:
                return lines[-1]  # آخرین URL ذخیره شده
    return None

# شروع عملیات
def main():
    # مسیر فایل txt حاوی URL‌ها
    input_file = input("enter your urls file txt : ")
    
    # خواندن URL‌ها از فایل
    urls = read_urls_from_file(input_file)
    print(f"Found {len(urls)} URLs in the file.")
    
    # درخواست فایل لاگ از کاربر
    log_file = input("Enter the path to the log file (or '0' to start from the beginning): ").strip()
    
    if log_file == '0':
        # ایجاد فایل لاگ جدید با تاریخ و ساعت شروع
        start_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_file = f"crawl_log_{start_time}.txt"
        print(f"Starting from the beginning. New log file created: {log_file}")
        start_index = 0
    else:
        # بررسی وجود فایل لاگ
        if os.path.exists(log_file):
            last_url = read_last_url_from_log(log_file)
            if last_url:
                print(f"Found log file. Last crawled URL: {last_url}")
                start_index = urls.index(last_url) + 1 if last_url in urls else 0
            else:
                print("Log file is empty. Starting from the beginning.")
                start_index = 0
        else:
            print("Log file does not exist. Starting from the beginning.")
            start_index = 0
    
    # پیمایش هر URL و انجام عملیات استخراج
    for i in range(start_index, len(urls)):
        scrape_page(urls[i], log_file)

# اجرای برنامه
if __name__ == "__main__":
    main()