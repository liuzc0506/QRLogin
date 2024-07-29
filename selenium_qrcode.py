from selenium import webdriver
import cv2
from pyzbar.pyzbar import decode
from urllib.parse import urlparse, parse_qs, parse_qsl
import json, os, time, sys
import base64


def capture_screenshot(url):
    try:
        options = webdriver.ChromeOptions()
        # options.add_argument("--headless")  # 无头模式
        options.add_argument("--proxy-server=localhost:7778")
        options.add_argument('--disable-blink-features=AutomationControlled')       # 禁用window.navigator.webdriver，应对服务器检测
        options.add_argument('--ignore-certificate-errors')  # 忽略证书错误
        options.page_load_strategy = 'none'
        driver = webdriver.Chrome(options=options)
        driver.maximize_window()

        # 加载网页
        driver.get(url)

        # 截取页面截图
        screenshot_path = "screenshot.png"
        input("When QR Code appears on the screen, press Enter to continue...")

        # 获取当前所有打开的标签页的句柄
        window_handles = driver.window_handles

        # 切换到新的标签页
        driver.switch_to.window(window_handles[-1])
        
        driver.save_screenshot(screenshot_path)
        print(f"Screenshot captured: {screenshot_path}")


        input("After finishing QRLogin, press Enter to start FLAW DETECTION...")
        with open('done_flag.txt', 'w') as f:
            f.write('1')

        input("Press Enter to exit...")

        # 关闭浏览器
        # driver.quit()



    except Exception as e:
        print(f"Error capturing screenshot: {e}")



# 找到尺寸最大的二维码，解析二维码获取qrid
def decode_qrcode(screenshot_path):
    # 等待截图文件出现，或者超时
    # start_time = time.time()
    # while not os.path.exists(screenshot_path):
    #     time.sleep(0.1)  # 暂停0.1秒，然后再次检查
    print(f"File {screenshot_path} exists")

    # 读取截图
    image = cv2.imread(screenshot_path)

    # 使用pyzbar解码二维码
    decoded_objects = decode(image)

    params = {}
    if not decoded_objects:
        print("pyzbar未检测到二维码")
    else:
        # 打印所有二维码信息
        for obj in decoded_objects:
            print(f"类型: {obj.type}, 数据: {obj.data}")

        # 找到最大的二维码
        largest_qr = max(decoded_objects, key=lambda x: x.rect[2] * x.rect[3])

        # 标记出来看看找对没
        # 在原始图像上画出最大二维码的边框
        # x, y, w, h = largest_qr.rect
        # cv2.rectangle(image, (x, y), (x + w, y + h), (0, 255, 0), 2)

        # # 显示带有标记的图像
        # cv2.imshow("Marked Image", image)
        # cv2.waitKey(0)

        # 解码最大的二维码
        decoded_data = largest_qr.data.decode("utf-8")
        print(f"最大二维码解码内容: {decoded_data}")

        params = extract_para(decoded_data)
        print(f"提取参数: {params}")
        print("\n\n\n\n")

    #pyzbar检测不到二维码，用opencv的API兜底
    if not decoded_objects:
        # gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        decoded_objects= cv2.QRCodeDetector().detectAndDecode(image)
        if decoded_objects[0] != '':
            decoded_data = decoded_objects[0]
            print(f"最大二维码解码内容: {decoded_data}")
            params = extract_para(decoded_data)
            print(f"提取参数: {params}")
            print("\n\n\n\n")
        else:
            print("opencv detectAndDecode 未检测到二维码")

    return params

# 从解码的二维码中提取qrid等参数
def extract_para(decoded_data):
    params = {}

    # 检查是否是base64编码，若是则先进行解码
    try:
        decoded_data = base64.b64decode(decoded_data).decode()
    except Exception:
        pass

    # 提取qrid（二维码中的参数）
    if decoded_data.startswith("http") or "://" in decoded_data:    # 自定义协议
        # 如果是URL，从URL中提取qrid
        parsed_url = urlparse(decoded_data)
        # 解析查询参数
        params = dict(parse_qsl(parsed_url.query))      # parse_qsl解析得到的value不是列表，parse_qs解析得到的字典值是列表
        # qrid可能是参数中的一部分 e.g. "ZEPETO://PLATFORM/QR_LOGIN?url=https://zauth.zepeto.io&api=/oauth2/authorize/qr/66ca2f88-7568-4e3b-b57b-aa2348682ef6/confirm&udid=7efb336e-8944-4ad7-9e88-38ac5680bfbe&type=world" 中，qrid为66ca2f88-7568-4e3b-b57b-aa2348682ef6
        if params:
            params_copy = params.copy()
            for key, value in params_copy.items():
                if '/' in value:
                    tmps = value.split('/')
                    for tmp in tmps:
                        if len(tmp) > 15:
                            params['addition_qrid'] = tmp
                            break
        # 可能在#片段中
        if not params and '#' in decoded_data:  
            params = dict(parse_qsl(parsed_url.fragment))
        if not params and not parsed_url.path:
            if "=" not in parsed_url.netloc:
                params = {'qrid': parsed_url.netloc}
            else:
                params = dict(parse_qsl(parsed_url.netloc)) 
        # 可能在URL路径中，取最后一段为qrid，如http://www.camscanner.com/l/42946B1BD620471A0C7DR7RS
        if not params:
            if parsed_url.path[-1] == '/':
                params = {'qrid': parsed_url.path.split('/')[-2]}
            else:
                params = {'qrid': parsed_url.path.split('/')[-1]}
        
    elif is_json(decoded_data):
        # 如果是json，直接解析json
        params = json.loads(decoded_data)
    elif ':' in decoded_data:           # 江苏智慧人社，江苏政务服务
        # 如果是键值对形式，直接解析
        key, value = decoded_data.split(':', 1)
        params = {key: value}
    elif '&' in decoded_data:          # xt.com  9c70f2be57ca47c089ba14cd5ea0cef4&qrLogin
        values = decoded_data.split('&')
        for i, value in enumerate(values):
            params[f'qrcode{i}'] = value
    else:
        # 其他情况，直接返回解码内容
        params = {'qrcode': decoded_data}
    return params
            
            

# 判断是否为json格式
def is_json(json_string):
    try:
        json.loads(json_string)
    except ValueError:
        return False
    return True


if __name__ == "__main__":
    # url = "https://kyfw.12306.cn/otn/resources/login.html"    # 12306 重用
    # url = "https://www.qcc.com/"
    # url = "https://gab.122.gov.cn/m/login"      # 交管12123 重用（已修复）
    # url = "https://user.zjzwfw.gov.cn/pc/login?action=ssoLogin&servicecode=yhzxxt&goto=https%253A%252F%252Fwww.zjzwfw.gov.cn%252Fzjservice-fe%252F%2523%252Fhome"   # 浙江政务服务 重用
    # url = "https://zwfw.xinjiang.gov.cn/xjwwrz/login/oauth2login?client_id=e79538ce-f924-4795-96c4-779e3b5ce07c&response_type=code&scope=user&redirect_uri=https%3A%2F%2Fzwfw.xinjiang.gov.cn"  # 新疆政务服务 二维码本地生成
    # url = "https://yun.139.com/w/#/"
    # url = "https://pan.bitqiu.com/#signin-phone"
    # url = "https://cloud.189.cn/web/login.html"

    url = ""
    if len(sys.argv) > 1:
        url = sys.argv[1]
        print("url:", url)
        capture_screenshot(url)
    else:
        print("No url argument provided.")
    

    # test = "qrid=11222&bus=NA"
    # print(dict(parse_qsl(test)))

    # test = "tmri://12123?ywlx=9921&token=8ed43c99-2f92-4f79-86f1-ce831375ac5a"
    # test = "https://yun.139.com/w/#/qrcLogin?sID=HbECpALM4W7kcm4W&dID=79e937930664585a5d9953b414cf6ccf&cType=9"
    # test = "ZEPETO://PLATFORM/QR_LOGIN?url=https://zauth.zepeto.io&api=/oauth2/authorize/qr/66ca2f88-7568-4e3b-b57b-aa2348682ef6/confirm&udid=7efb336e-8944-4ad7-9e88-38ac5680bfbe&type=world"
    # print(extract_para(test))
    
    
    # TEST
    # decode_qrcode("screenshot.png")