import datetime
from http.cookies import SimpleCookie
import os
import string
import sys
import signal
from urllib.parse import unquote
import json
import re
from requests.exceptions import Timeout
# from selenium import webdriver

from mitmproxy import ctx
import chardet
import threading
import logging
import configparser
from urllib.parse import parse_qs, parse_qsl, urlparse, quote
import urllib
import time
import requests
from mitmproxy.http import HTTPFlow


import nltk
from nltk.corpus import words
import wordninja


if not nltk.data.find('corpora/words'):
    nltk.download('words')
if not nltk.data.find('tokenizers/punkt'):
    nltk.download('punkt')


import selenium_qrcode

class Analyzer:
    def __init__(self,url):
        self.debuggable = False     # 是否记录流量信息

        self.url = url

        self.domain = ".".join(urlparse(url).netloc.split(":")[0].split(".")[-2:])    # 获取url中的域名后两段，过滤无关流量

        # 创建logger
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(level=logging.DEBUG)
        self.logger.propagate = False   

        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)

        os.makedirs("./logs", exist_ok=True)
        fh = logging.FileHandler(f"./logs/log_{urllib.parse.quote(url, safe='')}.log", mode='w')
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)

        # self.logger.addHandler(logging.NullHandler())     # 若需终端输出，注释掉

        # 记录流量信息
        os.makedirs("./logs", exist_ok=True)
        self.traffic_recording = f"./logs/traffic_{urllib.parse.quote(url, safe='')}.txt"
        if os.path.exists(self.traffic_recording):
            os.remove(self.traffic_recording)
        self.flows = []             # 由于无法区分是request还是response，所以用列表[flow, "request"/"response"]存储
        self.url_flow_map = {}      # 去除参数的URL与对应的flow集合映射

        # 记录结果信息
        self.res_file = f"./res/res_{urllib.parse.quote(url, safe='')}.txt"

        ### Polling related ###
        self.url_counts = {}        # 记录每个url出现的次数，便于找轮询请求
        self.polling_url = ""
        self.polling_flow = None    # 轮询请求flow
        self.new_polling_flow_replay = None    # 重放的修改为新的qrid的轮询请求flow
        self.polling_flow_replay = None        # 重放的原轮询请求flow
        self.login_success_response = None     # 登录成功的轮询请求的response

        ### QRcode related ###
        self.qrcode_params = {}
        self.qrid = {}                         # qrid可能有多个字段，用字典存储键值
        self.newqrid = {}                      # 重新调用创建二维码的请求，获取新的qrid
        self.qrid_name_in_creation = ""        # 单独记录创建二维码请求中的qrid字段名（可能与轮询请求中字段名不一致）
        self.qrid_name_in_roll = ""
        self.request_cookie_url = ""
        
        ### Create QRcode related ###
        self.create_qrcode_flow_info = None   # 创建二维码的流，[flow, "request"/"response"]表示qrid最早出现在request/response中
        self.create_qrcode_flow_replay = None   # 重新调用创建二维码的请求，获取新的qrid

        self.num = 0
        self.screenshot_path = "screenshot.png"
        if os.path.exists(self.screenshot_path):
            os.remove(self.screenshot_path)
        if os.path.exists("done_flag.txt"):
            os.remove("done_flag.txt")
        
        # 开启一个线程，定时检查是否完成扫码登录，开始缺陷检测
        self.lock = threading.Lock()
        threading.Thread(target=self.run_check_done).start()

        ### app端相关 ###
        self.app_flows = []
        self.login_request = []    # 扫码登录发送的请求flow

    def load(self, loader):
        loader.add_option(name = "url", typespec = str, default = "", help = "The URL to analyze")

  
    # 是否已完成登录（通过selenium脚本生成的标志文件判断）
    def is_login_done(self):
        if os.path.exists('done_flag.txt'):
            return True
        return False
        
        
    # 开一个线程定时检查是否完成扫码登录，开始缺陷检测
    def run_check_done(self):
        # cnt = 1
        wf = open(self.res_file, 'w')
        write_head = False
        while True:
            if self.is_login_done():
                self.logger.info("************* is_login_done: True")
                self.prepare()
                # ready = self.is_ready_for_detection()     # 改成针对每个flaw进行特定的检查，不统一判断
                # self.logger.info("************* Ready for detection result: " + str(ready))
                # if ready:
                if not write_head:
                    wf.write("qrid: \n" + str(self.qrid) + "\n\n")
                    wf.write("F1\t\tF2\t\tF3\t\tF4\t\tF5\t\tF6\t\tF7\n")
                    write_head = True
                res = self.detect()
                for i in res:
                    wf.write(str(i) + "\t")
                wf.write("\n")
                self.logger.info("^^^^^^^^^^^^ Detection result: " + str(res))
                print(f"^^^^^^^^^^^^ Detection result: " + str(res))
                # else:
                #     self.logger.info("************* Not ready for detection!!!")
                #     print("************* Not ready for detection!!!")
                break
            time.sleep(3)
    

    # 分析流量，识别基本信息（如qrid，轮询请求，创建二维码请求等），为检测做准备
    def prepare(self):
        self.logger.info("************* Start prepare...")

        # 1. 根据截图解析二维码
        if self.qrcode_params == {} and os.path.exists(self.screenshot_path):
            print("######### run_decode_qrcode:decode #########")
            self.qrcode_params = selenium_qrcode.decode_qrcode(self.screenshot_path)
            self.logger.info(f"************* Decoded qrcode_params: {self.qrcode_params}")
            print("######### run_decode_qrcode:decode done #########")

        # 2. 对比二维码内容与请求内容，找轮询请求及qrid（根据url频次排序找，以及判断多个二维码字段情况）
        if self.qrid == {} or self.polling_flow is None:
            # 先过滤二维码中的字段 (值为英文单词组成的字段 / 值长度为1)
            self.qrcode_params = self.flatten_nested_dict(self.qrcode_params)
            keys_to_delete = []
            for key, value in self.qrcode_params.items():
                if self.is_english_phrase(str(value)) or len(str(value)) <= 2 or str(value) == 'zh-CN':
                    keys_to_delete.append(key)
            for key in keys_to_delete:
                del self.qrcode_params[key]
            print("***** filtered self.qrcode_params: ", self.qrcode_params)
            self.logger.info(f"************* Filtered qrcode_params: {self.qrcode_params}")

            # 根据请求url频次进行排序，从出现次数最多的URL开始与二维码中的字段进行对比
                # 去除url中的参数
            filtered_url_counts = {}
            for url, cnt in self.url_counts.items():
                filtered_url = self.remove_params_from_url(url)
                filtered_url_counts[filtered_url] = filtered_url_counts.get(filtered_url, 0) + self.url_counts[url]
            sorted_url_counts = sorted(filtered_url_counts.items(), key=lambda x: x[1], reverse=True)
            print("sorted_url_counts: ", sorted_url_counts)
            self.logger.info(f"************* Sorted filtered_url_counts: {sorted_url_counts}")

            self.url_flow_map = self.build_url_flow_map()       

            # 从出现次数最多的URL开始与二维码中的字段进行对比
            for url, count in sorted_url_counts:
                if self.polling_flow is not None:
                    break 
                url_flows = self.url_flow_map[url]
                for flow in url_flows:
                    if flow.request.method == "OPTIONS":        # 过滤option请求，不作为轮询请求
                        continue
                    # flow = url_flows[0]
                    # 当与轮询请求中匹配上多个二维码中的字段时，判断
                        # 若字段名包含关键词(id,qr,token,code,login,no)，则为qrid
                        # 若无关键词，则值长度最长为qrid
                    match_field_cnt = 0
                    for key, value in self.qrcode_params.items():
                        qrid_name = str(self.search(flow, "request", str(value)))
                        if qrid_name != "":
                            print("matched_qrid_name: ", qrid_name)
                            match_field_cnt += 1
                            self.qrid[qrid_name] = value
                    if match_field_cnt > 1:
                        print("************* Multiple qrid matched: ", self.qrid)
                        self.logger.info(f"************* Multiple qrid matched: {self.qrid}")
                        max_len = 0
                        max_len_key = ""
                        for key0, value in self.qrid.items():
                            key = key0.lower()
                            if ("id" in key or "qr" in key or "token" in key or "code" in key or "login" in key or "no" in key):
                                max_len_key = key0
                                break
                            elif len(value) > max_len:
                                max_len = len(value)
                                max_len_key = key0
                        self.qrid = {max_len_key: self.qrid[max_len_key]}
                        self.qrid_name_in_roll = max_len_key
                        
                    if match_field_cnt > 0:
                        # 若匹配到的URL中同时存在POST请求和GET请求，则以GET请求作为轮询请求
                        if flow.request.method == "POST":
                            for tmpflow in url_flows:
                                if tmpflow.request.method == "GET":
                                    flow = tmpflow
                                    break
                        self.polling_flow = flow
                        self.polling_url = flow.request.url
                        self.logger.info(f"************* Determine qrid: {self.qrid}")
                        print(f"************* Determine qrid: {self.qrid}")
                        self.qrid_name_in_roll = str(list(self.qrid.keys())[0])
                        # break
                        # 检查是否识别到的轮询请求中所有请求中都包含qrid，排除无关干扰请求
                        threshold = 0       # 放宽条件，如果仅一个请求未包含qrid，仍认为是轮询请求
                        for flow in url_flows:
                            if flow.request.method == "OPTIONS":        # 过滤option请求，无内容
                                continue
                            if self.search(flow, "request", list(self.qrid.values())[0]) == "":
                                threshold += 1
                                if threshold > 2:
                                    print(f"------- clear polling: {self.polling_url}")
                                    self.logger.info(f"------- clear polling: {self.polling_url}")
                                    self.polling_flow = None
                                    self.polling_url = ""
                                    self.qrid = {}
                                    break
                    if self.polling_flow is not None:
                        self.logger.info(f"************* Determine polling flow: {str(self.polling_flow)}")
                        print(f"************* Determine polling flow: {str(self.polling_flow)}")
                        break
                if self.polling_flow is not None:
                    break
            if self.polling_flow is None:
                print("[ERROR] cannot match qrcode_params with polling request")


        # 3. 根据qrid找创建二维码的请求（这部分耗时较久，会影响连接，不能放在request处理函数中，放在这）
        if self.qrid != {} and self.create_qrcode_flow_info is None:
            self.logger.info("************* Searching create qrcode flow...(qrid != {})")
            self.logger.info("========== len(flows):" + str(len(self.flows)))
            print("************* Searching create qrcode flow...")
            for flow_info in self.flows:
                flow = flow_info[0]
                flow_type = flow_info[1]
                if flow.request.method == "OPTIONS":        # 过滤option请求，无内容
                    continue
                if flow_type == "request" and self.remove_params_from_url(flow.request.url) == self.remove_params_from_url(self.polling_url) and flow.request.method == self.polling_flow.request.method:
                    continue
                field = self.search(flow, flow_type, list(self.qrid.values())[0])
                if field != "":
                    self.qrid_name_in_creation = field
                    self.logger.info(f"************* Found qrid_name_in_creation: {self.qrid_name_in_creation}")
                    self.create_qrcode_flow_info = flow_info
                    self.logger.info(f"$$$$$$$$$$$ Found create qrcode flow: {str(self.create_qrcode_flow_info)}")
                    print(f"$$$$$$$$$$$ Found create qrcode flow: {str(self.create_qrcode_flow_info)}")
                    break
            # 从创建二维码的请求中提取cookie(如果有的话), 并定位请求cookie的request
            # cookie_str = self.create_qrcode_flow_info.request.headers.get('Cookie', '')
            # cookie = SimpleCookie()
            # cookie.load(cookie_str)
            # cookie_dict = {}
            # for key, morsel in cookie.items():
            #     cookie_dict[key] = morsel.value
            cookie_dict = {}
            if self.create_qrcode_flow_info is not None:
                # print("@@@@@@@@@@@@@@@@@@@@@@length of create_qrcode_flow_info", len(self.create_qrcode_flow_info))
                # print("@@@@@@@@@@@@@@@@@@@@@@create_qrcode_flow_info0:", str(self.create_qrcode_flow_info[0]))
                # print("@@@@@@@@@@@@@@@@@@@@@@create_qrcode_flow_info1:", str(self.create_qrcode_flow_info[1]))
                flow = self.create_qrcode_flow_info[0]
                flow_type = self.create_qrcode_flow_info[1]
                cookie_dict = self.parse_cookie(flow, "request")

                # for flow_info in self.create_qrcode_flow_info:
                #     flow = flow_info[0]
                #     flow_type = flow_info[1]
                #     if flow_type == "response":
                #         continue
                #     cookie_dict = self.parse_cookie(flow, flow_type)
                #     break
                print("@@@@@@@@@@@@@@@cookie_dict in create_qrcode_request:", str(cookie_dict))
                if cookie_dict != {}:
                    for flow_info in self.flows:
                        flow = flow_info[0]
                        flow_type = flow_info[1]
                        if flow_type == "request":
                            continue
                        # print("@@@@@@@@@@@@@@@@flow.response.header:", flow.response.headers)
                        has_found = False
                        for k, v in cookie_dict.items():
                            if k not in str(flow.response.headers) or v not in str(flow.response.headers):
                                break
                            self.request_cookie_url = flow.request.url
                            print("@@@@@@@@@@@@@@@create cookie url:", self.request_cookie_url)
                            has_found = True
                            break
                        if has_found == True:
                            break
        
        # 4. app端分析，找到登录请求
        if self.login_request == [] and self.qrid != {}:
            qrid_value = list(self.qrid.values())[0]
            for flow_info in self.app_flows:
                flow = flow_info[0]
                flow_type = flow_info[1]
                if flow_type == "request":
                    if self.search(flow, flow_type, qrid_value) != "":
                        self.login_request.append(flow_info)
                        self.logger.info(f"$$$$$$$$$$$[app] Found login request: {str(self.login_request)}")
                        break

    # 判断是否为英文单词组成（用来过滤qrid）
    def is_english_phrase(self, phrase):
        words_set = set(words.words())
        split_phrase = wordninja.split(phrase)
        return all(word.lower() in words_set for word in split_phrase)

    # 将嵌套字典转换为一维字典，只保留最内层直接的键
    def flatten_nested_dict(self, nested_dict):
        """
        将嵌套字典展平，保留最内层直接的键
        """
        flattened_dict = {}
        for key, value in nested_dict.items():
            if isinstance(value, dict):
                flattened_dict.update(self.flatten_nested_dict(value))
            else:
                flattened_dict[key] = value
        return flattened_dict

    # 去除URL中的参数
    def remove_params_from_url(self, url):
        parsed_url = urlparse(url)
        return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
    
    # 构建去除参数后的URL与flow集合的映射
    def build_url_flow_map(self):
        url_flow_map = {}
        for flow_info in self.flows:
            flow = flow_info[0]
            flow_type = flow_info[1]
            if flow_type == "request":
                url = self.remove_params_from_url(flow.request.url)
                url_flow_map[url] = url_flow_map.get(url, []) + [flow]
        return url_flow_map

    # 写入日志
    def write_log_request(self, flow):
        if not self.debuggable:
            return
        # 写入request
        with open(self.traffic_recording, "a") as f:
            # f.write(f"\n[Request]\n{flow.request.pretty_url}\n")      # 进行处理，更适合显示给用户，而非用于网络请求
            f.write(f"\n[Request{self.num}]{flow.request.url}\n")
            f.write(f"Method: {flow.request.method}\n")
            self.logger.debug(f"\n[Request{self.num}]\n{flow.request.url}")
            self.logger.debug(f"Method: {flow.request.method}")

            # print("############", dict(flow.request.headers))
            headers = dict(flow.request.headers)
            for key in headers:
                f.write(f"{key}: {headers[key]}\n")
                self.logger.debug(f"{key}: {headers[key]}")
            # f.write(f"{dict(flow.request.headers)}\n\n")
                
            if flow.request.content:
                decoded_content = self.decode_content(flow.request.content)
                f.write(f"Body:$$${decoded_content}$$$")
                self.logger.debug(f"Body:$$${decoded_content}$$$\n")
            else:
                # print("******** No request content ********")
                pass
            f.write("\n\n\n\n")
    
    def write_log_response(self, flow):
        if not self.debuggable:
            return
        # 写入response
        with open(self.traffic_recording, "a", encoding="utf-8") as f:
            f.write(f"\n[Response]\n{flow.request.url}\n")
            self.logger.debug(f"\n[Response]{flow.request.url}")

            headers = dict(flow.response.headers)
            for key in headers:
                f.write(f"{key}: {headers[key]}\n")
                self.logger.debug(f"{key}: {headers[key]}")
            # f.write(f"{flow.response.headers}\n\n")

            if flow.response.content:
                decoded_content = self.decode_content(flow.response.content)
                f.write(f"Body:$$${decoded_content}$$$")
                self.logger.debug(f"Body:$$${decoded_content}$$$\n")
            else:
                # print("******** No response content ********")
                pass
            f.write("\n\n\n\n")

    # 写入日志，同时在终端打印
    def print_log(self, content):
        print(content)
        self.logger.info(content)

    # 开新线程解析二维码，不阻塞后续程序（deprecated）
    def run_decode_qrcode(self):
        def decode():
            start_time = time.time()
            self.lock.acquire()
            try:
                print("######### run_decode_qrcode:decode #########")
                self.qrcode_params = selenium_qrcode.decode_qrcode(self.screenshot_path)
            finally:
                self.lock.release()
            end_time = time.time()
            self.logger.info("&&&&&& decode time:" + str(end_time - start_time))
        # 开新线程解析二维码，不阻塞后续程序
        t = threading.Thread(target=decode)
        t.start()
        


    def request(self, flow):
        # if self.domain not in flow.request.url:
        #     return
        if self.is_login_done():
            self.write_log_request(flow)
            return
        # app端登录请求
        if "Android" in flow.request.headers.get('User-Agent', ''):
            self.app_flows.append([flow, "request"])
            self.write_log_request(flow)
            return
        # print("=========request=========")
        self.num = self.num + 1

        # 开新线程解析二维码，不阻塞后续程序
        # self.lock.acquire()
        # qrcode_params = self.qrcode_params
        # screenshot_exists = os.path.exists(self.screenshot_path)
        # self.lock.release()
        # if qrcode_params == {} and screenshot_exists:
        #     self.run_decode_qrcode()

        self.write_log_request(flow)

        self.flows.append([flow, "request"])
        url = flow.request.url
        self.url_counts[url] = self.url_counts.get(url, 0) + 1
        # filtered_url = self.remove_params_from_url(url)
        # self.url_counts[filtered_url] = self.url_counts.get(filtered_url, 0) + 1

        # if self.polling_flow is None and str(url) == str(self.polling_url):
        #     self.polling_flow = flow

        # self.analysis()
        
        # if self.is_ready_for_detection():
        #     self.detect()
    
    def response(self, flow):
        # if self.domain not in flow.request.url:
        #     return
        if self.is_login_done():
            self.write_log_request(flow)
            return
        # app端登录请求
        if "Android" in flow.request.headers.get('User-Agent', ''):
            self.app_flows.append([flow, "response"])
            self.write_log_response(flow)
            return
        # print("=========response=========")

        self.write_log_response(flow)
        self.flows.append([flow, "response"])

        # 获取重放的创建二维码的请求的响应，解析获取新的qrid
        if flow.request == self.create_qrcode_flow_replay:
            self.logger.info("[REPLAY]Get response of replayed create qrcode request" + str(flow.response))

        # 获取重放的轮询请求的响应
        if flow.request == self.new_polling_flow_replay:
            self.logger.info("[REPLAY]Get response of replayed polling request" + str(flow.response))
        
        # self.analysis()

        # if self.is_ready_for_detection():
        #     self.detect()


    # 找出出现次数最多的url
    def most_common_url(self):    
        if self.url_counts:
            return max(self.url_counts, key=self.url_counts.get)

    # 识别轮询请求以及qrid，以及创建二维码的请求（deprecated）
    def analysis(self):
        st = time.time()

        print("\n\n\n\n")
        # print("Total number of flows: ", len(self.flows))
        # self.logger.info("************* Polling url: " + str(self.most_common_url()))
        self.logger.info("************* Most common url: " + str(self.most_common_url()))

        # 根据二维码中的参数，对比轮询请求参数，找qrid
        if self.polling_flow is not None:
            self.lock.acquire()
            try:
                for key, value in self.qrcode_params.items():
                    print("value: ", value)
                    qrid_name = self.search(self.polling_flow, "request", value)
                    if qrid_name != "":
                    # if self.search(self.polling_flow, "request", value) != "":
                        self.qrid[qrid_name] = value      # qrid字段名在轮询请求中和二维码中可能不一样，用轮询请求中的
                self.logger.info(f"************* Found qrid: {self.qrid}")
            finally:
                self.lock.release()
        
        et = time.time()
        self.logger.info("&&&&&& analysis time:" + str(et - st))
        if et - st > 1:
            self.logger.info("&&&&&&[timeout] analysis time:" + str(et - st))


    # 搜索关键词是否在该请求/响应中
    # 如果找到，则返回请求中的参数名/在body中"inBody"
    def search(self, flow, flow_type, keyword):
        # try:
        if flow_type == "request":
            # 比较请求url参数
            for k, v in flow.request.query.items():
                if keyword == str(v):
                    return k
            # print("////////////////////", str(flow.request.url))
            if keyword in str(flow.request.url):
                return "noName"
            # 搜索content
            if flow.request.content:
                content_dict = self.parse_content(flow.request)
                # print("@@@@@@@@@@@@@@@parse_content_dict:", str(content_dict))
                if isinstance(content_dict, dict):
                    for k, v in content_dict.items():
                        if keyword in str(v):
                            return k
                        elif keyword in str(unquote(str(v))):
                            return k
            # 搜索headers
            for k, v in flow.request.headers.items():
                if k.lower() in ['cookie', 'set-cookie']:
                    continue
                if keyword in str(v):
                    return k
            # 轮询请求中找qrid时，可能出现在cookie中，进一步解析cookie中的字段名键值对
            cookie_dict = self.parse_cookie(flow, flow_type)
            for key, value in cookie_dict.items():
                if str(value) == str(keyword):
                    return key
    
        if flow_type == "response":
            # 搜索content
            if flow.response.content:
                content_dict = self.parse_content(flow.response)
                # 先做精确匹配，如果精确匹配匹配不到，再用局部匹配
                if isinstance(content_dict, dict):
                    flatten_dict = self.flatten_nested_dict(content_dict)
                    for k, v in flatten_dict.items():
                        if keyword == str(v):
                            return k
                        # 可能URL编码了
                        elif keyword == str(unquote(str(v))):
                            return k
                    for k, v in flatten_dict.items():
                        if keyword in str(v):
                            return k
                        # 可能URL编码了
                        elif keyword in str(unquote(str(v))):
                            return k
            # 搜索headers
            for k, v in flow.response.headers.items():
                if keyword == str(v):
                    print("##############search result in headers(actually):", k)
                    return k
            for k, v in flow.response.headers.items():
                if keyword in str(v):
                    cookie_dict = self.parse_cookie(flow, "response")
                    for key, value in cookie_dict.items():
                        if keyword == str(value):
                            print("##############search result in headers(in set-cookie):", key)
                            return key
                    # print("##############search result in headers(not in set-cookie):", key)
                    return k
        # except Exception as e:
        #     self.logger.error("Error in search: " + str(e))
        return ""


    # 解析cookie中的字段键值对
    def parse_cookie(self, flow, flow_type):
        if flow_type == "request":
            cookie_str = flow.request.headers.get('Cookie', '')
            if cookie_str == "":
                cookie_str = flow.request.headers.get('cookie', '')
        if flow_type == "response":
            cookie_str = flow.response.headers.get('Set-Cookie', '')
        cookie = SimpleCookie()
        cookie.load(cookie_str)
        cookie_dict = {}
        for key, morsel in cookie.items():
            cookie_dict[key] = morsel.value
        return cookie_dict


    # 解码content
    def decode_content(self, content):
        if content is None:
            return ''
        encoding = chardet.detect(content)['encoding']
        if encoding is not None:
            try:
                return content.decode(encoding)
            except UnicodeDecodeError:
                pass
        encodings = ['utf-8', 'gbk', 'latin1', 'ascii']  # 添加你想尝试的其他编码
        for encoding in encodings:
            try:
                return content.decode(encoding)
            except UnicodeDecodeError:
                pass
        raise ValueError('Unable to decode content' + str(content))

    # 解析请求/响应体参数内容
    def parse_content(self, flow):     # 这里的flow是request/response，不是完整的flow
        
        # 获取Content-Type头部，指明了请求/响应体的格式
        content_type = flow.headers.get('Content-Type', '')

        # 根据Content-Type头部来解析内容
        content = self.decode_content(flow.content)
        if not content:
            return dict()
        if 'application/x-www-form-urlencoded' in content_type:
            return dict(parse_qsl(content))
        elif 'application/json' in content_type and "({" not in content:        # smartedu.cn轮询请求response content-type为json，但是内容为js代码
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                return {"content": content}
            # return json.loads(content)
        elif 'javascript' in content_type or "({" in content:
            if "({" in str(content):  
                # 飞客、苏宁易购、微博，格式为loginRes({"success":0,"msg":"","data":[],"uid":0})，js里面是一个字典  
                content = self.remove_parenthesis(str(content))  
                try:
                    return json.loads(content)      # 淘宝找创建二维码的请求时存在response为js代码，解析失败
                except json.JSONDecodeError:
                    return {"content": content}
        else:
            # 对于其他格式，先尝试json解析，不行就直接返回content（天翼云盘中type写的html，content是个json
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                return {"content": content}
            # return {"content":content}
    
    # 去除content中的小括号  
    def remove_parenthesis(self, content):  
        result = re.search(r"\((.*?)\)", content, re.DOTALL)  
        if result:  
            return result.group(1)  
        else:
            return content



    ########################## Flaw Detection ##########################

    # 判断检测需要的信息是否已经收集齐全
    def is_ready_for_detection(self):

        self.logger.info("************* Ready for detection? ")# + str(self.polling_flow) + str(self.qrid) + str(self.create_qrcode_flow_info))
        if not self.is_login_done():
            return False
        self.logger.info("************* login done")

        self.logger.info(f"************* is_ready_for_detection detail: \nself.polling_flow is not None:{self.polling_flow is not None},self.qrid != none:{self.qrid != {}}, self.create_qrcode_flow_info is not None:{self.create_qrcode_flow_info is not None}")
        res = True
        if self.polling_flow is None:
            print("*************[ERROR] cannot find polling_flow!!")
            res = False
        if self.qrid == {}:
            print("*************[ERROR] cannot find qrid!!")
            res = False
        if self.create_qrcode_flow_info is None:
            print("*************[ERROR] cannot find create_qrcode_flow!!")
            res = False
        return res

    # 检测flaw
    def detect(self):
        self.logger.info("!!!!!!!!!!! Start detecting flaw...")

        f1 = self.F1_Unbound_session_id()
        self.print_log("!!!!!!!!!!! Detect flaw F1 unbound sessionid: " + str(f1))

        f2 = self.F2_Reusable_qrcode()
        self.print_log("!!!!!!!!!!! Detect flaw F2 resuable qrcode: " + str(f2))

        f3 = self.F3_Predictable_qr_id()
        self.print_log("!!!!!!!!!!! Detect flaw F3 predictable qrid: " + str(f3))
        
        f4 = self.F4_Controllable_qr_id()
        self.print_log("!!!!!!!!!!! Detect flaw F4 controllable qrid: " + str(f4))

        f5 = self.F5_Invalid_token_Validation()
        self.print_log("!!!!!!!!!!! Detect flaw F5 invalid token validation: " + str(f5))
        
        f6 = self.F6_Insecure_token_Usage()
        self.print_log("!!!!!!!!!!! Detect flaw F6 insecure token usage: " + str(f6))
        
        f7_data = self.F7_Sensitive_Data_Leakage()
        self.print_log("!!!!!!!!!!! Detect flaw F7 sensitive data leakage: " + str(f7_data))
        f7 = False
        if f7_data:
            f7 = True
        
        return [f1, f2, f3, f4, f5, f6, f7]


    # F1. Unbound session_id
    def F1_Unbound_session_id(self):
        print("======= Start detecting flaw F1: Unbound session_id =======")
        self.logger.info("************* Start detecting flaw F1: Unbound session_id")

        if not self.is_ready_for_detection():
            self.print_log("************* [F1] Not Ready: Unbound sessionid")
            return False

        ### 重新调用创建二维码的请求，获取新的qrid（新请求，新session）
        if self.create_qrcode_flow_info is not None and self.create_qrcode_flow_replay is None:     # 避免重复循环生成
            flow = self.create_qrcode_flow_info[0]
            flow_type = self.create_qrcode_flow_info[1]

            if flow_type == "request":
                # TODO：处理本地生成二维码的情况，需要编一个qrid替换请求中的qrid作为新的qrid
                self.logger.info("************* Flaw F1: Unbound session_id, TODO create qrcode locally")
                # 尝试将其中一个数字替换为另一个数字，得到一个新的qrid后发送给服务端
                oldvalue = list(self.qrid.values())[0]
                for i in range(10):
                    if str(i) in oldvalue:
                        newvalue = oldvalue.replace(str(i), str((i+1)%10))
                        qrid_name = self.qrid_name_in_creation
                        self.newqrid[qrid_name] = newvalue
                        break
                # 若qrid中无数字，替换大写或小写字母
                if self.newqrid == {}:
                    for c in string.ascii_letters:
                        if c in oldvalue:
                            if c == 'z':
                                newvalue = oldvalue.replace(c, 'a')
                            else:
                                newvalue = oldvalue.replace(c, chr(ord(c)+1))
                            qrid_name = self.qrid_name_in_creation
                            self.newqrid[qrid_name] = newvalue
                            break
                print("************* create newqrid: ", self.newqrid)
                self.logger.info("************* create newqrid: " + str(self.newqrid))
                # return False
            
            # 服务端生成二维码情况

                ## 第一种方法：直接把cookie置空
            # newflow = flow.copy()
            # newflow.request.cookies = {}
            # self.create_qrcode_flow_replay = newflow
            # print("$$$$$$$ send newflow1")
            # ctx.master.commands.call("replay.client", [newflow])

                ## 第二种方法：采用访问网站时新获取的cookie来创建二维码
            newflow2 = flow.copy()
            # 修改新创建二维码请求的cookie
            # response = requests.get(self.url)
            try:
                if self.request_cookie_url != "":
                    response =  requests.get(self.request_cookie_url, timeout=10)
                else:
                    response = requests.get(self.url, timeout=10)
            except Timeout:
                print("!!!!!!!!! Request timeout!")
                response = None
            print("@@@@@@@@@@@@@@@@@@@@@new cookie resp:", response)

            # response = requests.get(flow.request.url)
            if response is None:
                cookie_header = ""
            else:
                resp_cookie = response.cookies
                print("######## resp_cookie:",resp_cookie)
                new_cookie = {c.name: c.value for c in resp_cookie}
                cookie_header = "; ".join([f"{name}={value}" for name, value in new_cookie.items()])
                print("######## new_cookie:",new_cookie)
                print("######## newflow2.request.cookies:",newflow2.request.cookies)
            # print("######## newflow2.request.headers['cookie']:",newflow2.request.headers['Cookie'])
            # if cookie_header != "":
            #     newflow2.request.headers["Cookie"] = cookie_header
            newflow2.request.headers["Cookie"] = cookie_header
            print("######## newflow2.request.headers['cookie'] (changed):",newflow2.request.headers['Cookie'])
            print("$$$$$$$ send newflow2")
            # 处理本地生成qrid的情况：将请求中的旧的qrid替换为新的qrid
            if self.newqrid != {}:
                new_value = list(self.newqrid.values())[0]
                old_value = list(self.qrid.values())[0]
                qrid_name = list(self.newqrid.keys())[0]
                newflow2 = self.replace_field(newflow2, old_value, new_value, qrid_name)
            self.create_qrcode_flow_replay = newflow2
            ctx.master.commands.call("replay.client", [newflow2])

            # # 改轮询请求中的cookie，保持创建二维码请求的cookie与原来一致
            # newflow3 = flow.copy()
            # self.create_qrcode_flow_replay = newflow3
            # print("$$$$$$$ send newflow3")
            # ctx.master.commands.call("replay.client", [newflow3])
        
        ### 获取到新的qrid后，替换轮询请求中的qrid，重放轮询请求
        # 等待重放的创建二维码的请求的响应
        # while self.create_qrcode_flow_replay.response is None:
        while self.newqrid == {} and self.create_qrcode_flow_replay.response is None:
            print("************* Waiting for replayed create qrcode request response...")
            time.sleep(0.5)
        # 获取重放的创建二维码的请求的响应，解析获取新的qrid
        if self.newqrid == {} and self.create_qrcode_flow_replay.response is not None:
            self.logger.info("[REPLAY]Get response of replayed create qrcode request" + str(self.create_qrcode_flow_replay.response))
            content_dict = self.parse_content(self.create_qrcode_flow_replay.response)
            self.logger.info("[REPLAY]content_dict: " + str(content_dict))
            self.logger.info("[DETECT]qrid: " + str(self.qrid))
            print("[DETECT]qrid: " + str(self.qrid)) 
            # (qrid_name, old_value) = self.qrid.items()
            # qrid_name = list(self.qrid.keys())[0]
            qrid_name = self.qrid_name_in_creation      # 用单独记录的创建二维码请求中的qrid字段名
            old_value = list(self.qrid.values())[0]
            content_dict = self.flatten_nested_dict(content_dict)
            print("#############qrid name/ in creation:", qrid_name)
            print("#############qrid name in roll:", self.qrid_name_in_roll)
            print("#############qrid old_value:", old_value)
            print("#############create_qrcode_flow_replay response:", str(content_dict))
            for key, value in content_dict.items():
                if isinstance(value, dict):
                    for k1, v1 in value.items():
                        if k1 == qrid_name and v1 != old_value:
                            self.newqrid[k1] = v1
                elif key == qrid_name:
                    self.newqrid[key] = value

            # qrid可能出现在cookie中，解析cookie获取新的qrid
            if self.newqrid == {}:
                cookie_dict = self.parse_cookie(self.create_qrcode_flow_replay, "response")
                for key, value in cookie_dict.items():
                        if key == qrid_name and value != old_value:
                            self.newqrid[key] = value


            self.logger.info("*************[REPLAY] Found new qrid: " + str(self.newqrid))
            print("*************[REPLAY] Found new qrid: " + str(self.newqrid))


        # 获取到新的qrid后，替换轮询请求中的qrid，重放轮询请求
        if self.newqrid != {} and self.new_polling_flow_replay is None:     
            # (qrid_name, new_value) = self.newqrid.items()
            qrid_name = list(self.newqrid.keys())[0]
            new_value = list(self.newqrid.values())[0]
            old_value = list(self.qrid.values())[0]
            newpollingflow = self.polling_flow.copy()

            newpollingflow = self.replace_field(newpollingflow, old_value, new_value, qrid_name)

            # 使用replay模块来重新发送请求
            print("[REPLAY] send replayed polling request")
            ctx.master.commands.call("replay.client", [newpollingflow])

            # 保存重播的流对象，以便在response方法中获取响应
            self.new_polling_flow_replay = newpollingflow

        # 等待重放的轮询请求的响应
        while self.new_polling_flow_replay is not None and self.new_polling_flow_replay.response is None:
            print("************* Waiting for replayed polling request response...")
            time.sleep(0.5)
        ### 获取到重放的轮询请求的response后，判断response是否合法
        if self.new_polling_flow_replay is not None and self.new_polling_flow_replay.response is not None:   # 收到response后
            # 找到第一个轮询请求的response（合法的轮询请求）（非空response）
            legal_response = None
            for flow_info in self.flows:
                flow = flow_info[0]
                flow_type = flow_info[1]
                if flow_type == "response":
                    if flow.request.url == self.polling_url and flow.request.method == self.polling_flow.request.method:
                        legal_response = flow.response
                        if not flow.response.content:
                            continue
                        # legal_response = self.decode_content(flow.response.content)
                        self.logger.info("************* Found legal response: " + str(self.decode_content(flow.response.content)))
                        print("############## Found legal response: ", str(self.decode_content(flow.response.content)))
                        break
            replay_response = self.new_polling_flow_replay.response
            self.logger.info("************* Replayed new polling response: " + str(self.decode_content(replay_response.content)))
            print("############## Replayed new polling response: ", str(self.decode_content(replay_response.content)))

            # 对成功响应及重放的响应进行处理，去除本身就不一致的字段，如traceId、时间戳
            parsed_legal_response = self.parse_content(legal_response)
            parsed_replay_response = self.parse_content(replay_response)
            self.print_log("************* F1: parsed_legal_response: " + str(parsed_legal_response))
            self.print_log("************* F1: parsed_replay_response: " + str(parsed_replay_response))
            legal_response_content = self.filter_response_content(parsed_legal_response)
            replay_response_content = self.filter_response_content(parsed_replay_response)
            
            # response.content中可能包含qrid，进行去除
            old_qrid_value = list(self.qrid.values())[0]
            new_qrid_value = list(self.newqrid.values())[0]
            filter_legal_response = json.dumps(legal_response_content).replace(old_qrid_value, "")
            filter_replay_response_content = json.dumps(replay_response_content).replace(new_qrid_value, "")
 
            self.logger.info("************* F1: filter_legal_response: " + str(filter_legal_response))
            self.logger.info("************* F1: filter_replay_response_content: " + str(filter_replay_response_content))
            print("############## F1: filter_legal_response : ", str(filter_legal_response))
            print("############## F1: filter_replay_response_content: ", str(filter_replay_response_content))
            if json.loads(filter_legal_response) == json.loads(filter_replay_response_content):
                self.logger.info("************* Flaw F1: Unbound session_id exists!")
                return True
        return False


    # F2. Reusable qrcode
    def F2_Reusable_qrcode(self):
        print("======= Start detecting flaw F2: Reusable qrcode =======")
        self.logger.info("************* Start detecting flaw F2: Reusable qrcode")
        if self.qrid == {} or self.polling_flow is None:
            self.print_log("************* [F2] Not Ready: Reusable qrcode, qrid is None, polling_flow is None")
            return False
        # 登录成功后，重放原轮询请求
        if self.polling_flow_replay is None:
            copy_polling_flow = self.polling_flow.copy()
            print("[REPLAY] send replayed copy polling request")
            ctx.master.commands.call("replay.client", [copy_polling_flow])
            self.polling_flow_replay = copy_polling_flow

        while self.polling_flow_replay is not None and self.polling_flow_replay.response is None:
            print("************* Waiting for replayed copy polling request response...")
            time.sleep(0.5)

        # 获取到重放的轮询请求的response后，判断response是否登录成功
        if self.polling_flow_replay is not None and self.polling_flow_replay.response is not None:
            # 找到最后一个轮询请求的response（登录成功的轮询请求），用于对照判断
            success_response = None
            for flow_info in self.flows[::-1]:
                flow = flow_info[0]
                flow_type = flow_info[1]
                if flow_type == "response":
                    if self.remove_params_from_url(flow.request.url) == self.remove_params_from_url(self.polling_url):
                        success_response = flow.response
                        self.login_success_response = success_response
                        self.logger.info("************* F2: Found success response: " + str(self.decode_content(flow.response.content)))
                        break
            replay_response = self.polling_flow_replay.response
            self.logger.info("************* F2: Replayed polling response: " + str(self.decode_content(replay_response.content)))

            parsed_success_response = self.parse_content(success_response)
            parsed_replay_response = self.parse_content(replay_response)
            self.logger.info("************* F2: parsed_success_response: " + str(parsed_success_response))
            self.logger.info("************* F2: parsed_replay_response: " + str(parsed_replay_response))
            # 对成功响应及重放的响应进行处理，去除本身就不一致的字段，如traceId
            success_response_content = self.filter_response_content(parsed_success_response)
            replay_response_content = self.filter_response_content(parsed_replay_response)
            
            filter_success_response = json.dumps(success_response_content)
            filter_replay_response_content = json.dumps(replay_response_content)

            self.logger.info("************* F2: filter_success_response: " + str(filter_success_response))
            self.logger.info("************* F2: filter_replay_response_content: " + str(filter_replay_response_content))

            if json.loads(filter_success_response) == json.loads(filter_replay_response_content): # or "success" in str(filter_replay_response_content).lower():
                self.logger.info("************* Flaw F2: Reusable qrcode exists!")
                return True
        return False


    # F3. Predictable qr_id
    def F3_Predictable_qr_id(self):
        if self.qrid != {}:
            for key, value in self.qrid.items():
                if len(str(value)) <= 6:
                    self.logger.info("************* Flaw F3: Predictable qr_id, " + str(value))
                    return True
        else:
            self.print_log("************* [F3] Not Ready: Predictable qr_id, qrid is None")
        return False
    

    # F4. Controllable qr_id
    def F4_Controllable_qr_id(self):
        if self.create_qrcode_flow_info is not None:
            if self.create_qrcode_flow_info[1] == "request":
                self.logger.info("************* Flaw F4: Controllable qr_id, " + str(self.create_qrcode_flow_info))
                return True
        else:
            self.print_log("************* [F4] Not Ready: Controllable qr_id, create_qrcode_flow_info is None")
        return False
    

    # F5. Invalid token Validation（app）
    def F5_Invalid_token_Validation(self):
        # 看app登录请求中是否包含手机号/身份证号
        config = configparser.ConfigParser()
        config.read('config.ini')
        phone_num = config.get('Credentials', 'phone_num')
        id_card = config.get('Credentials', 'id_card')
        if self.login_request != []:
            for flow_info in self.login_request:
                flow = flow_info[0]
                flow_type = flow_info[1]
                if flow_type == "request":
                    content = self.decode_content(flow.request.content)
                    if phone_num in content:
                        self.logger.info("************* Flaw F5: Invalid token Validation, phone_num")
                        self.logger.info(f"************* Flaw F5: Invalid token Validation, {str(flow.request.url)}\n{str(content)}")
                        return True
                    if id_card in content:
                        self.logger.info("************* Flaw F5: Invalid token Validation, id_card")
                        self.logger.info(f"************* Flaw F5: Invalid token Validation, {str(flow.request.url)}\n{str(content)}")
                        return True
        else:
            self.print_log("************* [F5] Not Ready: Invalid token Validation, login_request is None")
        return False
                    

    # F6. Insecure token Usage(app)
    def F6_Insecure_token_Usage(self):
        # 比较pc端登录成功后的response和app端扫码登录的request，比较是否有重合的token
        if self.login_success_response is not None and self.login_request != []:
            success_response_content = self.parse_content(self.login_success_response)
            for flow_info in self.login_request:
                flow = flow_info[0]
                flow_type = flow_info[1]
                if flow_type == "request":
                    content = self.decode_content(flow.request.content)
                    for key, value in success_response_content.items():
                        if str(value) in str(content):
                            if len(str(value)) >= 6:
                                self.logger.info(f"************* Flaw F6: Insecure token Usage, {str(key)}, {str(value)}")
                                return True
        if self.login_success_response is None:
            self.print_log("************* Flaw F6: Insecure token Usage, login_success_response is None")
        if self.login_request is None:
            self.print_log("************* Flaw F6: Insecure token Usage, login_request is None")
        return False


    # F7. Sensitive Data Leakage
    # 找到敏感信息泄露，则返回敏感信息字段名，没有则返回“”
    def F7_Sensitive_Data_Leakage(self):
        config = configparser.ConfigParser()
        config.read('config.ini')       # 读取配置文件，包含phone_num, password, id_card
        start_search_flag = False
        leaked_info = []
        for field, value in config.items('Credentials'):
            # 遍历所有流，搜索是否有敏感信息泄露
            for flow_info in self.flows:
                flow = flow_info[0]
                flow_type = flow_info[1]
                if flow_type == "response":     # 只搜索response
                    if flow.request.url == self.polling_url:        # 从轮询请求开始搜索
                        start_search_flag = True
                    if not start_search_flag:
                        continue
                    # 判断如果是获取图片、css、js等资源的请求，不搜索
                    if flow.request.method == "GET" and flow.request.url.endswith(('.jpg', '.png', '.css', '.js')):
                        continue
                    if self.search(flow, flow_type, value) != "":
                        leaked_info.append(field)
                        self.logger.info(f"************* Flaw F7: Sensitive Data Leakage, {field}")
                        self.logger.info(f"************* Flaw F7: Sensitive Data Leakage, {str(flow.request.url)}\n{str(self.decode_content(flow.response.content))}")
                        # return field
                        break
        return leaked_info
        


    # 去除响应的content中无关字段（每个请求都不一致的字段）
    def filter_response_content(self, content_dict):
        filter_list = ['traceid', 'token', 'sign']
        flatten_content_dict = self.flatten_nested_dict(content_dict)
        for k, v in flatten_content_dict.items():
            for item in filter_list:
                if item == k.replace('-','').lower():
                    flatten_content_dict[k] = ''
                if self.is_timestamp(v):    # 去除时间戳，汽车之家case：/Date(1704869713809)/
                    flatten_content_dict[k] = '' 
                    print("************* filter timestamp: ", str(k), str(v))  
            # 去除token/ticket/uuid等干扰字段值
                    # 先判断是否为URL，若是，解析其参数，将长度大于等于30的字符串置空；若非URL，直接判断长度 （e.g. zepeto.me）
            if isinstance(v, str):
                if v.startswith("http") or "://" in v:
                    url = v
                    parsed_url = urlparse(url)
                    params = dict(parse_qsl(parsed_url.query)) 
                    for key, value in params.items():
                        if len(value) >= 30:
                            flatten_content_dict[k] = flatten_content_dict[k].replace(value, '')
                else:
                    if len(v) >= 30:
                        flatten_content_dict[k] = ''
        return flatten_content_dict

    # 判断时间戳
    def is_timestamp(self, s):
        if s is None:
            return False
        try:
            pattern = r'\d{10,13}'  # 匹配10到13位的数字，找时间戳
            match = re.search(pattern, str(s))
            if match:
                match_t = match.group()  # 如果找到匹配，返回匹配的字符串
                print(match_t)
                if len(str(match_t)) != 10 and len(str(match_t)) != 13:     # 10位秒级，13位毫秒级
                    return False
                ts = int(str(match_t))
                if len(str(ts)) == 13:
                    ts = ts / 1000
                datetime.datetime.fromtimestamp(ts)
                return True
        except ValueError:
            return False
        
    # 替换请求中的qrid为新的qrid
    def replace_field(self, flow, old_value, new_value, qrid_name):
        # 替换轮询请求content中的qrid
        content = self.parse_content(flow.request)
        if content and old_value in str(content):   # qrid在content中
            for key in content.keys():
                if qrid_name in key or self.qrid_name_in_roll in key:
                    content[key] = new_value
            # 将修改后的content设置回请求
            if 'application/x-www-form-urlencoded' in flow.request.headers.get('Content-Type', ''):
                flow.request.content = urllib.parse.urlencode(content).encode()
            elif 'application/json' in flow.request.headers.get('Content-Type', ''):
                flow.request.content = json.dumps(content).encode()
        
        # qrid可能出现在url中，替换url中的qrid
        flow.request.url = flow.request.url.replace(old_value, quote(new_value))

        # qrid可能在轮询请求的cookie中，替换cookie中的qrid
        cookie_dict = self.parse_cookie(flow, "request")
        for key, value in cookie_dict.items():
            if (key == qrid_name or key == self.qrid_name_in_roll) and value == old_value:
                cookie_dict[key] = new_value
        new_cookie_header = "; ".join([f"{name}={value}" for name, value in cookie_dict.items()])
        flow.request.headers["Cookie"] = new_cookie_header
        return flow


    

if len(sys.argv) > 1:
    url = sys.argv[4][4:]
    print("url:", url)
    addons = [
        Analyzer(url)]
else:
    print("[!] No url argument provided.")

