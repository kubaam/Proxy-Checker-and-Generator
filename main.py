import threading
import concurrent.futures
import requests
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Dict, List
import re
import logging
from logging.handlers import RotatingFileHandler
import time
import os
import random
import ipaddress
import sys

# Optional: Use plyer for notifications if you want
# from plyer import notification

# ================= Optional SSL monkeypatch ================= #
import ssl
if sys.version_info < (3, 11):
    original_create_default_context = ssl.create_default_context
    def create_default_context(purpose=ssl.Purpose.SERVER_AUTH, *, cafile=None, capath=None, cadata=None):
        context = original_create_default_context(purpose, cafile=cafile, capath=capath, cadata=cadata)
        try:
            context.set_ciphers('DEFAULT@SECLEVEL=1')
            return context
        except Exception as e:
            logging.getLogger("ProxyChecker").error(f"Error setting ciphers: {e}")
            return context
    ssl.create_default_context = create_default_context

# ================= Disable InsecureRequestWarning ================= #
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# ================================================================== #

PROXY_PATTERN = re.compile(
    r"^(http|https|socks4|socks5)://"
    r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}:\d{2,5}$"
)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0)...",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)..."
]

def get_common_ports(protocol: str) -> List[str]:
    common_ports = {
        'http':  ['80','8080','3128','8000','8888','8008','8009','9999','8118','8001','8081','8880'],
        'https': ['443','8443','9443','8444','9444'],
        'socks4': ['1080','1081','1082','1083','1084'],
        'socks5': ['1080','1081','1082','1083','1084']
    }
    return common_ports.get(protocol.lower(), ['8080'])


# ===================== PROXY GENERATOR ===================== #
class ProxyGenerator:
    """
    Random IP generator for demonstration only. 
    """
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.generated_proxies = set()

    def generate_random_ip(self) -> str:
        while True:
            try:
                octets = [str(random.randint(0,255)) for _ in range(4)]
                ip_ = ".".join(octets)
                ipaddress.IPv4Address(ip_)
                return ip_
            except ipaddress.AddressValueError:
                continue

    def generate_random_port(self, protocol: str) -> str:
        return random.choice(get_common_ports(protocol))

    def generate_proxy(self, protocol: str) -> str:
        max_attempts = 2000
        for _ in range(max_attempts):
            ip_ = self.generate_random_ip()
            port_ = self.generate_random_port(protocol)
            candidate = f"{protocol}://{ip_}:{port_}"
            if candidate not in self.generated_proxies:
                self.generated_proxies.add(candidate)
                return candidate
        self.logger.warning("Exceeded random generation attempts.")
        return None

# ======================= PROXY CHECKER ======================= #
class ProxyChecker:
    """
    Strict IP match always ON => The test site must see the same IP as in the proxy.
    Also geolocation must not be 'Unknown' if enable_geolocation is True.
    """
    def __init__(self, logger: logging.Logger,
                 ssl_verify: bool=False,
                 enable_geolocation: bool=True,
                 test_urls: List[str]=None):
        self.logger = logger
        self.ssl_verify = ssl_verify
        self.enable_geolocation = enable_geolocation
        if test_urls is None:
            self.test_urls = [
                "http://httpbin.org/ip",
                "http://ipinfo.io/ip",
                "https://httpbin.org/ip",
                "https://ipinfo.io/ip"
            ]
        else:
            self.test_urls = test_urls

        self.proxy_pattern = PROXY_PATTERN
        self.checked_proxies: List[Dict[str,str]] = []
        self.valid_count = 0
        self.protocol_counts = {
            'http':   {'valid': 0, 'invalid': 0},
            'https':  {'valid': 0, 'invalid': 0},
            'socks4': {'valid': 0, 'invalid': 0},
            'socks5': {'valid': 0, 'invalid': 0},
        }
        self.user_agents = USER_AGENTS

        # Some fallback geolocation APIs
        self.geolocation_apis = [
            {
                "name": "ip-api.com",
                "url_template": "http://ip-api.com/json/{ip}",
                "parse_response": self.parse_ip_api_com
            },
            {
                "name": "geojs.io",
                "url_template": "https://get.geojs.io/v1/ip/geo/{ip}.json",
                "parse_response": self.parse_geojs_io
            },
            {
                "name": "ipwhois.io",
                "url_template": "http://ipwhois.app/json/{ip}",
                "parse_response": self.parse_ipwhois_io
            },
            {
                "name": "ipapi.co",
                "url_template": "https://ipapi.co/{ip}/json/",
                "parse_response": self.parse_ipapi_co
            }
        ]

    def parse_ip_api_com(self, data: Dict) -> str:
        city = data.get('city','Unknown')
        country = data.get('country','Unknown')
        isp = data.get('isp','Unknown')
        tz = data.get('timezone','Unknown')
        return f"{city}, {country}, {isp}, {tz}"

    def parse_geojs_io(self, data: Dict) -> str:
        city = data.get('city','Unknown')
        country = data.get('country','Unknown')
        org = data.get('organization','Unknown')
        tz = data.get('timezone','Unknown')
        return f"{city}, {country}, {org}, {tz}"

    def parse_ipwhois_io(self, data: Dict) -> str:
        city = data.get('city','Unknown')
        country = data.get('country','Unknown')
        isp = data.get('connection',{}).get('organization','Unknown')
        tz = data.get('timezone','Unknown')
        return f"{city}, {country}, {isp}, {tz}"

    def parse_ipapi_co(self, data: Dict) -> str:
        city = data.get('city','Unknown')
        country = data.get('country_name','Unknown')
        isp = data.get('org','Unknown')
        tz = data.get('timezone','Unknown')
        return f"{city}, {country}, {isp}, {tz}"

    def get_geolocation(self, ip: str) -> str:
        if not self.enable_geolocation:
            return "NoGeolocation"
        for api in self.geolocation_apis:
            url = api["url_template"].format(ip=ip)
            try:
                resp = requests.get(url, timeout=5)
                if resp.status_code==200:
                    data=resp.json()
                    loc=api["parse_response"](data)
                    if loc and loc!="Unknown":
                        return loc
                    else:
                        self.logger.error(f"[{api['name']}] partial or 'Unknown' => IP={ip}")
                else:
                    self.logger.error(f"[{api['name']}] code={resp.status_code} => IP={ip}")
            except Exception as e:
                self.logger.error(f"[{api['name']}] geoloc fail => IP={ip}: {e}")

        return "Unknown"

    def check_single_proxy(self, proxy: str, retries: int, timeout: int) -> Dict[str,str]:
        protocol = proxy.split("://")[0]
        ip_part = proxy.split("://")[1].split(':')[0]

        attempt_count = max(1, retries)
        backoff_delay=1

        for attempt in range(1, attempt_count+1):
            for url in self.test_urls:
                try:
                    headers = {'User-Agent': random.choice(self.user_agents)}
                    start_time = time.time()
                    resp = requests.get(
                        url,
                        proxies={protocol:proxy},
                        headers=headers,
                        timeout=timeout,
                        verify=self.ssl_verify
                    )
                    elapsed=time.time()-start_time

                    if resp.status_code==200:
                        returned_ip=None
                        try:
                            js=resp.json()
                            if "origin" in js:
                                returned_ip=js["origin"]
                        except:
                            returned_ip=resp.text.strip()

                        if returned_ip and "," in returned_ip:
                            returned_ip=returned_ip.split(",")[0].strip()

                        # Strict IP match
                        if not returned_ip or returned_ip!=ip_part:
                            self.logger.error(
                                f"{proxy} => 200 but mismatch {returned_ip} != {ip_part}"
                            )
                            continue

                        # If geolocation
                        location=self.get_geolocation(ip_part)
                        if location=="Unknown":
                            self.logger.error(
                                f"{proxy} => IP matched but geoloc=Unknown => invalid"
                            )
                            continue

                        self.valid_count+=1
                        self.protocol_counts[protocol]['valid']+=1
                        self.logger.info(
                            f"VALID => {proxy} => {url} => {elapsed:.2f}s => {location}"
                        )
                        return {
                            "proxy": proxy,
                            "status":"Valid",
                            "location": location,
                            "response_time":f"{elapsed:.2f}s"
                        }
                    else:
                        self.logger.error(f"{proxy} => {url} => status={resp.status_code}")
                except Exception as e:
                    self.logger.error(f"[Attempt {attempt}] {proxy} => {url} error: {e}")

            # If we have more than 0 retries, do exponential backoff
            if retries>0:
                self.logger.info(f"Retrying {proxy} in {backoff_delay}s...")
                time.sleep(backoff_delay)
                backoff_delay*=2

        self.logger.warning(f"{proxy} => invalid after {retries} attempts.")
        self.protocol_counts[protocol]['invalid']+=1
        return {
            "proxy":proxy,
            "status":"Invalid",
            "location":"Unknown",
            "response_time":"N/A"
        }

    def save_valid_proxy(self, pi: Dict[str,str]):
        os.makedirs("validated_proxies", exist_ok=True)
        path=os.path.join("validated_proxies","valid_proxies.txt")
        try:
            # Fix: if invalid bytes, ignore
            with open(path,"a",encoding='utf-8', errors="ignore") as f:
                f.write(f"{pi['proxy']}\n")
            self.logger.info(f"Saved valid => {pi['proxy']}")
        except Exception as e:
            self.logger.error(f"Error saving => {pi['proxy']}: {e}")

# =============== PROXY CHECKER GUI (SIMPLE TITLES) =============== #
class ProxyCheckerGUI:
    def __init__(self, root: tk.Tk):
        self.root=root
        self.root.title("Proxy Checker")
        self.root.geometry("1600x900")
        self.root.configure(bg="#1A1A1A")

        self.logger=self.setup_logging()

        self.settings={
            "check_retries":0,
            "check_timeout":10,
            "check_concurrency":20,
            "ssl_verify":False,
            "enable_geolocation":True
        }

        self.test_urls=[
            "http://httpbin.org/ip",
            "http://ipinfo.io/ip",
            "https://httpbin.org/ip",
            "https://ipinfo.io/ip"
        ]
        self.checker=ProxyChecker(
            logger=self.logger,
            ssl_verify=self.settings["ssl_verify"],
            enable_geolocation=self.settings["enable_geolocation"],
            test_urls=self.test_urls
        )
        self.generator=ProxyGenerator(logger=self.logger)

        self.valid_file=os.path.join("validated_proxies","valid_proxies.txt")
        self.load_valid_proxies()

        self.init_gui_vars()
        self.setup_gui()

        self.running=False
        self.executor=None
        self.proxies_list=[]
        self.current_threads=[]
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_logging(self)->logging.Logger:
        log=logging.getLogger("ProxyChecker")
        log.setLevel(logging.INFO)

        fh=RotatingFileHandler(
            "proxy_checker.log", maxBytes=5*1024*1024,
            backupCount=3, encoding='utf-8'
        )
        fh.setLevel(logging.INFO)
        fm=logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
        fh.setFormatter(fm)

        ch=logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.ERROR)
        ch.setFormatter(fm)

        log.addHandler(fh)
        log.addHandler(ch)
        return log

    def load_valid_proxies(self):
        self.checker.checked_proxies=[]
        self.checker.valid_count=0
        if os.path.exists(self.valid_file):
            try:
                # Fix: read with 'errors="ignore"' to avoid decode error
                with open(self.valid_file,"r",encoding='utf-8', errors="ignore") as f:
                    for line in f:
                        p=line.strip()
                        if not p:
                            continue
                        if not re.match(r"^(http|https|socks4|socks5)://", p):
                            p=f"http://{p}"
                        if self.checker.proxy_pattern.match(p):
                            info={
                                "proxy":p,
                                "status":"Valid",
                                "location":"Known",
                                "response_time":"N/A"
                            }
                            self.checker.checked_proxies.append(info)
                            self.checker.valid_count+=1
                self.logger.info(f"Loaded {self.checker.valid_count} from {self.valid_file}")
            except Exception as e:
                self.logger.error(f"Error reading {self.valid_file}: {e}")

    def init_gui_vars(self):
        self.retries_var=tk.IntVar(value=self.settings["check_retries"])
        self.timeout_var=tk.IntVar(value=self.settings["check_timeout"])
        self.concurrency_var=tk.IntVar(value=self.settings["check_concurrency"])
        self.ssl_var=tk.BooleanVar(value=self.settings["ssl_verify"])
        self.geo_var=tk.BooleanVar(value=self.settings["enable_geolocation"])

    def setup_gui(self):
        style=ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background="#1A1A1A", borderwidth=0)
        style.configure("TNotebook.Tab", background="#2E2E2E", foreground="#FFFFFF",
                        padding=[10,5], font=("Segoe UI",10,"bold"))
        style.map("TNotebook.Tab", background=[("selected","#FF4500")], foreground=[("selected","#FFFFFF")])

        self.notebook=ttk.Notebook(self.root)
        self.tab_checker=ttk.Frame(self.notebook,style="TFrame")
        self.tab_settings=ttk.Frame(self.notebook,style="TFrame")
        self.tab_about=ttk.Frame(self.notebook,style="TFrame")

        self.notebook.add(self.tab_checker,text="Checker")
        self.notebook.add(self.tab_settings,text="Settings")
        self.notebook.add(self.tab_about,text="About")
        self.notebook.pack(expand=True, fill="both", padx=10, pady=10)

        self.setup_checker_tab()
        self.setup_settings_tab()
        self.setup_about_tab()

        self.status_var=tk.StringVar(value="Status: Idle")
        self.status_label=tk.Label(
            self.root, textvariable=self.status_var,
            anchor="w", bg="#1A1A1A", fg="#FFFFFF",
            font=("Segoe UI",12,"bold")
        )
        self.status_label.pack(side="bottom", fill="x")

    def setup_checker_tab(self):
        hdr=tk.Label(
            self.tab_checker,
            text="Proxy Checker (Strict IP)",
            bg="#1A1A1A",
            fg="#FF4500",
            font=("Segoe UI",20,"bold")
        )
        hdr.pack(anchor="w", padx=10, pady=10)

        proto_frame=ttk.LabelFrame(self.tab_checker, text="Protocols", padding=10)
        proto_frame.pack(fill="x", padx=10, pady=10)

        self.protocol_vars={
            "HTTP":  tk.BooleanVar(value=True),
            "HTTPS": tk.BooleanVar(value=True),
            "SOCKS4":tk.BooleanVar(value=False),
            "SOCKS5":tk.BooleanVar(value=False),
            "All":   tk.BooleanVar(value=False)
        }
        for idx, proto in enumerate(["HTTP","HTTPS","SOCKS4","SOCKS5","All"]):
            cbtn=tk.Checkbutton(
                proto_frame,text=proto,
                variable=self.protocol_vars[proto],
                bg="#2E2E2E", fg="#FFFFFF",
                selectcolor="#FF4500",
                activebackground="#2E2E2E",
                activeforeground="#FFFFFF",
                font=("Segoe UI",10,"bold"),
                command=self.update_proto_selection
            )
            cbtn.grid(row=0,column=idx,padx=5,pady=5,sticky="w")

        self.ssl_checkbox=tk.Checkbutton(
            proto_frame,
            text="SSL Verify",
            variable=self.ssl_var,
            bg="#2E2E2E",
            fg="#FFFFFF",
            selectcolor="#FF4500",
            activebackground="#2E2E2E",
            activeforeground="#FFFFFF",
            font=("Segoe UI",10,"bold")
        )
        self.ssl_checkbox.grid(row=1,column=0, padx=5,pady=5, sticky="w")

        btn_frame=tk.Frame(self.tab_checker,bg="#1A1A1A")
        btn_frame.pack(anchor="w", padx=10, pady=10)

        self.start_btn=tk.Button(
            btn_frame, text="Start",
            command=self.start_checking,
            bg="#FF4500",
            fg="#FFFFFF",
            font=("Segoe UI",12,"bold"),
            bd=0, activebackground="#CC3700",
            width=10
        )
        self.start_btn.pack(side="left", padx=5)

        self.stop_btn=tk.Button(
            btn_frame, text="Stop",
            command=self.stop_checking,
            bg="#FF4500",
            fg="#FFFFFF",
            font=("Segoe UI",12,"bold"),
            bd=0, activebackground="#CC3700",
            width=10,
            state="disabled"
        )
        self.stop_btn.pack(side="left", padx=5)

        self.load_btn=tk.Button(
            btn_frame, text="Load",
            command=self.load_proxies,
            bg="#FF4500",
            fg="#FFFFFF",
            font=("Segoe UI",12,"bold"),
            bd=0, activebackground="#CC3700",
            width=10
        )
        self.load_btn.pack(side="left", padx=5)

        list_frame=tk.Frame(self.tab_checker,bg="#1A1A1A")
        list_frame.pack(fill="both", expand=True, padx=10, pady=10)

        sb=ttk.Scrollbar(list_frame)
        sb.pack(side="right", fill="y")

        self.checker_listbox=tk.Listbox(
            list_frame,
            bg="#2E2E2E",
            fg="#FF4500",
            selectbackground="#FF4500",
            font=("Consolas",10),
            yscrollcommand=sb.set
        )
        self.checker_listbox.pack(fill="both", expand=True)
        sb.config(command=self.checker_listbox.yview)

    def setup_settings_tab(self):
        hdr=tk.Label(
            self.tab_settings,
            text="Settings",
            bg="#1A1A1A", fg="#FF4500",
            font=("Segoe UI",20,"bold")
        )
        hdr.pack(anchor="w", padx=10, pady=10)

        frm=ttk.LabelFrame(self.tab_settings, text="Checking Params", padding=10)
        frm.pack(fill="x", padx=10, pady=10)

        tk.Label(frm, text="Retries (0=once):", bg="#2E2E2E", fg="#FFFFFF", font=("Segoe UI",10,"bold")).grid(row=0,column=0,sticky="w",padx=5,pady=5)
        tk.Entry(frm, textvariable=self.retries_var, width=10, font=("Segoe UI",10,"bold")).grid(row=0,column=1,sticky="w",padx=5,pady=5)

        tk.Label(frm, text="Timeout (s):", bg="#2E2E2E", fg="#FFFFFF", font=("Segoe UI",10,"bold")).grid(row=1,column=0,sticky="w",padx=5,pady=5)
        tk.Entry(frm, textvariable=self.timeout_var, width=10, font=("Segoe UI",10,"bold")).grid(row=1,column=1,sticky="w",padx=5,pady=5)

        tk.Label(frm, text="Concurrency:", bg="#2E2E2E", fg="#FFFFFF", font=("Segoe UI",10,"bold")).grid(row=2,column=0,sticky="w",padx=5,pady=5)
        tk.Entry(frm, textvariable=self.concurrency_var, width=10, font=("Segoe UI",10,"bold")).grid(row=2,column=1,sticky="w",padx=5,pady=5)

        self.geo_checkbox=tk.Checkbutton(
            frm, text="Enable Geolocation",
            variable=self.geo_var,
            bg="#2E2E2E", fg="#FFFFFF",
            selectcolor="#FF4500",
            activebackground="#2E2E2E",
            activeforeground="#FFFFFF",
            font=("Segoe UI",10,"bold")
        )
        self.geo_checkbox.grid(row=3,column=0,padx=5,pady=5,sticky="w")

        tk.Button(
            self.tab_settings, text="Save",
            command=self.save_settings,
            bg="#FF4500",
            fg="#FFFFFF",
            font=("Segoe UI",12,"bold"),
            bd=0, activebackground="#CC3700",
            width=15
        ).pack(pady=20)

    def setup_about_tab(self):
        hdr=tk.Label(
            self.tab_about,
            text="About",
            bg="#1A1A1A", fg="#FF4500",
            font=("Segoe UI",20,"bold")
        )
        hdr.pack(anchor="w", padx=10, pady=10)

        about_text=(
            "Strict IP match always ON.\n"
            "Stop is truly immediate (shuts down generation & tasks).\n"
            "Use real proxy list for best success.\n"
        )
        lbl=tk.Label(
            self.tab_about,
            text=about_text,
            bg="#1A1A1A",
            fg="#FFFFFF",
            font=("Segoe UI",10,"bold"),
            justify="left",
            wraplength=1500
        )
        lbl.pack(anchor="w", padx=10, pady=10)

    def update_proto_selection(self):
        if self.protocol_vars["All"].get():
            for p in ["HTTP","HTTPS","SOCKS4","SOCKS5"]:
                self.protocol_vars[p].set(True)

        # If socks => no SSL
        if self.protocol_vars["SOCKS4"].get() or self.protocol_vars["SOCKS5"].get():
            self.ssl_checkbox.config(state="disabled")
            self.ssl_var.set(False)
        else:
            if self.protocol_vars["HTTP"].get() or self.protocol_vars["HTTPS"].get():
                self.ssl_checkbox.config(state="normal")
            else:
                self.ssl_checkbox.config(state="disabled")
                self.ssl_var.set(False)

        if self.protocol_vars["All"].get():
            if self.protocol_vars["SOCKS4"].get() or self.protocol_vars["SOCKS5"].get():
                self.ssl_checkbox.config(state="disabled")
                self.ssl_var.set(False)

    def start_checking(self):
        if self.running:
            messagebox.showwarning("Already Running","Proxy checking in progress.")
            return
        selected=[]
        if self.protocol_vars["All"].get():
            selected=["http","https","socks4","socks5"]
        else:
            for k,v in self.protocol_vars.items():
                if k!="All" and v.get():
                    selected.append(k.lower())
        if not selected:
            messagebox.showerror("No Protocols","Select at least one protocol.")
            self.status_var.set("No protocols selected.")
            return

        try:
            r_=self.retries_var.get()
            t_=self.timeout_var.get()
            c_=self.concurrency_var.get()
            if r_<0 or t_<1 or c_<1:
                raise ValueError("Retries>=0, Timeout>0, Concurrency>0")
        except ValueError as ve:
            self.logger.error(f"Settings error: {ve}")
            messagebox.showerror("Invalid",str(ve))
            return

        self.settings["check_retries"]=r_
        self.settings["check_timeout"]=t_
        self.settings["check_concurrency"]=c_
        self.settings["ssl_verify"]=self.ssl_var.get()
        self.settings["enable_geolocation"]=self.geo_var.get()

        self.checker.ssl_verify=self.settings["ssl_verify"]
        self.checker.enable_geolocation=self.settings["enable_geolocation"]

        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_var.set("Checking proxies...")
        self.logger.info(
            f"Start => protocols={selected}, retries={r_}, timeout={t_}, concurrency={c_}"
        )

        self.checker_listbox.delete(0,tk.END)
        for proto in self.checker.protocol_counts:
            self.checker.protocol_counts[proto]['valid']=0
            self.checker.protocol_counts[proto]['invalid']=0
        self.checker.valid_count=0
        self.checker.checked_proxies=[]

        self.running=True
        self.executor=concurrent.futures.ThreadPoolExecutor(max_workers=c_)

        t=threading.Thread(
            target=self._continuous_check_proxies,
            args=(selected,)
        )
        t.daemon=True
        t.start()
        self.current_threads.append(t)

    def _continuous_check_proxies(self, selected_protocols: List[str]):
        """
        The main loop. We stop ASAP if self.running=False or user calls stop_checking().
        """
        try:
            while self.running:
                batch=[]
                if self.proxies_list:
                    batch = random.sample(self.proxies_list, min(50, len(self.proxies_list)))
                else:
                    for _ in range(50):
                        if not self.running:
                            break
                        p=random.choice(selected_protocols)
                        cand=self.generator.generate_proxy(p)
                        if cand:
                            batch.append(cand)
                if not self.running:
                    break

                if not batch:
                    time.sleep(1)
                    continue

                futs=[]
                for proxy in batch:
                    if not self.running:
                        break
                    fut=self.executor.submit(
                        self.checker.check_single_proxy,
                        proxy,
                        self.settings["check_retries"],
                        self.settings["check_timeout"]
                    )
                    futs.append(fut)

                if not self.running:
                    break

                for fut in concurrent.futures.as_completed(futs):
                    if not self.running:
                        break
                    try:
                        info=fut.result()
                    except concurrent.futures.CancelledError:
                        self.logger.info("Task was canceled.")
                        continue
                    if info["status"].lower()=="valid":
                        self.checker.save_valid_proxy(info)
                    self.root.after(0, lambda i=info:self.on_proxy_checked(i))

                time.sleep(1)
        finally:
            if self.executor:
                self.executor.shutdown(wait=False, cancel_futures=True)
            self.root.after(0,self._stop_done)

    def _stop_done(self):
        self.logger.info("Finished or forcibly stopped. Executor shutdown.")
        self.running=False
        self.executor=None
        self.status_var.set(f"Stopped. Valid={self.checker.valid_count}")
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def stop_checking(self):
        self.logger.info("Stop pressed => shutting down tasks.")
        self.running=False
        if self.executor:
            self.executor.shutdown(wait=False, cancel_futures=True)
        self.stop_btn.config(state="disabled")
        self.start_btn.config(state="normal")
        self.status_var.set("Stopped by user.")

    def on_proxy_checked(self, info: Dict[str,str]):
        self.checker.checked_proxies.append(info)
        total=len(self.checker.checked_proxies)
        valid=self.checker.valid_count
        sr=(valid/total)*100 if total>0 else 0
        self.status_var.set(f"Checked={total} | Valid={valid} | Rate={sr:.2f}%")

        pxy=info["proxy"]
        st=info["status"]
        color="#00FF00" if st.lower()=="valid" else "#FF0000"
        dt=f"{pxy} => {('🟢 Valid' if st.lower()=='valid' else '🔴 Invalid')} - {info['response_time']}"
        loc=info.get("location")
        if loc not in [None,"Unknown","NoGeolocation"]:
            dt+=f" - {loc}"

        self.checker_listbox.insert(tk.END, dt)
        self.checker_listbox.itemconfig(tk.END,{'fg':color})
        self.checker_listbox.yview_moveto(1)

    def load_proxies(self):
        path=filedialog.askopenfilename(
            title="Select Proxy File",
            filetypes=[("Text Files","*.txt"),("All Files","*.*")]
        )
        if path:
            try:
                with open(path,"r",encoding="utf-8", errors="ignore") as f:
                    raw=[line.strip() for line in f if line.strip()]
                val=[]
                for r in raw:
                    if not re.match(r"^(http|https|socks4|socks5)://", r):
                        r=f"http://{r}"
                    if self.checker.proxy_pattern.match(r):
                        val.append(r)
                self.proxies_list=val
                messagebox.showinfo("Proxies Loaded",f"Loaded {len(val)} proxies.")
            except Exception as e:
                messagebox.showerror("Error",str(e))

    def save_settings(self):
        try:
            r_=self.retries_var.get()
            t_=self.timeout_var.get()
            c_=self.concurrency_var.get()
            if r_<0 or t_<1 or c_<1:
                raise ValueError("Retries>=0, Timeout>0, Concurrency>0")

            self.settings["check_retries"]=r_
            self.settings["check_timeout"]=t_
            self.settings["check_concurrency"]=c_
            self.settings["ssl_verify"]=self.ssl_var.get()
            self.settings["enable_geolocation"]=self.geo_var.get()

            self.checker.ssl_verify=self.settings["ssl_verify"]
            self.checker.enable_geolocation=self.settings["enable_geolocation"]

            messagebox.showinfo("Settings Saved","Updated settings.\n(Strict IP is always ON.)")
        except ValueError as ve:
            self.logger.error(f"Settings error: {ve}")
            messagebox.showerror("Invalid",str(ve))
        except Exception as e:
            self.logger.error(f"Save settings error: {e}")
            messagebox.showerror("Save Failed",str(e))

    def on_close(self):
        if messagebox.askokcancel("Quit","Stop tasks and close?"):
            self.logger.info("User closing => forcibly stopping tasks.")
            self.running=False
            if self.executor:
                self.executor.shutdown(wait=False, cancel_futures=True)
            self.root.destroy()

def main():
    root=tk.Tk()
    app=ProxyCheckerGUI(root)
    root.mainloop()

if __name__=="__main__":
    main()
