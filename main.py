# -*- coding: utf-8 -*-
"""
OSINT Mobile — Android-версия (Kivy).
Модули: Deep IP, Phone OSINT (HLR), VK OSINT, CCTV Cameras, Ship Tracker.
Сборка APK: buildozer android debug (см. buildozer.spec).
Все сетевые запросы — в потоках, обновление UI — только через Clock (иначе краш).
"""

import os, sys, json, time, threading, socket, webbrowser, re

import requests
from kivy.app import App
from kivy.clock import Clock
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.screenmanager import Screen, ScreenManager
from kivy.core.window import Window

Window.softinput_mode = "below_target"

UA = {"User-Agent": "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 OSINT-Mobile/1.0"}
try:
    from android.storage import app_storage_path  # noqa
    HISTORY_FILE = os.path.join(os.environ.get("ANDROID_PRIVATE", os.getcwd()), "osint_history.json")
except Exception:
    HISTORY_FILE = os.path.join(os.getcwd(), "osint_history.json")

# ============================ ИСТОРИЯ ============================
def load_history():
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
    except Exception:
        pass
    return []

def save_history(h):
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(h[-500:], f, indent=2, ensure_ascii=False)
    except Exception:
        pass

def add_to_history(qtype, query, summary):
    h = load_history()
    h.append({"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
              "type": qtype, "query": query, "result": summary})
    save_history(h)

# ============================ ТЕМЫ ============================
THEMES = {
    "dark":      {"bg":  (0.12, 0.12, 0.12, 1), "panel": (0.16, 0.16, 0.17, 1),
                  "text": (0.88, 0.88, 0.88, 1), "accent": (0.31, 0.79, 0.69, 1),
                  "btn":  (0.05, 0.39, 0.61, 1)},
    "light":     {"bg":  (0.96, 0.96, 0.96, 1), "panel": (1, 1, 1, 1),
                  "text": (0.12, 0.12, 0.12, 1), "accent": (0, 0.47, 0.83, 1),
                  "btn":  (0, 0.47, 0.83, 1)},
    "cyberpunk": {"bg":  (0.04, 0.05, 0.15, 1), "panel": (0.08, 0.10, 0.24, 1),
                  "text": (0, 1, 0.62, 1),   "accent": (1, 0, 1, 1),
                  "btn":  (1, 0, 1, 1)},
    "matrix":    {"bg":  (0, 0, 0, 1), "panel": (0, 0.07, 0, 1),
                  "text": (0, 1, 0, 1), "accent": (0, 1, 0, 1),
                  "btn":  (0, 0.2, 0, 1)},
}

# ============================ IP INTELLIGENCE ============================
def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return ip.count(".") == 3 and all(0 <= int(x) <= 255 for x in ip.split("."))
    except Exception:
        return False

class IPIntel:
    DNSBL = {"Spamhaus ZEN": "zen.spamhaus.org", "Barracuda": "b.barracudacentral.org",
             "DroneBL": "dnsbl.dronebl.org", "S5H": "all.s5h.net", "TOR exit": "torexit.dan.me.uk"}

    @staticmethod
    def _get(url, timeout=10):
        try:
            r = requests.get(url, timeout=timeout, headers=UA)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return {}

    @staticmethod
    def ipwhois(ip): return IPIntel._get(f"https://ipwho.is/{ip}")
    @staticmethod
    def ipapi(ip):
        return IPIntel._get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,"
                            "region,regionName,city,zip,lat,lon,timezone,offset,isp,org,as,asname,"
                            "reverse,mobile,proxy,hosting,query")
    @staticmethod
    def ipinfo(ip): return IPIntel._get(f"https://ipinfo.io/{ip}/json")
    @staticmethod
    def rdap(ip):
        try:
            r = requests.get(f"https://rdap.org/ip/{ip}", timeout=15, headers=UA)
            return r.json() if r.status_code == 200 else {}
        except Exception:
            return {}

    @staticmethod
    def dnsbl_check(ip):
        if not is_valid_ip(ip):
            return {}
        rev = ".".join(reversed(ip.split(".")))
        res = {}
        for name, zone in IPIntel.DNSBL.items():
            try:
                ans = socket.gethostbyname(f"{rev}.{zone}")
                res[name] = {"listed": True, "code": ans}
            except socket.gaierror:
                res[name] = {"listed": False, "code": "-"}
            except Exception as e:
                res[name] = {"listed": None, "code": str(e)}
            time.sleep(0.05)
        return res

    @staticmethod
    def full_report(ip):
        report = {"ip": ip, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"), "sources": {}}
        w = IPIntel.ipwhois(ip); a = IPIntel.ipapi(ip); i = IPIntel.ipinfo(ip); rd = IPIntel.rdap(ip)
        report["sources"]["ipwho.is"] = w.get("success", False)
        report["sources"]["ip-api.com"] = a.get("status") == "success"
        report["sources"]["ipinfo.io"] = "ip" in i
        report["sources"]["rdap.org"] = bool(rd)

        g = w.get("flag") or {}; tz = w.get("timezone") or {}; cur = w.get("currency") or {}
        sec = w.get("security") or {}; con = w.get("connection") or {}

        report["geo"] = {
            "city": (w.get("city") or a.get("city") or i.get("city") or "").strip(),
            "region": (w.get("region") or a.get("regionName") or i.get("region") or "").strip(),
            "country": (w.get("country") or a.get("country") or i.get("country") or "").strip(),
            "country_code": (w.get("country_code") or a.get("countryCode") or i.get("country") or "").strip(),
            "latitude": w.get("latitude", a.get("lat", "")),
            "longitude": w.get("longitude", a.get("lon", "")),
        }
        report["security"] = {
            "is_vpn": sec.get("vpn", False), "is_proxy": sec.get("proxy", a.get("proxy", False)),
            "is_tor": sec.get("tor", False), "is_relay": sec.get("relay", False),
            "is_hosting": sec.get("hosting", a.get("hosting", False)),
        }
        report["timezone"] = {"id": tz.get("id", a.get("timezone", i.get("timezone", ""))),
                              "current_time": tz.get("current_time", "")}
        report["flag"] = g.get("emoji", "")
        report["connection"] = {
            "asn": con.get("asn", ""), "org": con.get("org") or a.get("org", ""),
            "isp": con.get("isp") or a.get("isp", ""),
            "as_name": a.get("asname", ""), "reverse_dns": a.get("reverse") or i.get("hostname", ""),
        }
        rd_out = {}
        if rd:
            rd_out["handle"] = rd.get("handle", ""); rd_out["name"] = rd.get("name", "")
            ents = []
            for ent in (rd.get("entities") or [])[:4]:
                fn = ""
                try:
                    for item in ent.get("vcardArray", [None, []])[1]:
                        if item[0] == "fn": fn = item[3]
                except Exception:
                    pass
                ents.append(f"{ent.get('handle','')} [{', '.join(ent.get('roles', []))}] {fn}")
            rd_out["entities"] = ents
            rd_out["events"] = [f"{e.get('eventAction','')} {e.get('eventDate','')[:10]}"
                                for e in (rd.get("events") or [])[:6]]
        report["rdap"] = rd_out
        report["blacklist"] = IPIntel.dnsbl_check(ip)
        lat, lon = report["geo"]["latitude"], report["geo"]["longitude"]
        report["maps"] = (f"https://www.google.com/maps?q={lat},{lon}"
                          if isinstance(lat, (int, float)) and isinstance(lon, (int, float)) else "")
        return report

def format_report(rep):
    L = [f"item  ({rep['timestamp']})", f"  ip_address: {rep['ip']}"]
    for k, v in rep["geo"].items(): L.append(f"  {k}: {v}")
    L.append("  security")
    for k, v in rep["security"].items(): L.append(f"    {k}: {v}")
    L.append("  timezone")
    for k, v in rep["timezone"].items(): L.append(f"    {k}: {v}")
    L.append(f"  flag: {rep['flag']}")
    L.append("  connection")
    for k, v in rep["connection"].items(): L.append(f"    {k}: {v}")
    L.append("  rdap (whois)")
    rd = rep["rdap"]
    if rd:
        L.append(f"    handle: {rd.get('handle','')}")
        for e in rd.get("entities", []): L.append(f"    entity: {e}")
        for e in rd.get("events", []): L.append(f"    event: {e}")
    else:
        L.append("    нет данных RDAP")
    L.append("  blacklist (DNSBL)")
    for name, res in rep["blacklist"].items():
        mark = "LISTED!" if res.get("listed") else ("clean" if res.get("listed") is False else "error")
        L.append(f"    {name}: {mark}")
    L.append("  sources: " + ", ".join(k for k, v in rep["sources"].items() if v))
    if rep.get("maps"):
        L += ["", "map:", f"  {rep['maps']}"]
    return "\n".join(L)

# ============================ PHONE OSINT ============================
RU_DEF = {
    "900":"Теле2 / СберМобайл","901":"Tele2 (Сибирь)","902":"Tele2 (Урал)","903":"Билайн (Москва)",
    "904":"Билайн (Урал)","905":"Билайн (Северо-Запад)","906":"Билайн (Средняя Волга)","908":"Билайн (Кавказ)",
    "909":"Билайн (Москва)","910":"МТС (Средняя Волга)","911":"МТС (Северо-Запад)","912":"МТС (Урал)",
    "913":"МТС (Сибирь)","914":"МТС (Дальний Восток)","915":"МТС (Москва)","916":"МТС (Москва)",
    "917":"МТС (Поволжье)","918":"МТС (Северо-Кавказский)","919":"МТС (Урал)","920":"МегаФон (Сибирь)",
    "921":"МегаФон (Северо-Запад)","922":"МегаФон (Урал)","923":"МегаФон (Сибирь)","924":"МегаФон (Дальний Восток)",
    "925":"МегаФон (Москва)","926":"МегаФон (Москва)","927":"МегаФон (Поволжье)","928":"МегаФон (Северо-Кавказский)",
    "929":"МегаФон (Москва)","930":"МТС (Центр)","931":"МТС (Северо-Запад)","932":"МТС (Урал)",
    "933":"МТС (Сибирь)","934":"МТС (Поволжье)","936":"МТС (Юг)","937":"Теле2 (Поволжье)",
    "938":"МТС (Северо-Кавказский)","939":"МТС (Сибирь)","950":"Теле2 (Сибирь)","951":"Теле2 (Урал)",
    "952":"Теле2 (Поволжье)","953":"Теле2 (Юг)","954":"Теле2 (Центр)","955":"Теле2 (Северо-Запад)",
    "956":"Теле2 (Кавказ)","958":"Теле2 (Дальний Восток)","960":"Билайн (Северо-Запад)","961":"Билайн (Юг)",
    "962":"Билайн (Сибирь)","963":"Билайн (Урал)","964":"Билайн (Поволжье)","965":"Билайн (Москва)",
    "966":"Билайн (Северо-Кавказский)","967":"Теле2 / ГТК (Москва)","968":"Билайн (Москва)","969":"Билайн (Москва)",
    "970":"Теле2 / ГТК (Москва)","971":"Билайн (Центр)","977":"Теле2 / ГТК (Москва)","978":"МТС (Крым)",
    "980":"МТС (Москва)","981":"МТС (Северо-Запад)","982":"МТС (Урал)","983":"МТС (Сибирь)",
    "984":"МТС (Дальний Восток)","985":"МТС (Москва)","986":"МТС (Поволжье)","987":"МТС (Поволжье)",
    "988":"МТС (Северо-Кавказский)","989":"МТС (Юг)","991":"Теле2 (Москва)","992":"МегаФон (Москва)",
    "993":"МегаФон (Москва)","994":"МТС (Москва)","995":"МТС (Москва)","996":"Билайн (Москва)",
    "997":"Билайн (Москва)","998":"Билайн (Москва)","999":"Теле2 (Москва)",
}
RU_MNC = {"01":"МТС","02":"МегаФон","03":"НТК (Ростелеком)","05":"ЕТК (Tele2)","06":"БайкалВестКом (Tele2)",
          "07":"СМАРТС","09":"Скай Линк","10":"Билайн","11":"ЮТК (Tele2)","12":"Билайн","13":"Кубань GSM (Tele2)",
          "14":"МегаФон (Дагестан)","15":"СМАРТС","16":"НСС (МТС)","17":"Ютел (Tele2)","20":"Теле2",
          "23":"ГТК (Москва)","28":"МТС","35":"МОТИВ","38":"МТС","39":"Голден Телеком (МТС)","50":"МТС",
          "62":"Теле2","93":"МегаФон","97":"Теле2","99":"Билайн"}

class PhoneIntel:
    @staticmethod
    def normalize(raw):
        d = "".join(ch for ch in raw if ch.isdigit())
        if len(d) == 11 and d[0] in "78": d = d[1:]
        if len(d) == 12 and d.startswith("37"): d = d[2:]
        return d if len(d) == 10 else None

    @staticmethod
    def htmlweb(digits10):
        try:
            r = requests.get("https://htmlweb.ru/geo/api.php",
                             params={"json": 1, "tel": digits10}, timeout=12, headers=UA)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, dict) and data.get("error"):
                    return {"__api_error__": str(data.get("error"))}
                return data if isinstance(data, dict) else {}
        except Exception as e:
            return {"__api_error__": str(e)}
        return {}

    @staticmethod
    def _hw_info(hw):
        if not isinstance(hw, dict): return {}
        for key in ("0", 0, "1"):
            v = hw.get(key)
            if isinstance(v, dict) and v: return v
        for v in hw.values():
            if isinstance(v, dict) and ("oper" in v or "region" in v): return v
        return {}

    @staticmethod
    def full_report(raw):
        digits = PhoneIntel.normalize(raw)
        if not digits:
            return {"error": "нужен номер вида +7XXXXXXXXXX (10 цифр)"}
        defc, sub = digits[:3], digits[3:]
        nat = f"8 ({defc}) {sub[:3]}-{sub[3:5]}-{sub[5:]}"
        hw = PhoneIntel.htmlweb(digits)
        api_err = hw.get("__api_error__") if isinstance(hw, dict) else None
        info = PhoneIntel._hw_info(hw)
        hw_ok = bool(info)
        oper_brand = info.get("oper_brand") or info.get("brand") or ""
        def_ref = RU_DEF.get(defc, "DEF-код не найден в справочнике РФ")
        carrier = oper_brand if oper_brand else def_ref.split(" ")[0]
        mnp = bool(oper_brand) and oper_brand.lower() not in def_ref.lower() and defc in RU_DEF
        mnc = str(info.get("mnc", "")).zfill(2) if info.get("mnc") else ""
        return {
            "msisdn": f"+7{digits}", "national_format": nat, "def_code": defc,
            "country": "Россия (+7)",
            "api_status": ("OK (live HLR-запрос)" if hw_ok else
                           (f"htmlweb.ru: {api_err} (лимит 2/день без ключа) — локальный справочник"
                            if api_err else "htmlweb.ru молчит — локальный справочник")),
            "carrier": {"operator": carrier,
                        "operator_full": info.get("oper") or info.get("operator") or "",
                        "region": info.get("region") or info.get("obl") or "",
                        "city": info.get("city") or info.get("np") or "",
                        "def_reference": def_ref, "mnp_ported_suspected": mnp},
            "network": {"mcc": info.get("mcc", "250"), "mnc": mnc,
                        "mnc_decoded": RU_MNC.get(mnc, "") if mnc else "",
                        "time_zone": info.get("time_zone", "")},
            "hlr": {"hlr_request_status": "выполнен к бесплатным live-источникам" if hw_ok else "частично (лимит API)",
                    "imsi_hint": f"250{mnc}*********" if mnc else "недоступно без HLR-шлюза",
                    "sim_live_status": "только платный SS7/HLR API — не выдумывается",
                    "ported_mnp": mnp},
            "footprint": {"whatsapp": f"https://wa.me/7{digits}",
                          "telegram": f"https://t.me/+7{digits}",
                          "who_calls": f"https://neberitrubku.ru/nomer-telefona/{digits}",
                          "vk": f"https://vk.com/search?c%5Bq%5D=%2B7{digits}",
                          "avito": f"https://www.avito.ru/all?q=%2B7{digits}"},
        }

def format_phone_report(rep):
    if "error" in rep: return rep["error"]
    L = ["item", f"  msisdn: {rep['msisdn']}", f"  national_format: {rep['national_format']}",
         f"  country: {rep['country']}", f"  api_status: {rep['api_status']}", "  carrier"]
    for k, v in rep["carrier"].items(): L.append(f"    {k}: {v}")
    L.append("  network")
    for k, v in rep["network"].items(): L.append(f"    {k}: {v}")
    L.append("  hlr")
    for k, v in rep["hlr"].items(): L.append(f"    {k}: {v}")
    L.append("  footprint (открыть в браузере):")
    for k, v in rep["footprint"].items(): L.append(f"    {k}: {v}")
    return "\n".join(L)

# ============================ UI-ХЕЛПЕРЫ ============================
def make_out(text="", theme=None):
    lbl = Label(text=text, size_hint_y=None, valign="top", padding=(10, 10),
                font_name="RobotoMono-Regular" if False else "Roboto",
                font_size="13sp")
    lbl.bind(texture_size=lbl.setter("size"))
    lbl.bind(width=lambda s, w: s.setter("text_size")((w, None)))
    if theme:
        lbl.color = theme["text"]
    return lbl

class BaseScreen(Screen):
    def __init__(self, app, **kw):
        super().__init__(**kw)
        self.app = app
        root = BoxLayout(orientation="vertical", padding=8, spacing=8)
        self.out = make_out(theme=app.theme)
        scroll = ScrollView()
        scroll.add_widget(self.out)
        root.add_widget(scroll, 1)
        self.add_widget(root)

    def set_out(self, text):
        Clock.schedule_once(lambda dt: setattr(self.out, "text", text))

# ============================ ЭКРАНЫ ============================
class IPScreen(BaseScreen):
    def __init__(self, app, **kw):
        super().__init__(app, **kw)
        root = self.children[0]
        box = BoxLayout(size_hint_y=None, height="48dp", spacing=8)
        self.inp = TextInput(hint_text="8.8.8.8", multiline=False, size_hint_x=1)
        self.inp.bind(on_text_validate=self.analyze)
        btn = Button(text="Анализ", size_hint_x=None, width="110dp")
        btn.bind(on_release=self.analyze)
        box.add_widget(self.inp); box.add_widget(btn)
        root.add_widget(box, 0)

    def analyze(self, *a):
        ip = self.inp.text.strip()
        if not is_valid_ip(ip):
            self.set_out("Введи корректный IPv4"); return
        self.set_out("Сбор: ipwho.is / ip-api / ipinfo / RDAP / DNSBL ...")
        def worker():
            try:
                rep = IPIntel.full_report(ip)
                Clock.schedule_once(lambda dt: self.show(rep))
            except Exception as e:
                Clock.schedule_once(lambda dt: self.set_out(f"Ошибка: {e}"))
        threading.Thread(target=worker, daemon=True).start()

    def show(self, rep):
        self.set_out(format_report(rep))
        add_to_history("Deep IP", rep["ip"], rep["geo"].get("city", ""))

class PhoneScreen(BaseScreen):
    def __init__(self, app, **kw):
        super().__init__(app, **kw)
        root = self.children[0]
        box = BoxLayout(size_hint_y=None, height="48dp", spacing=8)
        self.inp = TextInput(hint_text="+7 999 123-45-67", multiline=False)
        self.inp.bind(on_text_validate=self.analyze)
        btn = Button(text="HLR-анализ", size_hint_x=None, width="130dp")
        btn.bind(on_release=self.analyze)
        box.add_widget(self.inp); box.add_widget(btn)
        root.add_widget(box, 0)
        links = BoxLayout(size_hint_y=None, height="48dp", spacing=6)
        for name, key in [("WA", "whatsapp"), ("TG", "telegram"), ("Звонки", "who_calls"),
                          ("VK", "vk"), ("Avito", "avito")]:
            b = Button(text=name)
            b.bind(on_release=lambda _, k=key: self.open_link(k))
            links.add_widget(b)
        root.add_widget(links, 1)

    def analyze(self, *a):
        raw = self.inp.text.strip()
        if not raw: return
        self.set_out("HLR live-запрос htmlweb.ru + план нумерации ...")
        def worker():
            try:
                rep = PhoneIntel.full_report(raw)
                Clock.schedule_once(lambda dt: self.show(rep))
            except Exception as e:
                Clock.schedule_once(lambda dt: self.set_out(f"Ошибка: {e}"))
        threading.Thread(target=worker, daemon=True).start()

    def show(self, rep):
        self.set_out(format_phone_report(rep))
        if "msisdn" in rep:
            add_to_history("Phone", rep["msisdn"], rep["carrier"].get("operator", ""))
        self._rep = rep

    def open_link(self, key):
        rep = getattr(self, "_rep", None)
        if rep and key in rep.get("footprint", {}):
            webbrowser.open(rep["footprint"][key])

class VKScreen(BaseScreen):
    def __init__(self, app, **kw):
        super().__init__(app, **kw)
        root = self.children[0]
        box = BoxLayout(size_hint_y=None, height="48dp", spacing=8)
        self.inp = TextInput(hint_text="ФИО / ID / телефон", multiline=False)
        btn = Button(text="Искать", size_hint_x=None, width="110dp")
        btn.bind(on_release=self.search)
        box.add_widget(self.inp); box.add_widget(btn)
        root.add_widget(box, 0)
        from urllib.parse import quote
        row = BoxLayout(size_hint_y=None, height="48dp", spacing=6)
        b1 = Button(text="VK поиск"); b1.bind(on_release=lambda _: self.open(f"https://vk.com/people/{quote(self.inp.text.strip())}"))
        b2 = Button(text="Профиль по ID")
        b2.bind(on_release=lambda _: self.open("https://vk.com/" + self.inp.text.strip().replace("https://vk.com/", "").strip("/")))
        b3 = Button(text="RegVK"); b3.bind(on_release=lambda _: self.open(f"https://regvk.com/?q={quote(self.inp.text.strip())}"))
        for b in (b1, b2, b3): row.add_widget(b)
        root.add_widget(row, 1)
        self.set_out("VK OSINT — только публичные данные.\nОнлайн/устройство/«шпионаж» — недоступно никому, "
                     "такие «шпионы» это обман.\n\nПоиск откроется во внешнем браузере телефона.")

    def search(self, *a):
        from urllib.parse import quote
        q = self.inp.text.strip()
        if q:
            self.open(f"https://vk.com/people/{quote(q)}")
            add_to_history("VK", q, "people search")

    def open(self, url):
        if url and url != "https://vk.com/":
            webbrowser.open(url)

class CamScreen(BaseScreen):
    SOURCES = [("Insecam (мировые камеры)", "https://www.insecam.org/"),
               ("World-Cam.ru", "https://world-cam.ru/"),
               ("ЯНАО: переправа Обь", "https://dtidh.yanao.ru/"),
               ("Connect Online", "https://connect-online.ru/"),
               ("WebcamTaxi", "https://www.webcamtaxi.com/"),
               ("SkylineWebcams", "https://www.skylinewebcams.com/")]
    def __init__(self, app, **kw):
        super().__init__(app, **kw)
        root = self.children[0]
        for name, url in self.SOURCES:
            b = Button(text=name, size_hint_y=None, height="48dp")
            b.bind(on_release=lambda _, u=url: webbrowser.open(u))
            root.add_widget(b, 1)

class ShipScreen(BaseScreen):
    SITES = [("MarineTraffic", "https://www.marinetraffic.com/"),
             ("VesselFinder", "https://www.vesselfinder.com/"),
             ("FleetMon", "https://www.fleetmon.com/"),
             ("MarineVesselTraffic", "https://www.marinevesseltraffic.com/")]
    def __init__(self, app, **kw):
        super().__init__(app, **kw)
        root = self.children[0]
        box = BoxLayout(size_hint_y=None, height="48dp", spacing=8)
        self.inp = TextInput(hint_text="Название судна / MMSI / IMO", multiline=False)
        self.inp.bind(on_text_validate=self.search)
        btn = Button(text="AIS-поиск", size_hint_x=None, width="130dp")
        btn.bind(on_release=self.search)
        box.add_widget(self.inp); box.add_widget(btn)
        root.add_widget(box, 0)
        row = BoxLayout(size_hint_y=None, height="48dp", spacing=6)
        for name, url in self.SITES:
            b = Button(text=name)
            b.bind(on_release=lambda _, u=url: webbrowser.open(u))
            row.add_widget(b)
        root.add_widget(row, 1)
        self.set_out("Ship Tracker — AIS-трекинг. Поиск по названию/MMSI/IMO откроется в браузере.")

    def search(self, *a):
        from urllib.parse import quote
        q = self.inp.text.strip()
        if q:
            webbrowser.open(f"https://www.marinetraffic.com/en/ais/index/search/all?keyword={quote(q)}")
            add_to_history("Ship", q, "AIS")

class HistoryScreen(BaseScreen):
    def __init__(self, app, **kw):
        super().__init__(app, **kw)
        root = self.children[0]
        b = Button(text="Обновить", size_hint_y=None, height="48dp")
        b.bind(on_release=lambda _: self.refresh())
        root.add_widget(b, 0)
        self.refresh()

    def refresh(self):
        h = load_history()
        if not h:
            self.set_out("История пуста"); return
        lines = [f"[{x['timestamp']}] {x['type']}: {x['query']} -> {x['result']}" for x in reversed(h)]
        self.set_out("\n".join(lines))

class ThemeScreen(Screen):
    def __init__(self, app, **kw):
        super().__init__(**kw)
        self.app = app
        root = BoxLayout(orientation="vertical", padding=8, spacing=8)
        for key, name in [("dark", "Dark"), ("light", "Light"), ("cyberpunk", "Cyberpunk"), ("matrix", "Matrix")]:
            b = Button(text=name, size_hint_y=None, height="56dp")
            b.bind(on_release=lambda _, t=key: self.app.set_theme(t))
            root.add_widget(b)
        self.add_widget(root)

# ============================ ПРИЛОЖЕНИЕ ============================
class OSINTApp(App):
    def build(self):
        self.title = "OSINT"
        self.theme = THEMES["dark"]
        Window.clearcolor = self.theme["bg"]
        sm = ScreenManager()
        self.screens = {}
        for key, cls in [("ip", IPScreen), ("phone", PhoneScreen), ("vk", VKScreen),
                         ("cams", CamScreen), ("ship", ShipScreen),
                         ("hist", HistoryScreen), ("theme", ThemeScreen)]:
            sc = cls(self, name=key)
            self.screens[key] = sc
            sm.add_widget(sc)
        root = BoxLayout(orientation="vertical")
        tabs = BoxLayout(size_hint_y=None, height="52dp", spacing=2)
        labels = [("ip", "IP"), ("phone", "Phone"), ("vk", "VK"), ("cams", "Cams"),
                  ("ship", "Ship"), ("hist", "Hist"), ("theme", "Theme")]
        for key, label in labels:
            b = Button(text=label)
            b.bind(on_release=lambda _, k=key: setattr(sm, "current", k))
            tabs.add_widget(b)
        root.add_widget(tabs)
        root.add_widget(sm, 1)
        return root

    def set_theme(self, name):
        self.theme = THEMES[name]
        Window.clearcolor = self.theme["bg"]

if __name__ == "__main__":
    OSINTApp().run()
