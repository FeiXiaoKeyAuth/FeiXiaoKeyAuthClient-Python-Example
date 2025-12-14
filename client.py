import requests
import json
import time
import uuid
import hashlib
import threading
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


# ============================================================
# 配置区域开始 请从作者后台 软件管理 操作按钮 那边获取相应配置 Py就是复制Python配置 C++就是复制C++配置
# ============================================================
# Python配置
API_URL = "https://feixiaokeyauth.top"
AUTHOR_ID = 2
SOFTWARE_ID = 1
SECRET_KEY = "c3a05165514d51d0ad86dc7ff4e05a44" # Hex
VERSION = "1.0"

# 安全配置
CRYPTO_TYPE = "AES"
USE_SIGNATURE = True

# RSA公钥
PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsqArxmtuGwDTPuGJd6MK
5HCsk+08loR95uWJCe/mjHaIMtpjNHvE1WQyip9QZoInQONyH+N07I0N8t/vrgb4
EuEQPbn3xRgbDdSBb/WTZ8vTAm1rr8UoDC2+bFNqehhqT3vSscGpbyCmBloNjdTH
U5fwvR1p1UYejPiCbu/t3G6jIbaOX6lUcmKdNOQsB70ZIzmXWlCHIi5fdGEckMQr
Eo1P+/2je+AY1eu/SDCe7iKclimCsyQJw1+q05ps+NjJE9XUZH5r4GzeVw8vY/yA
ayoEY2rLFC8fD8e/eMF17oxn2ZMIaB8ZNI6peLaB5ckfO44ECSQzDoM72In+vuai
QQIDAQAB
-----END PUBLIC KEY-----"""


# ============================================================
# 配置区域结束
# ============================================================



# ============================================================
# 客户端
# ============================================================

class KeyAuthClient:
    def __init__(self):
        self.session_id = ""
        self.token = ""
        self.last_license = ""      # 上次登录卡密
        self.last_error = ""        # 最近错误码

        self.secret_key = bytes.fromhex(SECRET_KEY)
        self.hwid = self._get_hwid()

        self.rsa_key = RSA.import_key(PUBLIC_KEY_PEM)

        self.running = False
        self.thread = None
        self.lock = threading.Lock()

        print(f"   [验证] KeyAuth 初始化完成 (HWID: {self.hwid})")

    # ------------------------------
    # 工具
    # ------------------------------
    def _get_hwid(self):
        mac = uuid.getnode()
        return hashlib.md5(mac.to_bytes(6, "big")).hexdigest()

    def _timestamp(self):
        return int(time.time())

    def _nonce(self):
        return uuid.uuid4().hex

    def _is_token_error(self, err: str):
        err = err.lower()
        return (
            "invalid token" in err or
            "session timeout" in err or
            "session expired" in err
        )
    def _build_aad(self):
        return f"author={AUTHOR_ID}|software={SOFTWARE_ID}".encode()


    # ------------------------------
    # 加解密
    # ------------------------------
    def _encrypt_payload(self, data):
        raw = json.dumps(data, separators=(",", ":")).encode()

        if CRYPTO_TYPE.upper() == "PLAIN":
           return raw.hex(), ""

        nonce = get_random_bytes(12)
        cipher = AES.new(self.secret_key, AES.MODE_GCM, nonce=nonce)

        cipher.update(self._build_aad())

        ciphertext, tag = cipher.encrypt_and_digest(raw)

        return (ciphertext + tag).hex(), nonce.hex()


    def _decrypt_payload(self, data_hex, iv_hex):
        if CRYPTO_TYPE.upper() == "PLAIN":
            return json.loads(bytes.fromhex(data_hex).decode())

        data = bytes.fromhex(data_hex)
        nonce = bytes.fromhex(iv_hex)

        if len(nonce) != 12:
            raise ValueError("invalid GCM nonce length")

        cipher = AES.new(self.secret_key, AES.MODE_GCM, nonce=nonce)

        cipher.update(self._build_aad()) 

        ciphertext = data[:-16]
        tag = data[-16:]

        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return json.loads(plaintext.decode())


    def _verify_signature(self, data_hex, sig_hex):
        if not USE_SIGNATURE:
            return True
        try:
            h = SHA256.new(bytes.fromhex(data_hex))
            pkcs1_15.new(self.rsa_key).verify(h, bytes.fromhex(sig_hex))
            return True
        except:
            return False

    # ------------------------------
    # 通用请求
    # ------------------------------
    def send_request(self, endpoint, inner, max_retry=3):
        self.last_error = ""

        for attempt in range(1, max_retry + 1):
            try:
                inner["timestamp"] = self._timestamp()
                nonce = self._nonce()
                inner["nonce"] = nonce

                data_hex, iv_hex = self._encrypt_payload(inner)

                payload = {
                    "author_id": AUTHOR_ID,
                    "software_id": SOFTWARE_ID,
                    "data": data_hex,
                    "iv": iv_hex,
                    "signature": "",
                }

                HEADERS = {
                "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
                ),
                "Content-Type": "application/json",
                "Accept": "application/json"
}


                r = requests.post(
                API_URL + endpoint,
                json=payload,
                headers=HEADERS,
                timeout=30
                )

                res = r.json()

                if "error" in res:
                    self.last_error = res["error"]
                    print("   [服务器错误]", res["error"])
                    return None

                if "data" not in res:
                    self.last_error = "protocol error"
                    return None

                if USE_SIGNATURE:
                    if not self._verify_signature(res["data"], res.get("sign", "")):
                        self.last_error = "signature failed"
                        return None

                dec = self._decrypt_payload(res["data"], res.get("iv", ""))

                if dec.get("nonce") != nonce:
                    print("   [严重安全警告] 遭到重放攻击！Nonce 不匹配！")
                    sys.exit(1)

                return dec

            except Exception as e:
                print(f"   [网络错误] ({attempt}/{max_retry})", e)
                self.last_error = "network error"
                if attempt == max_retry:
                    return None
                time.sleep(30)

    # ------------------------------
    # 登录
    # ------------------------------
    def login(self, license_key):
        req = {
        "license": license_key,
            "hwid": self.hwid,
            "version": VERSION,
        }

        res = self.send_request("/api/client/login", req)
        if not res:
            return False

        self.session_id = res["session_id"]
        self.token = res["token"]
        self.last_license = license_key

        print("   [验证] 登录成功")

        if "announcement" in res:
            print("   [公告]", res["announcement"])

        # 版本检查
        cloud_ver = res.get("latest_version", "")

        if not cloud_ver:
            print("   [更新] 无法获取服务器版本号，跳过更新")
        elif cloud_ver != VERSION:
            print("   [更新] 发现新版本！请更新客户端！")
            print(f"   [更新] 当前版本：{VERSION}  →  最新版本：{cloud_ver}")

            if "download_url" in res:
                print(f"   [更新] 下载链接：{res['download_url']}")
        else:
            print("   [更新] 客户端已是最新版本")

        if "expiry" in res:
            dt = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(res["expiry"]))
            print("   [到期时间]", dt)

        return True
    
    # ------------------------------
    # 获取远程变量
    # ------------------------------
    def get_var(self, key):
        req = {"session_id": self.session_id, "var_key": key}
        res = self.send_request("/api/client/get_var", req)
        return res.get("var_value", "") if res else ""


    # ------------------------------
    # 心跳线程
    # ------------------------------
    def _heartbeat_once(self):
        req = {"session_id": self.session_id, "token": self.token}
        return self.send_request("/api/client/heartbeat", req)

    def _heartbeat_loop(self, interval):
        while self.running:
            res = self._heartbeat_once()

            if not res:
                # token 错误 自动重登一次 再心跳一次
                if self._is_token_error(self.last_error) and self.last_license:
                    with self.lock:
                        print("   [心跳] token 异常，尝试重新登录")
                        if self.login(self.last_license):
                            print("   [心跳] 重登成功，重试心跳")
                            res = self._heartbeat_once()
                            if not res:
                                print("   [心跳] 重登后仍失败")
                                break
                        else:
                            print("   [心跳] 重登失败")
                            break
                else:
                    print("   [心跳] 失败，停止心跳")
                    break

            next_token = res.get("next_token")

            server_time = res.get("server_time", 0)

            self.token = next_token

            print(f"   [心跳] OK | token={self.token} | server_time={server_time}")

            time.sleep(interval)

        self.running = False

    def start_keep_alive(self, interval_ms=60000):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(
            target=self._heartbeat_loop,
            args=(interval_ms / 1000,),
            daemon=True
        )
        self.thread.start()

    def stop_keep_alive(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)


# ============================================================
# 主入口
# ============================================================

if __name__ == "__main__":
    client = KeyAuthClient()

    key = input("   [验证] 请输入卡密：")

    if client.login(key):
        v = client.get_var("test233")
        print("   [远程变量] =", v)

        # 心跳间隔建议设置为 30 秒以上，防止被Cloudflare拉黑。
        client.start_keep_alive(30000)

        input("   按回车退出...\n")
        client.stop_keep_alive()
    else:
        print("   [验证] 登录失败")
