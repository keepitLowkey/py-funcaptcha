import requests
import random
import time
from urllib.parse import urlsplit
from requests.packages.urllib3.exceptions import InsecureRequestWarning
## For image manipulation
from PIL import Image
from io import BytesIO
## Modules for encryption and decryption
from Crypto.Cipher import AES
import base64
import hashlib
import json
import string
import re
import execjs
import secrets


## Default params
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0"
## Decides if images should be downloaded over the specified proxy or not
## Turning this off improves speed
PROXY_IMAGE_DOWNLOADS = False

## Load .js module for murmur3 related functions (used in BDA/fingerprint2 generation)
with open("fp.js") as f:
    js_source = f.read()
    mm3js = execjs.compile(js_source)


## Create dict of fields from full token string
def parse_full_token(token):
    token = "token=" + token
    assoc = {}

    for field in token.split("|"):
        s = field.partition("=")
        key, value = s[0], s[-1]
        assoc[key] = value
    
    return assoc


## Get random float value
def get_float():
    return random.uniform(0, 1)


## Get random X,Y click coordinates for button
def get_xy():
    start_pos = [117, 248]
    button_size = [90, 28]
    new_pos = [
        start_pos[0] + random.randint(1, button_size[0]),
        start_pos[1] + random.randint(1, button_size[1])]
    return new_pos


## CryptoJS AES Encryption
def cryptojs_encrypt(data, key):
    # Padding
    data = data + chr(16-len(data)%16)*(16-len(data)%16)

    salt = b"".join(random.choice(string.ascii_lowercase).encode() for x in range(8))
    salted, dx = b"", b""
    while len(salted) < 48:
        dx = hashlib.md5(dx+key.encode()+salt).digest()
        salted += dx

    key = salted[:32]
    iv = salted[32:32+16]
    aes = AES.new(key, AES.MODE_CBC, iv)

    encrypted_data = {"ct": base64.b64encode(aes.encrypt(data.encode())).decode("utf-8"), "iv": iv.hex(), "s": salt.hex()}
    return json.dumps(encrypted_data, separators=(',', ':'))


## CryptoJS AES Decryption
def cryptojs_decrypt(data, key):
    data = json.loads(data)
    dk = key.encode()+bytes.fromhex(data["s"])

    md5 = [hashlib.md5(dk).digest()]
    result = md5[0]
    for i in range(1, 3+1):
        md5.insert(i, hashlib.md5((md5[i-1]+dk)).digest())
        result += md5[i]
    
    aes = AES.new(result[:32], AES.MODE_CBC, bytes.fromhex(data["iv"]))
    data = aes.decrypt(base64.b64decode(data["ct"]))
    return data


class FunCaptchaChallenge():
    images = None
    metadata = {}
    
    ## Set up challenge object
    def __init__(self, session, bda, full_token, session_token, region, lang, analytics_tier, download_images=True):
        self.session = session
        self.bda = bda
        self.full_token = full_token
        self.session_token = session_token
        self.region = region
        self.lang = lang
        self.analytics_tier = analytics_tier
        self.download_images = download_images
        self.send_analytics(render_type="canvas", sid=self.region, category="Site URL", analytics_tier=self.analytics_tier, session_token=self.session_token, action=self.session.page_url)
        self.reload(status="init")

    
    ## Reload the challenge
    def reload(self, status):
        r_resp = self.session.r.post(
            url=f"{self.session.service_url}/fc/gfct/",
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "cache-control": "no-cache",
                "X-Requested-ID": self.get_request_id(),
                "Origin": self.session.service_url, 
                "Referer": self.session.service_url + "/fc/gc"},
            data={
                "analytics_tier": self.analytics_tier,
                "render_type": "canvas",
                "lang": self.lang,
                "sid": self.region,
                "token": self.session_token,
                "data[status]": status}).json()

        self.metadata = {}
        self.token = r_resp["challengeID"]
        self.id = r_resp["challengeURL"]
        self.timeout = r_resp["sec"]
        self.angle = 51.4
        self.encrypted_mode = bool(r_resp["game_data"]["customGUI"]["encrypted_mode"])
        self.image_urls = r_resp["game_data"]["customGUI"]["_challenge_imgs"]

        if self.image_urls:
            ## Preload images
            if self.download_images:
                self.images = list(map(self.download_image, self.image_urls))
            
            self.send_analytics(render_type="canvas", sid=self.region, category="loaded", game_token=self.token, analytics_tier=self.analytics_tier, game_type=1, session_token=self.session_token, action="game loaded")
    
            ## Get encryption key, if needed
            if self.encrypted_mode:
                self.key = self.get_encryption_key()
                self.send_analytics(render_type="canvas", sid=self.region, category="begin app", game_token=self.token, analytics_tier=self.analytics_tier, game_type=1, session_token=self.session_token, action="user clicked verify")


    ## This is some sort of weird metadata that's sent in
    ## the X-Requested-ID header
    def update_metadata(self, origin, value=None):
        if origin == "ekey" and not self.metadata.get("sc"):
            self.metadata["sc"] = get_xy()
        
        elif origin == "guess" and not self.metadata.get("dc"):
            self.metadata["dc"] = get_xy()
        
        elif origin == "lastguess" and value:
            self.metadata["ech"] = "{:.2f}".format(value)
    
    
    ## Send analytics logging request
    def send_analytics(self, **kwargs):
        an_resp = self.session.r.post(
            url=f"{self.session.service_url}/fc/a/",
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "cache-control": "no-cache",
                "X-Requested-ID": self.get_request_id(),
                "Origin": self.session.service_url, 
                "Referer": self.session.service_url + "/fc/gc"},
            data={
                **kwargs}).json()

        return an_resp.get("logged")
    

    ## Submit guesses
    def submit_guesses(self, guesses):
        data = ",".join(map(lambda x: "{:.2f}".format(x), guesses))
        encrypted_data = cryptojs_encrypt(data, self.session_token)

        if len(guesses) == len(self.image_urls):
            self.update_metadata(origin="lastguess", value=guesses[-1])
        else:
            self.update_metadata(origin="guess")
        
        sg_resp = self.session.r.post(
            url=f"{self.session.service_url}/fc/ca/",
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "cache-control": "no-cache",
                "X-Requested-ID": self.get_request_id(),
                "Origin": self.session.service_url, 
                "Referer": self.session.service_url + "/fc/gc"},
            data={
                "game_token": self.token,
                "session_token": self.session_token,
                "sid": self.region,
                "guess": encrypted_data,
                "analytics_tier": self.analytics_tier}).json()
        
        ## Update encryption key if response contains one
        if "decryption_key" in sg_resp:
            self.key = sg_resp["decryption_key"]
        
        ## Return status of challenge
        return sg_resp.get("solved")


    ## Download image data from url
    def download_image(self, image_url):
        i_resp = (self.session.r if PROXY_IMAGE_DOWNLOADS else requests).get(
            url=image_url,
            headers={
                "Referer": f"{self.session.service_url}/fc/apps/canvas/{self.id}/?meta=6"})
        return i_resp.content
    

    ## Get encryption key for the first image
    def get_encryption_key(self):
        self.update_metadata(origin="ekey")

        ek_resp = self.session.r.post(
            url=f"{self.session.service_url}/fc/ekey/",
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "cache-control": "no-cache",
                "X-Requested-ID": self.get_request_id(),
                "Origin": self.session.service_url, 
                "Referer": f"{self.session.service_url}/fc/gc"},
            data={
                "game_token": self.token,
                "sid": self.region,
                "session_token": self.session_token}).json()
        
        return ek_resp["decryption_key"]
    

    ## Generates value for X-Requested-ID header
    def get_request_id(self):
        key = "REQUESTED" + self.session_token + "ID"
        data = json.dumps(self.metadata, separators=(',', ':'))
        return cryptojs_encrypt(data, key)


    def get_iter(self):
        guesses = []
        images_enabled = self.download_images
        for img_data in self.images or self.image_urls:
            img = None
            if images_enabled:
                img_data = cryptojs_decrypt(img_data, self.key)
                img = Image.open(BytesIO(img_data))
            def submit(guess):
                guesses.append(guess)
                return self.submit_guesses(guesses)
            yield img, submit


class FunCaptchaSession:
    ## Set up session object
    def __init__(self, public_key, service_url, page_url, proxy=None, download_images=True, verify=True, timeout=15):
        self.public_key = public_key
        self.service_url = service_url.rstrip("/")
        self.page_url = page_url.rstrip("/")
        self.site_url = "https://" + urlsplit(self.page_url).netloc
        self.user_agent = DEFAULT_USER_AGENT
        self.download_images = download_images

        ## Create and set-up requests.Session() object
        self.r = requests.session()
        if proxy: self.r.proxies = {"http": proxy, "https": proxy}
        self.r.timeout = timeout
        self.r.headers["User-Agent"] = self.user_agent
        self.r.headers["Accept"] = "*/*"
        self.r.headers["Accept-Language"] = "en-US,en;q=0.5"
        self.r.headers["Accept-Encoding"] = "gzip, deflate, br"
        ## Disable SSL validation (for debugging)
        if not verify:
            self.r.verify = False
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    

    ## Get base64-encoded string of browser data for identification
    ## So far this is all that is needed for not getting blocked
    ## Over time the canvas int thing may get blocked, so try randomizing that
    def get_browser_data(self):
        ## Calculate encryption key
        ts = time.time()
        timeframe = int(ts - (ts % 21600))
        key = self.user_agent + str(timeframe)

        ## Data
        data = []
        data.append({"key": "api_type", "value": "js"})
        data.append({"key": "p", "value": 1})

        ## Fingerprint
        fonts = "Arial,Arial Black,Arial Narrow,Book Antiqua,Bookman Old Style,Calibri,Cambria,Cambria Math,Century,Century Gothic,Century Schoolbook,Comic Sans MS,Consolas,Courier,Courier New,Garamond,Georgia,Helvetica,Impact,Lucida Bright,Lucida Calligraphy,Lucida Console,Lucida Fax,Lucida Handwriting,Lucida Sans,Lucida Sans Typewriter,Lucida Sans Unicode,Microsoft Sans Serif,Monotype Corsiva,MS Gothic,MS PGothic,MS Reference Sans Serif,MS Sans Serif,MS Serif,Palatino Linotype,Segoe Print,Segoe Script,Segoe UI,Segoe UI Light,Segoe UI Semibold,Segoe UI Symbol,Tahoma,Times,Times New Roman,Trebuchet MS,Verdana,Wingdings,Wingdings 2,Wingdings 3".split(",")
        plugins = "Chrome PDF Plugin,Chrome PDF Viewer,Native Client".split(",")
        canvas_fp = -1424337346

        fe = [
            ## DoNotTrack flag
            "DNT:unknown",
            ## Language
            "L:en-US",
            ## Depth
            "D:24",
            ## Pixel ratio
            "PR:1",
            ## Screen resolution
            "S:1920,1080",
            ## Available screen resolution (browser window size)
            "AS:1920,1040",
            ## Time offset
            "TO:-120",
            ## Session storage enabled
            "SS:true",
            ## Local storage enabled
            "LS:true",
            ## Indexed DB enabled
            "IDB:true",
            ## .addBehaviour enabled - https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms535922(v%3Dvs.85)
            "B:false",
            ## OpenDB enabled
            "ODB:true",
            ## CPU class
            "CPUC:unknown",
            ## Platform key
            "PK:Win32",
            ## Canvas fingerprint
            "CFP:" + str(canvas_fp),
            ## Has fake resolution
            "FR:false",
            ## Has fake OS
            "FOS:false",
            ## Has fake browser
            "FB:false",
            ## Javascript fonts
            "JSF:" + ",".join(fonts),
            ## Plugin keys
            "P:" + ",".join(plugins),
            ## Touch
            "T:0,false,false",
            ## navigator.hardwareConcurrency enabled
            "H:8",
            ## Flash enabled
            "SWF:false"]
        
        ## Calculate hashes
        ## I haven't managed to replicate fp hashes yet, so it's just filled with a random value for now
        fp = secrets.token_hex(16)
        ife_hash = mm3js.call("x64hash128", ", ".join(fe), 38)

        ## Window hash
        ## This cannot be verified by the server, so it's just a random value for now
        wh = secrets.token_hex(16) + "|" + secrets.token_hex(16)
        
        ## Additional data
        data.append({"key": "f", "value": fp})
        data.append({"key": "n", "value": base64.b64encode(str(int(ts)).encode("utf-8")).decode("utf-8")})
        data.append({"key": "wh", "value": wh})
        data.append({"key": "fe", "value": fe})
        data.append({"key": "ife_hash", "value": ife_hash})
        data.append({"key": "cs", "value": 1})
        data.append({"key": "jsbd", "value": '{"HL":28,"NCE":true,"DA":null,"DR":null,"DMT":31,"DO":null,"DOT":31}'})

        data = json.dumps(data, separators=(',', ':'))
        data = cryptojs_encrypt(data, key)
        data = base64.b64encode(data.encode("utf-8")).decode("utf-8")
        return data


    ## Get new challenge
    def new_challenge(self):
        bda = self.get_browser_data()
        rnd = get_float()
        nc_resp = self.r.post(
            url=f"{self.service_url}/fc/gt2/public_key/{self.public_key}",
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Origin": self.site_url,
                "Referer": self.page_url},
            data={
                "bda": bda,
                "public_key": self.public_key,
                "site": self.site_url,
                "userbrowser": self.user_agent,
                "simulate_rate_limit": 0,
                "simulated": 0,
                "language": "en",
                "rnd": rnd}).json()

        ## Create FunCaptchaChallenge object based on data
        ## returned by /fc/gc/public_key/{pk}
        full_token = nc_resp["token"]
        data = parse_full_token(full_token)
        return FunCaptchaChallenge(
            session=self,
            bda=bda,
            full_token=full_token,
            session_token=data["token"],
            region=data["r"],
            lang=data["lang"],
            analytics_tier=int(data["at"]),
            download_images=self.download_images)


## Testing stuff
if __name__ == "__main__":
    s = FunCaptchaSession(
        public_key="9F35E182-C93C-EBCC-A31D-CF8ED317B996",
        service_url="https://roblox-api.arkoselabs.com",
        page_url="https://www.roblox.com/login")
    ch = s.new_challenge()

    print("Full Token ::", ch.full_token)
    print("Session Token ::", ch.session_token)
    print("Challenge Token ::", ch.token)
    print("# of Images ::", len(ch.image_urls))

    for image, submit in ch.get_iter():
        image.show()
        solved = submit(51.4)
    
    print("Solved ::", solved)

    input("Press any key to exit ..")