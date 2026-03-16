#!/user/bin/env python
"""
@Time   : 2022-01-23 17:12
@Author : LFY
@File   : config.py
"""

# here put the import lib
from enum import Enum, unique


class Config:
    def __getitem__(self, key):
        return self.__getattribute__(key)


class DefaultConfig(Config):
    MAX_PAGE_NUM = 8
    MAX_GRAPH_NUM = 1
    TAB_RUN_TIMEOUT = 30 * 1000
    EVENT_TRIGGER_INTERVAL = 500
    RESOURCE_SKIP_TYPES = ["script", "stylesheet"]
    RESOURCE_SKIP_EXTS = ["js", "css", "map"]
    # EVENT_TRIGGER_MODE = "random"
    EVENT_TRIGGER_MODE = "full"
    INLINE_EVENT_LIMIT = 100
    DOM2_EVENT_LIMIT = 200
    DOM_LOADED_TIMEOUT = 10 * 1000
    BEFORE_EXIT_DELAY = 3
    SUSPECT_URL_REGEX = r"""((?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;|*()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|)))(?:"|'))"""
    URL_REGEX = r"(((https?|ftp|file):)?//[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|])"
    CUSTOM_FORM_KEYWORD = {}
    URL_BLACKLIST_WORDS = [
        "/docs/",
        "__webpack_hmr",
        "/lib/",
        "logout",
        "loginout",
        "quit",
        "exit",
        "/node_modules",
        "/site-packages",
        "third-part",
    ]
    ACTION_BLACKLIST_WORDS = ["logout", "log out", "signout", "sign out", "exit", "quit"]
    ACTION_BLACKLIST_REGEX = []
    ACTION_BLACKLIST_ATTRS = ["id", "class", "name", "action", "formaction", "href", "onclick", "aria-label", "title"]
    DANGEROUS_ELEMENT_KEYWORDS = [
        "logout",
        "log out",
        "log-out",
        "signout",
        "sign out",
        "sign-out",
        "exit",
        "quit",
        "退出",
        "登出",
        "注销",
    ]
    DEFAULT_INPUT_VALUE = "admin"
    FILTER_MODE = "smart"
    HEADLESS_MODE = True
    PROXY = None
    LAYER = 3

    FULL_DIMENSION = 3000
    COOKIE_PATH = None
    COOKIE = None
    EXTRA_HEADER = {}


@unique
class RequestMethod(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


@unique
class HttpRequest(Enum):
    METHOD = "method"
    HEADERS = "headers"
    POST_DATA = "post_data"
    RESPONSE = "response"
    REDIRECT = "redirect_flag"


@unique
class InputTextMap(Enum):
    VERITYCODE = {
        "key": ["verifyCode"],
        "value": "1",
    }
    TAG = {
        "key": ["TAG_NAME"],
        "value": "tag_name11",
    }
    EMAIL = {
        "key": ["mail", "basic_email"],
        "value": "admin@test.com",
    }
    PHONE = {
        "key": ["phone", "number", "tel", "shouji", "手机号码"],
        "value": "18812345678",
    }
    QQ = {
        "key": ["qq", "wechat", "tencent", "weixin"],
        "value": "123456789",
    }
    ID_CARD = {
        "key": ["card", "shenfen"],
        "value": "511702197409284963",
    }
    DATE = {
        "key": ["date", "time", "year", "now"],
        "value": "2018-01-01",
    }
    NUMBER = {
        "key": ["day", "age", "num", "count"],
        "value": "10",
    }
    CODE = {
        "key": ["yanzhengma", "code", "ver", "captcha"],
        "value": "123a",
    }
    URL = {
        "key": ["url", "site", "web", "blog", "link"],
        "value": "",
    }
    ADDRESS = {
        "key": ["收货地址"],
        "value": "cnshanghai",
    }


# CHROME_BROWSER_PATH = None  # Use Playwright's bundled Chromium


# FIREFOX_BROWSER_PATH = "/Users/lfy/Library/Caches/ms-playwright/firefox-1313/firefox/Nightly.app/Contents/MacOS/firefox"
# CHROME_BROWSER_PATH = "/home/crawler/.cache/ms-playwright/chromium-1045/chrome-linux/chrome"
CHROME_BROWSER_PATH = "C:/Program Files/Google/Chrome/Application/chrome.exe"


# content-type
class ContentType(Config):
    JSON = "application/json"
    URLENCODED = "application/x-www-form-urlencoded"
    MULTIPART = "multipart/form-data"


STATIC_SUFFIX = [
    "png",
    "gif",
    "jpg",
    "mp4",
    "mp3",
    "mng",
    "pct",
    "bmp",
    "jpeg",
    "pst",
    "psp",
    "ttf",
    "tif",
    "tiff",
    "ai",
    "drw",
    "wma",
    "ogg",
    "wav",
    "ra",
    "aac",
    "mid",
    "au",
    "aiff",
    "dxf",
    "eps",
    "ps",
    "svg",
    "3gp",
    "asf",
    "asx",
    "avi",
    "mov",
    "mpg",
    "qt",
    "rm",
    "wmv",
    "m4a",
    "bin",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "doc",
    "docx",
    "odt",
    "ods",
    "odg",
    "odp",
    "exe",
    "zip",
    "rar",
    "tar",
    "gz",
    "iso",
    "rss",
    "pdf",
    "txt",
    "dll",
    "ico",
    "gz2",
    "apk",
    "crt",
    "woff",
    "map",
    "woff2",
    "webp",
    "less",
    "dmg",
    "bz2",
    "otf",
    "swf",
    "flv",
    "mpeg",
    "dat",
    "xsl",
    "csv",
    "cab",
    "exif",
    "wps",
    "m4v",
    "rmvb",
    "webm",
]

CONTENT_TYPE = [
    "application/x-www-form-urlencoded",
    "application/x-",
    "application/octet-stream",
    "application/pdf",
    "application/postscript",
    "application/atom+xml",
    "text/javascript",
    "application/ecmascript",
    "application/EDI-X12",
    "application/EDIFACT",
    "application/json",
    "application/javascript",
    "application/ogg",
    "application/rdf+xml",
    "application/rss+xml",
    "application/soap+xml",
    "application/font-woff",
    "application/xhtml+xml",
    "application/xml",
    "application/xml-dtd",
    "application/xop+xml",
    "application/zip",
    "application/gzip",
    "application/x-xls",
    "application/x-001",
    "application/x-301",
    "application/x-906",
    "application/x-a11",
    "application/vnd",
    "application/x-bmp",
    "application/x-c4t",
    "application/x-cals",
    "application/x-netcdf",
    "application/x-cel",
    "application/x-g4",
    "application/x-cit",
    "application/x-bot",
    "application/x-c90",
    "application/vnd-pki",
    "application/x-cdr",
    "application/x-x509-ca-cert",
    "application/x-cgm",
    "application/x-cmx",
    "application/pkix-crl",
    "application/x-csi",
    "application/x-cut",
    "application/x-dbm",
    "application/x-cmp",
    "application/x-cot",
    "application/x-x509-ca-cert",
    "application/x-dbf",
    "application/x-dbx",
    "application/x-dcx",
    "application/x-dgn",
    "application/x-msdownload",
    "application/msword",
    "application/x-x509-ca-cert",
    "application/x-dib",
    "application/msword",
    "application/x-drw",
    "application/x-dwf",
    "application/x-dxb",
    "application/vnd",
    "application/x-dwg",
    "application/x-dxf",
    "application/x-emf",
    "application/x-epi",
    "application/postscript",
    "application/x-msdownload",
    "application/vnd",
    "application/x-ps",
    "application/x-ebx",
    "application/fractals",
    "application/x-frm",
    "application/x-gbr",
    "application/x-g4",
    "application/x-gl2",
    "application/x-hgl",
    "application/x-hpgl",
    "application/mac-binhex40",
    "application/hta",
    "application/x-gp4",
    "application/x-hmr",
    "application/x-hpl",
    "application/x-hrf",
    "application/x-icb",
    "application/x-ico",
    "application/x-g4",
    "application/x-iphone",
    "application/x-internet-signup",
    "application/x-iff",
    "application/x-igs",
    "application/x-img",
    "application/x-internet-signup",
    "application/x-jpe",
    "application/x-javascript",
    "application/x-jpg",
    "application/x-laplayer-reg",
    "application/x-latex",
    "application/x-lbm",
    "application/x-ltr",
    "application/x-troff-man",
    "application/msaccess",
    "application/x-mac",
    "application/x-mdb",
    "application/x-shockwave-flash",
    "application/x-mi",
    "application/x-mil",
    "application/vnd-project",
    "application/vnd-project",
    "application/vnd-project",
    "application/vnd-project",
    "application/vnd-project",
    "application/x-mmxp",
    "application/x-nrf",
    "application/x-out",
    "application/x-pkcs12",
    "application/pkcs7-mime",
    "application/x-pkcs7-certreqresp",
    "application/x-pc5",
    "application/x-pcl",
    "application/vnd",
    "application/x-pgl",
    "application/vnd-pki",
    "application/pkcs10",
    "application/x-pkcs7-certificates",
    "application/pkcs7-mime",
    "application/pkcs7-signature",
    "application/x-pci",
    "application/x-pcx",
    "application/pdf",
    "application/x-pkcs12",
    "application/x-pic",
    "application/x-perl",
    "application/x-plt",
    "application/x-png",
    "application/vnd-powerpoint",
    "application/vnd-powerpoint",
    "application/x-ppt",
    "application/pics-rules",
    "application/x-prt",
    "application/postscript",
    "application/vnd-powerpoint",
    "audio/vnd-realaudio",
    "application/x-ras",
    "application/vnd-powerpoint",
    "application/x-ppm",
    "application/vnd-powerpoint",
    "application/x-pr",
    "application/x-prn",
    "application/x-ps",
    "application/x-ptn",
    "application/x-red",
    "application/vnd-realsystem-rjs",
    "application/x-rlc",
    "application/vnd-realmedia",
    "application/rat-file",
    "application/vnd-recording",
    "application/x-rgb",
    "application/vnd-realsystem-rjt",
    "application/x-rle",
    "application/vnd",
    "application/vnd-realsystem-rmj",
    "application/vnd-rn_music_package",
    "application/vnd-realmedia-vbr",
    "application/vnd-realplayer",
    "audio/x-pn-realaudio-plugin",
    "application/vnd-realmedia-secure",
    "application/vnd-realsystem-rmx",
    "application/vnd-rsml",
    "application/msword",
    "video/vnd-realvideo",
    "application/x-sat",
    "application/x-sdw",
    "application/x-slb",
    "application/x-rtf",
    "application/x-sam",
    "application/sdp",
    "application/x-stuffit",
    "application/x-sld",
    "application/smil",
    "application/x-smk",
    "application/smil",
    "application/x-pkcs7-certificates",
    "application/futuresplash",
    "application/streamingmedia",
    "application/vnd-pki",
    "application/vnd-pki",
    "application/x-tdf",
    "application/x-tga",
    "application/x-sty",
    "application/x-shockwave-flash",
    "application/x-tg4",
    "application/x-tif",
    "application/vnd",
    "application/x-vpeg005",
    "application/x-vsd",
    "application/vnd",
    "application/vnd",
    "application/vnd",
    "application/x-bittorrent",
    "application/x-vda",
    "application/vnd",
    "application/vnd",
    "application/x-vst",
    "application/vnd",
    "application/x-wb1",
    "application/x-wb3",
    "application/msword",
    "application/x-wk4",
    "application/x-wks",
    "application/x-wb2",
    "application/x-wk3",
    "application/x-wkq",
    "application/x-wmf",
    "application/x-ms-wmd",
    "application/x-wp6",
    "application/x-wpg",
    "application/x-wq1",
    "application/x-wri",
    "application/x-ws",
    "application/x-ms-wmz",
    "application/x-wpd",
    "application/vnd-wpl",
    "application/x-wr1",
    "application/x-wrk",
    "application/x-ws",
    "application/vnd",
    "application/vnd",
    "application/vnd",
    "application/vnd-excel",
    "application/x-xwd",
    "application/vnd",
    "application/x-x_t",
    "application/vnd-archive",
    "application/x-x_b",
    "application/vnd",
    "application/vnd",
    "application/x-silverlight-app",
    "application/x-xlw",
    "audio/scpls",
    "application/x-anv",
    "application/x-icq",
    "text/h323",
    "text/asa",
    "text/asp",
    "text/css",
    "text/csv",
    "text/x-component",
    "text/html",
    "text/html",
    "text/html",
    "text/webviewhtml",
    "text/html",
    "text/html",
    "text/vnd-realtext",
    "text/plain",
    "text/html",
    "text/xml",
    "text/plain",
    "text/iuls",
    "text/x-vcard",
    "text/vnd",
    "text/scriptlet",
    "text/html",
    "text/x-ms-odc",
    "text/vnd-realtext3d",
    "text/plain",
    "audio/x-mei-aac",
    "audio/aiff",
    "audio/aiff",
    "audio/aiff",
    "audio/basic",
    "audio/x-liquid-file",
    "audio/x-liquid-secure",
    "audio/x-la-lms",
    "audio/mpegurl",
    "audio/mid",
    "audio/mid",
    "audio/mp2",
    "audio/mp3",
    "audio/mp4",
    "audio/x-musicnet-download",
    "audio/mp1",
    "audio/x-musicnet-stream",
    "audio/rn-mpeg",
    "audio/scpls",
    "audio/x-pn-realaudio",
    "audio/mid",
    "audio/x-pn-realaudio",
    "audio/basic",
    "audio/wav",
    "audio/x-ms-wax",
    "audio/x-ms-wma",
    "video/x-ms-asf",
    "video/x-ms-asf",
    "video/avi",
    "video/x-ivf",
    "video/x-mpeg",
    "video/x-mpeg",
    "video/mpeg4",
    "video/x-sgi-movie",
    "video/mpeg",
    "video/mpeg4",
    "video/x-mpg",
    "video/x-mpeg",
    "video/mpg",
    "video/mpg",
    "video/x-mpeg",
    "video/mpg",
    "video/mpeg",
    "video/x-ms-wm",
    "video/x-ms-wmv",
    "video/x-ms-wmx",
    "video/x-ms-wvx",
    "image/tiff",
    "image/fax",
    "image/gif",
    "image/x-icon",
    "image/jpeg",
    "image/jpeg",
    "image/jpeg",
    "image/jpeg",
    "image/pnetvue",
    "image/png",
    "image/vnd-realpix",
    "image/tiff",
    "image/tiff",
    "image/vnd",
    "message/rfc822",
    "message/rfc822",
    "message/rfc822",
    "message/rfc822",
    "drawing/907",
    "drawing/x-slk",
    "drawing/x-top",
    "java/*",
    "java/*",
    "Model/vnd",
]

crawler_config: DefaultConfig = DefaultConfig()
