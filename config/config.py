import os

# 甯哥敤閰嶇疆閫夐」
SUPPORTED_CMS = [
    "newbee_mall",
    "xmall",
    "icecms",
    "snipe-it",
    "collabtive",
    "memos",
    "joomal",
    "inlong",
    "PrestaShop",
    "wordpress",
    "webid",
]
DEFAULT_CMS = (os.getenv("BACSCAN_CMS") or "memos").strip() or "memos"
# Backward compatibility export for legacy imports.
CMS_LIST = [DEFAULT_CMS]

Black_list = ["goods", "book", "register", "logout", "help", "search", "news", "index", "browse", "Setting",
              "undefined",
              "download", "thanks"]


class Config:
    def __init__(self):
        self.ES_ADDR = 'https://10.176.36.21:9200'
        self.ES_USER = 'elastic'
        self.ES_PASS = 'jV*478mJjn11+L33QlNO'
        self.OPERATE_METHOD_LIST = ["POST", "PATCH", "DELETE", "PUT", "FETCH"]
        self.URLENCODED_POST_DATA_TYPE = ["application/x-www-form-urlencoded",
                                          'application/x-www-form-urlencoded; charset=UTF-8']
        self.JSON_POST_DATA_TYPE = ["application/json;charset=UTF-8", "application/json"]
        self.CONTENT_LENGTH_HEADER = "content-length"
        self.CONTENT_TYPE_HEADER = "content-type"
        self.REDIRECT_KEY = "redirect"
        self.REPLAY_ERROR_MARKERS = [
            r"\b404\s+not\s+found\b",
            r"\b500\s+internal\s+server\s+error\b",
            r"\b(status|code|status_code|error_code)\s*[:=]\s*404\b",
            r"\b(status|code|status_code|error_code)\s*[:=]\s*500\b",
            r"\bnot\s+found\b",
            r"\bnot\s+valid\b",
            r"\binvalid\s+id\b",
            r"\bnot\s+exist\b",
            r"\berrurl\b",
        ]
        self.DELETE_ERROR_MARKERS = list(self.REPLAY_ERROR_MARKERS)
        self.INPUT_STRING_LIST = ["title", "text", "content", "remark", "address", "username", "nickname", "streetName",
                                  "desc"]
        self.NOT_INPUT_STRING_LIST = ["size", "type", "color", "full"]
        self.INPUT_NUM_LIST = ["num"]
        self.EMAIL_FIELD_KEYWORDS = ["email", "e-mail", "mail"]
        self.EMAIL_DOMAIN = "gmail.com"
        self.AUTH_URL_KEYWORDS = ["login", "signin", "sign-in", "signup", "sign-up", "register", "logout"]
        self.AUTH_PARAM_KEYWORDS = ["password", "passwd", "pwd"]
        self.TOKEN_FALLBACK_PARAM = "__sec_auto_token"
        self.TOKEN_APPEND_IF_MISSING = False
        self.SESSION_NAME_MAP = {
            "token": "authorization",
            "access-admin": "authorization",
        }
        self.SESSION_VALUE_JSON_KEYS = ["token", "access_token", "jwt"]
        self.HEADER_TOKEN_KEYS = ["authorization", "x-csrf-token"]
        self.HEADER_COOKIE_MAP = {
            "x-csrf-token": ["XSRF-TOKEN", "csrf_token", "xsrf-token"],
        }
        self.COOKIE_APPEND_MISSING = False
        self.HTML_FAILURE_MARKERS = ["vite-legacy", "vite-legacy-polyfill", "vite-legacy-entry",
                                     "__vite_is_modern_browser"]
        self.HTML_FAILURE_ROOT_IDS = ["root", "app"]
        self.HTML_FAILURE_REQUIRE_API = True
        self.HTML_FAILURE_REQUIRE_ROOT = True
        self.DOM_VECTOR_DIMENSION = 300
        self.DOM_FULL_DIMENSION = 3000
        self.DOM_VECTOR_MIN_LEN = 10
        self.DOM_SIMILARITY_THRESHOLD = 0.95
        self.DOM_WEIGHT_DIVISOR = 0.02
        self.DOM_INITIAL_WEIGHT = 1
        self.DOM_ATTENUATION_RATIO = 0.6
        self.JSON_SIMILARITY_THRESHOLD = 0.95
        self.JSON_SIMILARITY_MISMATCH_PENALTY = 0.8
        self.SIGNATURE_IGNORE_QUERY_KEYS = ["page", "limit", "offset", "size", "sort", "order"]
        self.SIGNATURE_IGNORE_BODY_KEYS = ["csrf", "_csrf", "_token", "token"]
        self.SIGNATURE_ID_QUERY_KEYS = ["id", "uid", "user_id", "userid", "memoid", "itemid"]
        self.SIGNATURE_VALUE_QUERY_KEYS = ["type", "status", "action", "visibility"]
        self.SIGNATURE_VALUE_BODY_KEYS = ["type", "status", "action", "visibility"]
        self.SIGNATURE_ID_REGEX = [
            r"^\d+$",
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
            r"^[0-9a-fA-F]{16,}$",
        ]
        self.VISITOR = "visitor"
        self.USER_ROLE = "user"
        self.ADMIN_ROLE = "admin"
        self.DET_USER_ROLE = "det_user"
        self.ROOT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.TOKEN_KEY_LIST = ["token", "session", "openemr", "hmaccount"]
        self.CMS = DEFAULT_CMS
        self._initialize_paths()

    def _initialize_paths(self):
        self.USER_COOKIE_PATH = f"{self.ROOT_PATH}/auth/{self.CMS}/user_nav.json"
        self.USER_DET_COOKIE_PATH = f"{self.ROOT_PATH}/auth/{self.CMS}/user_det.json"
        self.ADMIN_COOKIE_PATH = f"{self.ROOT_PATH}/auth/{self.CMS}/admin_nav.json"
        self.NAV_GRAPH_DIR = f"{self.ROOT_PATH}/vuln_detection/input/nav_graphs/{self.CMS}/"
        self.ROLE_NAVIGRAPH_PATH = f"{self.NAV_GRAPH_DIR}{{}}_navigraph.json"
        self.DATA_DEPENDENCE_PATH = f"{self.ROOT_PATH}/vuln_detection/input/data_dependence/{self.CMS}.json"
        self.CONTROLLABLE_ID_PATH = f"{self.ROOT_PATH}/vuln_detection/input/controllable_id/{self.CMS}.json"
        self.CONTROLLABLE_PARAM_PATH = f"{self.ROOT_PATH}/vuln_detection/input/controllable_id/{self.CMS}_params.json"
        self.MERGE_NAVIGRAPH_PATH = f"{self.ROOT_PATH}/vuln_detection/input/merged_navigraph/{self.CMS}.json"
        self.XPATH_CLUSTER_PATH = f"{self.ROOT_PATH}/vuln_detection/input/XPath_cluster/{self.CMS}.json"
        self.SIM_PUBLIC_ELEMENTS = f"{self.ROOT_PATH}/vuln_detection/input/sim_public_elements/{self.CMS}.json"
        # self.VERTICAL_RESULT_PATH = f"{self.ROOT_PATH}/result/vertical_result.json"
        # self.HORIZONTAL_RESULT_PATH = f"{self.ROOT_PATH}/result/horizontal_result.json"
        self.RESULT_CSV_PATH = f"{self.ROOT_PATH}/result/result.csv"
        self.RESULT_JSON_PATH = f"{self.ROOT_PATH}/result/vuln_result.json"

    def set_cms(self, cms):
        self.CMS = cms
        self._initialize_paths()


vuln_scan_config = Config()
