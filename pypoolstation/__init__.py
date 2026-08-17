import json
import aiohttp
from aiohttp import ClientError, ClientResponseError
import logging
from datetime import datetime
import hashlib
import random
import time
import base64

DOMAIN = 'https://api.poolstation.net'
LOGIN_URL = DOMAIN + '/session/login'
POOL_LIST_URL = DOMAIN + '/devices/10/0'
POOL_INFO_URL = DOMAIN + '/devices/'
UPDATE_URL = DOMAIN + '/devices/saveSign'

# Default timeout applied to every HTTP request made by this library.
DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=30)

# HTTP statuses treated as "invalid/expired token, re-login required".
AUTH_ERROR_STATUSES = (401, 403, 410)

API_SIGNS = {
    "temperature": "ta",
    "salt_concentration": "cn",
    "current_ph": "mp",
    "target_ph": "sp",
    "current_orp": "mo",
    "target_orp": "so",
    "current_clppm": "mh",
    "target_clppm": "sh",
    "percentage_electrolysis": "pa",
    "target_percentage_electrolysis": "sn",
    "binary_input_1": "d1",
    "binary_input_2": "d2",
    "binary_input_3": "d3",
    "binary_input_4": "d4",
    "binary_input_1_name": "d1_name",
    "binary_input_2_name": "d2_name",
    "binary_input_3_name": "d3_name",
    "binary_input_4_name": "d4_name",
    "waterflow": "ac",
    "uv_available": "lu",
    "current_uv_timer": "hu",
    "total_uv_timer": "xu",
    "uv_ballast": "bu",
    "uv_fuse": "fu",
}

class Account:
    def __init__(self, session, username="", password="", token=None, logger=logging) -> None:
        self._session = session
        self._username = username
        self._password = password
        self._token = token
        self.logger = logger


    async def token(self):
        if self._token: return self._token
        return await self.login()

    async def login(self, login_code=""):
        self.logger.debug("Account attempting to log in")
        current_date = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        async with self._session.post(LOGIN_URL, json={
            "username": self._username, 
            "password": self._password, 
            "remember": True, 
            "connectdate": current_date,
            "login_code": login_code
        }, timeout=DEFAULT_TIMEOUT) as resp:
            if resp.status == 410:
                data = await resp.json()
                if data.get("error_code") == "REQUEST_LOGIN_CODE":
                    raise TwoFactorAuthRequiredException('2FA login code required')
                raise AuthenticationException('Authentication failed: 410 Gone')
            if resp.status == 401:
                raise AuthenticationException('Authentication failed')
            resp.raise_for_status()
            data = await resp.json()
            self.logger.debug("Account logged in successfully")
            self._token = data["token"]
            return self._token

    def get_auth_headers(self):
        """Get the authentication headers for API requests.
        Returns a tuple of (encoded_token, md5_hash)"""
        if not self._token:
            return "", ""
            
        self.logger.debug("Generating new auth headers for request")
        encoded_token, md5_hash = get_auth_headers(self._token)
        self.logger.debug(f"Generated Authorization header: Bearer {encoded_token}")
        self.logger.debug(f"Generated Q header: {md5_hash}")
        return encoded_token, md5_hash

class Pool:
    @classmethod
    async def get_all_pools(cls, session, username="", password="", account = None):
        if not account:
            account = Account(session, username=username, password=password)
        token = await account.token()
        account.logger.debug("Fetching all pools on the account")
        try:
            encoded_token, md5_hash = account.get_auth_headers()
            account.logger.debug(f"Sending request to {POOL_LIST_URL}")
            account.logger.debug("Request headers:")
            account.logger.debug(f"  Authorization: Bearer {encoded_token}")
            account.logger.debug(f"  Q: {md5_hash}")
            
            async with session.post(
                    POOL_LIST_URL,
                    data="",
                    headers={
                        "accept": "application/json", 
                        "content-type": "application/x-www-form-urlencoded",
                        "Authorization": f"Bearer {encoded_token}",
                        "Q": md5_hash
                    },
                    timeout=DEFAULT_TIMEOUT
            ) as resp:
                account.logger.debug(f"Response status: {resp.status}")
                if resp.status != 200:
                    account.logger.debug(f"Response body: {await resp.text()}")
                resp.raise_for_status()
                data = await resp.json()
                account.logger.debug(f"Account pools retrieved successfully. Number of pools: {len(data['items'])}")
                return [Pool(session, token, item['id'], account.logger) for item in data["items"]]

        except ClientResponseError:
            raise AuthenticationException("Request failed. Maybe token has expired.")

    def __init__(self, session, token, id, logger):
        self._session = session
        self._token = token
        self.id = id
        self.alias = None
        self.temperature = None
        self.salt_concentration = None
        self.current_ph = None
        self.target_ph = None
        self.current_orp = None
        self.target_orp = None
        self.current_clppm = None
        self.target_clppm = None
        self.percentage_electrolysis = None
        self.target_percentage_electrolysis = None
        self.relays = []
        self.binary_input_1 = None
        self.binary_input_1_name = None
        self.binary_input_2 = None
        self.binary_input_2_name = None
        self.binary_input_3 = None
        self.binary_input_3_name = None
        self.binary_input_4 = None
        self.binary_input_4_name = None
        self.waterflow_problem = None
        self.logger = logger
        self.uv_available = None

        self.uv_on = None
        self.uv_enabled = None

        self.current_uv_timer = None
        self.total_uv_timer = None
        self.uv_ballast_problem = None
        self.uv_fuse_problem = None
        self.raw_vars = {}

    def update_token(self, token):
        """Replace the API token used for subsequent requests.

        Lets a caller inject a freshly obtained token (e.g. after a re-login)
        without having to rebuild the Pool object."""
        self._token = token

    async def post(self, url, data=""):
        encoded_token, md5_hash = get_auth_headers(self._token)
        async with self._session.post(
            url,
            data=data,
            headers={
                "accept": "application/json", 
                "content-type": "application/x-www-form-urlencoded",
                "Authorization": f"Bearer {encoded_token}",
                "Q": md5_hash
            },
            timeout=DEFAULT_TIMEOUT
        ) as resp:
            try:
                resp.raise_for_status()
            except ClientResponseError as err:
                if err.status in AUTH_ERROR_STATUSES:
                    raise AuthenticationException("Request failed. Maybe token has expired.") from err
                # Let any other HTTP error (500, 504, ...) surface as-is so
                # callers can distinguish server errors from auth failures.
                raise
            return await resp.json()

    async def sync_info(self):
        self.logger.debug(f"Updating pool info for pool with id {self.id}")
        info = await self.post(POOL_INFO_URL + str(self.id))
        self.alias = info.get("alias")
        self.raw_vars = info.get("vars") or {}
        v = self.raw_vars

        def to_float(sign, strip_trailing_char=False):
            """Parse a numeric var, returning None if missing or malformed."""
            raw = v.get(sign)
            if raw is None:
                return None
            if strip_trailing_char and raw:
                # Some values arrive padded with a trailing space/unit char.
                raw = raw[:-1]
            try:
                return float(raw)
            except (ValueError, TypeError):
                return None

        def to_int(sign):
            raw = v.get(sign)
            try:
                return int(raw)
            except (ValueError, TypeError):
                return None

        # Individual sensors are parsed independently so a single missing or
        # malformed value never breaks the whole sync (people have reported
        # values being missing from time to time).
        self.temperature = to_float(API_SIGNS["temperature"], strip_trailing_char=True)  # in °C
        self.salt_concentration = to_float(API_SIGNS["salt_concentration"], strip_trailing_char=True)  # in gr/l
        self.current_ph = to_float(API_SIGNS["current_ph"])
        self.target_ph = to_float(API_SIGNS["target_ph"])
        self.current_orp = to_float(API_SIGNS["current_orp"])
        self.target_orp = to_float(API_SIGNS["target_orp"])
        self.current_clppm = to_float(API_SIGNS["current_clppm"])
        self.target_clppm = to_float(API_SIGNS["target_clppm"])

        self.binary_input_1 = v.get(API_SIGNS["binary_input_1"]) == "1"
        self.binary_input_2 = v.get(API_SIGNS["binary_input_2"]) == "1"
        self.binary_input_3 = v.get(API_SIGNS["binary_input_3"]) == "1"
        self.binary_input_4 = v.get(API_SIGNS["binary_input_4"]) == "1"
        self.waterflow_problem = v.get(API_SIGNS["waterflow"]) == "0"

        self.binary_input_1_name = info.get(API_SIGNS["binary_input_1_name"])
        self.binary_input_2_name = info.get(API_SIGNS["binary_input_2_name"])
        self.binary_input_3_name = info.get(API_SIGNS["binary_input_3_name"])
        self.binary_input_4_name = info.get(API_SIGNS["binary_input_4_name"])

        self.percentage_electrolysis = to_int(API_SIGNS["percentage_electrolysis"])
        self.target_percentage_electrolysis = to_int(API_SIGNS["target_percentage_electrolysis"])

        lu_val = v.get(API_SIGNS["uv_available"])
        if lu_val is not None:
            self.uv_available = lu_val != "-"

            # State machine based on 'bu' (uv_ballast). This probably only works
            # for non-prioritary UV lights to detect the light state.
            bu_val = v.get(API_SIGNS["uv_ballast"])
            if bu_val == "1":
                self.uv_on = True
                self.uv_enabled = True
                self.uv_ballast_problem = False
            elif bu_val == "0":
                self.uv_on = False
                self.uv_enabled = True
                self.uv_ballast_problem = False
            elif bu_val == "-":
                self.uv_on = False
                self.uv_enabled = False
                self.uv_ballast_problem = False
            else:
                # Absent, or an unexpected error code: not on, not usable.
                self.uv_on = False
                self.uv_enabled = False
                self.uv_ballast_problem = bu_val is not None

            self.current_uv_timer = to_int(API_SIGNS["current_uv_timer"])
            self.total_uv_timer = to_int(API_SIGNS["total_uv_timer"])
            self.uv_fuse_problem = v.get(API_SIGNS["uv_fuse"]) == "1"

        if len(self.relays) == 0:
            self.relays = [
                Relay(id=r["id"], pool=self, name=r["nombre"], sign=r["sign"], active=v.get(r["sign"]) == '1')
                for r in info.get("relays", [])
            ]

        else:
            relays_by_id = {r.id: r for r in self.relays}
            for obj in info.get("relays", []):
                relay = relays_by_id.get(obj["id"])
                if relay is None:
                    # New relay appeared since the first sync.
                    relay = Relay(id=obj["id"], pool=self, name=obj["nombre"], sign=obj["sign"], active=v.get(obj["sign"]) == '1')
                    self.relays.append(relay)
                else:
                    relay.name = obj["nombre"]
                    relay.active = v.get(obj["sign"]) == '1'

    async def set_target_attribute(self, attr, value): 
        previous_value = getattr(self, attr)
        setattr(self, attr, value)

        try:
            await self.post(UPDATE_URL, data=f"&data={json.dumps({'id': self.id, 'sign': API_SIGNS[attr], 'value': str(value)})}")
        except Exception:
            # Roll back local state so it never diverges from the device, and
            # re-raise so callers can actually detect the failure.
            setattr(self, attr, previous_value)
            raise
        return value

    async def set_target_ph(self, value): 
        return await self.set_target_attribute("target_ph", value)

    async def set_target_orp(self, value): 
        return await self.set_target_attribute("target_orp", value)

    async def set_target_clppm(self, value): 
        return await self.set_target_attribute("target_clppm", value)

    async def set_target_percentage_electrolysis(self, value): 
        return await self.set_target_attribute("target_percentage_electrolysis", value)

class Relay:
    def __init__(self, id=None, pool=None, name="", sign="", active=False):
        self.id = id
        self.pool = pool
        self.sign = sign
        self.name = name
        self.active = active

    async def set_active(self, active):
        previous_value = self.active
        self.active = active
        try:
            await self.pool.post(UPDATE_URL, data=f"&data={json.dumps({'id': self.pool.id, 'sign': self.sign, 'value': '1' if active else '0'})}")
        except Exception:
            # Roll back local state so it never diverges from the device, and
            # re-raise so callers can actually detect the failure.
            self.active = previous_value
            raise
        return active

class AuthenticationException(Exception):
    pass

class TwoFactorAuthRequiredException(Exception):
    pass

def get_auth_headers(token: str) -> tuple[str, str]:
    """Get the authentication headers for API requests.
    Returns a tuple of (encoded_token, md5_hash)"""
    if not token:
        return "", ""
    
    # Generate random number between 0 and 50
    i = random.randint(0, 50)
    logging.debug(f"Generated random number: {i}")
    
    # Get current timestamp in milliseconds
    a = str(int(time.time() * 1000))
    logging.debug(f"Generated timestamp: {a}")
    
    # Add timestamp to token exactly as in JavaScript
    token_with_timestamp = token + "&2&2" + a
    logging.debug(f"Token with timestamp: {token_with_timestamp}")
    
    # XOR each character with the random number, ensuring we handle Unicode correctly
    r = bytearray()
    for char in token_with_timestamp:
        # Convert to byte and XOR
        byte = ord(char)
        xored = byte ^ i
        # Ensure we stay within byte range (0-255)
        r.append(xored & 0xFF)
    
    logging.debug(f"XOR result length: {len(r)}")
    
    # Base64 encode with the same options as JavaScript
    # JavaScript's btoa() expects Latin1/ISO-8859-1 encoded input
    encoded_token = base64.b64encode(r).decode('ascii')
    logging.debug(f"Base64 encoded token length: {len(encoded_token)}")
    
    # Calculate MD5 of the random number
    md5_hash = hashlib.md5(str(i).encode()).hexdigest()
    logging.debug(f"MD5 hash: {md5_hash}")
    
    # Log the full request for debugging
    logging.debug("Full request details:")
    logging.debug(f"Original token: {token}")
    logging.debug(f"Random number: {i}")
    logging.debug(f"Timestamp: {a}")
    logging.debug(f"Token with timestamp: {token_with_timestamp}")
    logging.debug(f"XOR result (hex): {r.hex()}")
    logging.debug(f"Base64 encoded: {encoded_token}")
    logging.debug(f"MD5 hash: {md5_hash}")
    
    return encoded_token, md5_hash
