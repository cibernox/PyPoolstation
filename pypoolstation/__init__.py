import json
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

    async def login(self):
        self.logger.debug("Account attempting to log in")
        current_date = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        async with self._session.post(LOGIN_URL, json={
            "username": self._username, 
            "password": self._password, 
            "remember": True, 
            "connectdate": current_date
        }) as resp:
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
                    }
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

    async def post(self, url, data=""):
        try:
            # Create a new Account instance with the token
            account = Account(self._session, token=self._token)
            encoded_token, md5_hash = account.get_auth_headers()
            resp = await self._session.post(
                url,
                data=data,
                headers={
                    "accept": "application/json", 
                    "content-type": "application/x-www-form-urlencoded",
                    "Authorization": f"Bearer {encoded_token}",
                    "Q": md5_hash
                }
            )
            resp.raise_for_status()
        except ClientResponseError as err:
            if err.status == 504:
                raise
            else:
                raise AuthenticationException("Request failed. Maybe token has expired.")
        return await resp.json()

    async def sync_info(self):
        self.logger.debug(f"Updating pool info for pool with id {self.id}")
        info = await self.post(POOL_INFO_URL + str(self.id))
        self.alias = info["alias"]
        try:
            # I don't know why these values would be missing since all devices have these sensors
            # but people have reported that sometimes they are, so let's wrap them in try/except.
            self.temperature = float(info["vars"][API_SIGNS["temperature"]][0:-1])  # in °C
            self.salt_concentration = float(info["vars"][API_SIGNS["salt_concentration"]][0:-1])  # in gr/l
            self.current_ph = float(info["vars"][API_SIGNS["current_ph"]])
            self.target_ph = float(info["vars"][API_SIGNS["target_ph"]])
            self.binary_input_1 = info["vars"][API_SIGNS["binary_input_1"]] == "1"
            self.binary_input_2 = info["vars"][API_SIGNS["binary_input_2"]] == "1"
            self.binary_input_3 = info["vars"][API_SIGNS["binary_input_3"]] == "1"
            self.binary_input_4 = info["vars"][API_SIGNS["binary_input_4"]] == "1"
            self.waterflow_problem = info["vars"][API_SIGNS["waterflow"]] == "0"
            self.binary_input_1_name = info[API_SIGNS["binary_input_1_name"]]
            self.binary_input_2_name = info[API_SIGNS["binary_input_2_name"]]
            self.binary_input_3_name = info[API_SIGNS["binary_input_3_name"]]
            self.binary_input_4_name = info[API_SIGNS["binary_input_4_name"]]
        except ValueError:
            pass
            
        try:
            self.current_orp = float(info["vars"][API_SIGNS["current_orp"]])
            self.target_orp = float(info["vars"][API_SIGNS["target_orp"]])
        except ValueError:
            pass
            
        try:
            self.current_clppm = float(info["vars"][API_SIGNS["current_clppm"]])
            self.target_clppm = float(info["vars"][API_SIGNS["target_clppm"]])  
        except ValueError:
            pass
      
        try:
            self.uv_available = info["vars"][API_SIGNS["uv_available"]] != "-"

            # New Logic based on 'bu' (uv_ballast). This probably only works for non-prioriatary UV
            # lights to detect the light state.
            bu_val = info["vars"].get(API_SIGNS["uv_ballast"])
            if bu_val == "-":
                self.uv_on = False
                self.uv_enabled = False
            elif bu_val == "1":
                self.uv_on = True
                self.uv_enabled = True
            elif bu_val == "0":
                self.uv_on = False
                self.uv_enabled = True
            else:
                self.uv_on = False
                self.uv_enabled = False

            self.current_uv_timer = int(info["vars"][API_SIGNS["current_uv_timer"]])
            self.total_uv_timer = int(info["vars"][API_SIGNS["total_uv_timer"]])
            self.uv_ballast_problem = info["vars"][API_SIGNS["uv_ballast"]] == "1"
            self.uv_fuse_problem = info["vars"][API_SIGNS["uv_fuse"]] == "1"
        except ValueError:
            pass


        self.percentage_electrolysis = int(info["vars"][API_SIGNS["percentage_electrolysis"]])
        self.target_percentage_electrolysis = int(info["vars"][API_SIGNS["target_percentage_electrolysis"]])
        if len(self.relays) == 0:
            self.relays = [
                Relay(id=r["id"], pool=self, name=r["nombre"], sign=r["sign"], active=info["vars"][r["sign"]] == '1')
                for r in info["relays"]
            ]

        else:
            for obj in info["relays"]:
                relay = next((r for r in self.relays if r.id == obj["id"]), None)
                relay.name = obj["nombre"]
                relay.active = info["vars"][obj["sign"]] == '1'

    async def set_target_attribute(self, attr, value): 
        previous_value = getattr(self, attr)
        setattr(self, attr, value)

        api_value = str(value)
        try:
            await self.post(UPDATE_URL, data=f"&data={json.dumps({'id': self.id, 'sign': API_SIGNS[attr], 'value': api_value})}")
            return value
        except ClientError as err:
            setattr(self, attr, previous_value)

            return previous_value     

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
            return active
        except ClientError as err:
            self.active = previous_value 
            return previous_value   

class AuthenticationException(Exception):
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
