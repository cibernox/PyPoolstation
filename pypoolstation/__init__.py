import json
from aiohttp import ClientError, ClientResponseError
import logging

from backoff import constant

DOMAIN = 'https://api.idegis.net'
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
    "target_percentage_electrolysis": "sn"
}

class Account:
    def __init__(self, session, username="", password="", token=None, logger=logging) -> None:
        self._session = session
        self._username = username
        self._password = password
        self._token = token
        self.logger = logger;

    async def token(self):
        if self._token: return self._token
        return await self.login()

    async def login(self):
        self.logger.debug("Account attempting to log in")
        async with self._session.post(LOGIN_URL, json={"username": self._username, "password": self._password}) as resp:
            if resp.status == 401:
                raise AuthenticationException('Authentication failed')
            resp.raise_for_status()
            data = await resp.json()
            self.logger.debug("Account logged in successfully")
            self._token = data["token"]
            return self._token


class Pool:
    @classmethod
    async def get_all_pools(cls, session, username="", password="", account = None):
        if not account:
            account = Account(session, username=username, password=password)
        token = await account.token()
        account.logger.debug("Fetching all pools on the account")
        try:
            async with session.post(
                    POOL_LIST_URL,
                    data=f"Authorization=Bearer {token}",
                    headers={"accept": "application/json", "content-type": "application/x-www-form-urlencoded"}
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()
                account.logger.debug(f"Account pools retrieved successfully. Number of pools: {len(data['items'])}")
                return list(map(lambda x: Pool(session, token, x['id'], account.logger), data["items"]))
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
        self.logger = logger

    async def post(self, url, data=""):
        try:
            resp = await self._session.post(
                url,
                data=f"Authorization=Bearer {self._token}" + data,
                headers={"accept": "application/json", "content-type": "application/x-www-form-urlencoded"}
            )
            resp.raise_for_status()
        except ClientResponseError as err:
            # Unfortunately, the API is aweful and making a request with an expired token seems to trigger a generic 500 error.
            # For all I could find, there's not way of
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
        self.percentage_electrolysis = int(info["vars"][API_SIGNS["percentage_electrolysis"]])
        self.target_percentage_electrolysis = int(info["vars"][API_SIGNS["target_percentage_electrolysis"]])
        if len(self.relays) == 0:
            self.relays = list(
                map(
                    (lambda r: Relay(id=r["id"], pool=self, name=r["nombre"], sign=r["sign"], active=info["vars"][r["sign"]] == '1')),
                    info["relays"]
                )
            )
        else:
            for obj in info["relays"]:
                relay = next((r for r in self.relays if r.id == obj["id"]), None)
                relay.name = obj["nombre"]
                relay.active = info["vars"][obj["sign"]] == '1'

    async def set_target_attribute(self, attr, value): 
        previous_value = getattr(self, attr)
        setattr(self, attr, value);
        api_value = str(value)
        try:
            await self.post(UPDATE_URL, data=f"&data={json.dumps({'id': self.id, 'sign': API_SIGNS[attr], 'value': api_value})}")
            return value
        except ClientError as err:
            setattr(self, attr, previous_value);
            return previous_value     

    async def set_target_ph(self, value): 
        return self.set_target_attribute(self, "target_ph", value)

    async def set_target_orp(self, value): 
        return self.set_target_attribute(self, "target_orp", value)

    async def set_target_clppm(self, value): 
        return self.set_target_attribute(self, "target_clppm", value)

    async def set_target_percentage_electrolysis(self, value): 
        return self.set_target_attribute(self, "target_percentage_electrolysis", value)

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