import json
from aiohttp import ClientSession, ClientError

DOMAIN = 'https://api.idegis.net'
LOGIN_URL = DOMAIN + '/session/login'
POOL_LIST_URL = DOMAIN + '/devices/10/0'
POOL_INFO_URL = DOMAIN + '/devices/'
UPDATE_URL = DOMAIN + '/devices/saveSign'

class Account:
    def __init__(self, username="", password="", token=None) -> None:
        self._username = username
        self._password = password
        self._token = token

    async def token(self):
        if self._token: return self._token
        return await self.login()

    async def login(self):
        async with ClientSession() as session:
            async with session.post(LOGIN_URL, json={"username": self._username, "password": self._password}) as resp:
                resp.raise_for_status()
                data = await resp.json()
                self._token = data["token"]
                return self._token

class Pool:
    @classmethod
    async def all(cls, username="", password="", account = None):
        if not account:
            account = Account(username=username, password=password)
        token = await account.token()
        async with ClientSession() as session:
            async with session.post(
                    POOL_LIST_URL,
                    data=f"Authorization=Bearer {token}",
                    headers={"accept": "application/json", "content-type": "application/x-www-form-urlencoded"}
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()
                return list(map(lambda x: Pool(token, x['id']), data["items"]))

    def __init__(self, token, id):
        self._token = token
        self.id = id
        self.alias = None
        self.temperature = None
        self.salt_concentration = None
        self.current_ph = None
        self.target_ph = None
        self.percentage_electrolysis = None
        self.target_percentage_electrolysis = None
        self.relays = []

    async def post(self, url, data=""):
        session = ClientSession()
        resp = await session.post(
            url,
            data=f"Authorization=Bearer {self._token}" + data,
            headers={"accept": "application/json", "content-type": "application/x-www-form-urlencoded"}
        )
        resp.raise_for_status()
        info = await resp.json()
        await session.close()
        return info

    async def sync_info(self):
        info = await self.post(POOL_INFO_URL + str(self.id))
        self.alias = info["alias"]
        self.temperature = float(info["vars"]["ta"][0:-1])  # in °C
        self.salt_concentration = float(info["vars"]["cn"][0:-1])  # in gr/l
        self.current_ph = float(info["vars"]["mp"])
        self.target_ph = float(info["vars"]["sp"])
        self.percentage_electrolysis = int(info["vars"]["pa"])
        self.target_percentage_electrolysis = int(info["vars"]["sn"])
        self.relays = list(
            map(
                lambda r: {'id': r["id"], 'name': r["nombre"], 'sign': r["sign"],
                           'active': info["vars"][r["sign"]] == '1'},
                info["relays"]
            )
        )

    async def set_relay(self, relay_id, active):
        relay = next((r for r in self.relays if r['id'] == relay_id), None)
        previous_value = relay.active
        relay.active = active
        try:
            await self.post(UPDATE_URL, data=f"&data={json.dumps({'id': self.id, 'sign': relay['sign'], 'value': '1' if active else '0'})}")
            return active
        except ClientError as err:
            relay.active = previous_value 
            return previous_value               

    async def set_target_ph(self, value): 
        self.target_ph = value
        previous_value = self.target_ph     
        self.target_ph = value
        api_value = str(value)
        try:
            await self.post(UPDATE_URL, data=f"&data={json.dumps({'id': self.id, 'sign': 'sp', 'value': api_value})}")
            return value
        except ClientError as err:
            self.target_ph = previous_value  
            return previous_value     

    async def set_target_percentage_electrolysis(self, value): 
        previous_value = self.target_percentage_electrolysis     
        self.target_percentage_electrolysis = value
        api_value = str(value).zfill(3)
        try:
            await self.post(UPDATE_URL, data=f"&data={json.dumps({'id': self.id, 'sign': 'sn', 'value': api_value})}")
            return value
        except ClientError as err:
            self.target_percentage_electrolysis = previous_value
            return previous_value