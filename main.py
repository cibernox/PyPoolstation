import json
import requests

DOMAIN = 'https://api.idegis.net'
LOGIN_URL = DOMAIN + '/session/login'
POOL_LIST_URL = DOMAIN + '/devices/10/0'
POOL_INFO_URL = DOMAIN + '/devices/'
UPDATE_RELAY_URL = DOMAIN + '/devices/saveSign'

class Session:
    def __init__(self, username, password) -> None:
        self.username = username
        self.password = password
        self.token = None;
        self.login()

    def is_logged_in(self):
        return self.token != None

    def login(self):
        req = requests.post(LOGIN_URL, json={"username": self.username, "password": self.password})
        if req.status_code == 200:
            data = req.json()
            self.token = data["token"]
            return True
        else:
            self.token = None;
            return False

    def post(self, url, data=""):
        if not self.is_logged_in:
            self.login()
        req = requests.post(
            url,
            data=f"Authorization=Bearer {self.token}" + (data or ""),
            headers={"content-type": "application/x-www-form-urlencoded"}
        )
        if req.status_code == 200:
            return True, req.json()
        else:
            print(f'request to {url} failed')
            return False, None

class Pool:
    @classmethod
    def all(cls, username, password):
        session = Session(username, password)
        success, data = session.post(POOL_LIST_URL)
        if success:
            return True, list(map(lambda x: Pool(session, x['id']), data["items"]))
        else:
            return False, []

    def __init__(self, session, id):
        self.session = session
        self.id = id
        self.alias = None;
        self.temperature = None;
        self.salt_concentration = None;
        self.current_ph = None;
        self.target_ph = None;
        self.percentage_electrolysis = None;
        self.target_percentage_electrolysis = None;
        self.relays = []

    def sync_info(self):
        success, info = self.session.post(POOL_INFO_URL + str(self.id))
        if success:
            self.alias = info["alias"]
            self.temperature = float(info["vars"]["ta"][0:-1])  # in °C
            self.salt_concentration = float(info["vars"]["cn"][0:-1])  # in gr/l
            self.current_ph = float(info["vars"]["mp"])
            self.target_ph = float(info["vars"]["sp"])
            self.percentage_electrolysis = int(info["vars"]["pa"])
            self.target_percentage_electrolysis = int(info["vars"]["sn"])
            self.relays = list(
                map(
                    lambda r: {'id': r["id"], 'name': r["nombre"], 'sign': r["sign"], 'active': info["vars"][r["sign"]] == '1'},
                    info["relays"]
                )
            )
            return True

    def set_relay(self, relay_id, active):
        relay = next((r for r in self.relays if r['id'] == relay_id), None)
        self.session.post(
            UPDATE_RELAY_URL,
            data=f"&data={json.dumps({'id': self.id, 'sign': relay['sign'], 'value': '1' if active else '0'})}"
        )
#
# if __name__ == '__main__':
#     success, [pool] = Pool.all("user", "pass")
#     if not success:
#         exit(1)
#     pool.sync_info()
#     print(pool.id)
#     print(pool.relays)
#     pool.set_relay(41598, False)