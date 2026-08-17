import unittest
from unittest.mock import AsyncMock, patch, MagicMock
import aiohttp
import logging
import sys
import os

# Ensure pypoolstation is in path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from pypoolstation import Account, Pool, AuthenticationException, TwoFactorAuthRequiredException, get_auth_headers

class MockResponse:
    def __init__(self, status, json_data):
        self.status = status
        self._json_data = json_data
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass
    
    def __await__(self):
        async def _awaitable():
            return self
        return _awaitable().__await__()

    async def json(self):
        return self._json_data

    async def text(self):
        return str(self._json_data)

    def raise_for_status(self):
        if self.status >= 400:
             raise aiohttp.ClientResponseError(
                 request_info=MagicMock(),
                 history=tuple(),
                 status=self.status,
                 message='Mock Error'
             )

class TestPyPoolstation(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.session = MagicMock()
        
    async def test_login_success(self):
        self.session.post.return_value = MockResponse(200, {"token": "dummy_token"})
        
        account = Account(self.session, "user", "pass")
        token = await account.login()
        self.assertEqual(token, "dummy_token")
        
    async def test_login_2fa(self):
        self.session.post.return_value = MockResponse(410, {"error_code": "REQUEST_LOGIN_CODE"})
        
        account = Account(self.session, "user", "pass")
        with self.assertRaises(TwoFactorAuthRequiredException):
            await account.login()

    async def test_login_failure(self):
        self.session.post.return_value = MockResponse(401, {})
        
        account = Account(self.session, "user", "pass")
        with self.assertRaises(AuthenticationException):
            await account.login()

    def test_get_auth_headers(self):
        token = "testtoken"
        with patch('time.time', return_value=12345.0):
            with patch('random.randint', return_value=10):
                enc, md5 = get_auth_headers(token)
                self.assertTrue(enc)
                self.assertEqual(md5, "d3d9446802a44259755d38e6d163e820") # MD5 of '10'

    async def test_get_all_pools(self):
        self.session.post.return_value = MockResponse(200, {"items": [{"id": 123}]})
        
        account = Account(self.session, "user", "pass", token="dummy")
        with patch.object(Account, 'get_auth_headers', return_value=("a","b")):
            pools = await Pool.get_all_pools(self.session, account=account)
            self.assertEqual(len(pools), 1)
            self.assertEqual(pools[0].id, 123)

    async def test_sync_info(self):
        mock_info = {
            "alias": "My Pool",
            "vars": {
                "ta": "25.0 ", "cn": "3.5 ", "mp": "7.2", "sp": "7.3", 
                "lu": "1", "bu": "1", "hu": "100", "xu": "1000", "fu": "0", "ac": "1",
                "d1": "0", "d2": "0", "d3": "0", "d4": "0",
                "pa": "50", "sn": "60", "mo": "650", "so": "700", "mh": "1.5", "sh": "2.0",
                "r1": "1"
            },
            "relays": [{"id": 1, "nombre": "Pump", "sign": "r1"}],
            "d1_name": "Input 1", "d2_name": "Input 2", "d3_name": "Input 3", "d4_name": "Input 4"
        }

        self.session.post.return_value = MockResponse(200, mock_info)
        
        pool = Pool(self.session, "dummy_token", 123, logging.getLogger())
        with patch('pypoolstation.get_auth_headers', return_value=("a", "b")):
            await pool.sync_info()
            self.assertEqual(pool.temperature, 25.0)
            self.assertEqual(pool.salt_concentration, 3.5)
            self.assertEqual(pool.current_ph, 7.2)
            self.assertTrue(pool.uv_available)
            self.assertTrue(pool.uv_enabled)
            self.assertEqual(len(pool.relays), 1)
            self.assertTrue(pool.relays[0].active)
            self.assertFalse(pool.waterflow_problem)

    async def test_set_target_attribute(self):
        # Initial sync to setup state
        self.session.post.return_value = MockResponse(200, {
            "alias": "My Pool",
            "vars": {
                "ta": "25.0 ", "cn": "3.5 ", "sp": "7.0", "mp": "7.2", "ac": "1", "d1": "0", "d2": "0", "d3": "0", "d4": "0",
                "mo": "650", "so": "700", "mh": "1.5", "sh": "2.0", "pa": "50", "sn": "60", "lu": "1", "bu": "1", "hu": "100", "xu": "1000", "fu": "0", "r1": "1"
            },
            "relays": [{"id": 1, "nombre": "Pump", "sign": "r1"}],
            "d1_name": "", "d2_name": "", "d3_name": "", "d4_name": ""
        })
        pool = Pool(self.session, "dummy_token", 123, logging.getLogger())
        with patch('pypoolstation.get_auth_headers', return_value=("a", "b")):
            await pool.sync_info()
            self.assertEqual(pool.target_ph, 7.0)

            # Test successful update
            self.session.post.return_value = MockResponse(200, {"success": True})
            res = await pool.set_target_ph(7.5)
            self.assertEqual(res, 7.5)
            self.assertEqual(pool.target_ph, 7.5)

            # Test failed update: server errors propagate and roll back state
            self.session.post.return_value = MockResponse(500, {})
            with self.assertRaises(aiohttp.ClientResponseError):
                await pool.set_target_ph(8.0)
            self.assertEqual(pool.target_ph, 7.5, "state must be rolled back on failure")

            # Test failed update: auth errors propagate and roll back state
            self.session.post.return_value = MockResponse(401, {})
            with self.assertRaises(AuthenticationException):
                await pool.set_target_ph(8.0)
            self.assertEqual(pool.target_ph, 7.5, "state must be rolled back on failure")

            # Test failed update: network errors propagate (no silent swallow)
            self.session.post.side_effect = aiohttp.ClientError("simulated network error")
            with self.assertRaises(aiohttp.ClientError):
                await pool.set_target_orp(750)
            self.assertEqual(pool.target_orp, 700, "state must be rolled back on failure")

    async def test_relay_set_active(self):
        self.session.post.return_value = MockResponse(200, {
            "alias": "My Pool",
            "vars": {"ta": "25.0 ", "mp": "7.2", "r1": "0"},
            "relays": [{"id": 1, "nombre": "Pump", "sign": "r1"}],
        })
        pool = Pool(self.session, "dummy_token", 123, logging.getLogger())
        with patch('pypoolstation.get_auth_headers', return_value=("a", "b")):
            await pool.sync_info()
            relay = pool.relays[0]
            self.assertFalse(relay.active)

            # Success
            self.session.post.return_value = MockResponse(200, {"success": True})
            result = await relay.set_active(True)
            self.assertTrue(result)
            self.assertTrue(relay.active)

            # Failure rolls back and raises
            self.session.post.return_value = MockResponse(500, {})
            with self.assertRaises(aiohttp.ClientResponseError):
                await relay.set_active(False)
            self.assertTrue(relay.active, "relay state must be rolled back on failure")

    async def test_sync_info_missing_vars(self):
        # Sparse payload: most sensors missing. Must not raise.
        self.session.post.return_value = MockResponse(200, {
            "alias": "My Pool",
            "vars": {"ta": "25.0 ", "mp": "7.2"},
            "relays": [],
        })
        pool = Pool(self.session, "dummy_token", 123, logging.getLogger())
        with patch('pypoolstation.get_auth_headers', return_value=("a", "b")):
            await pool.sync_info()
            self.assertEqual(pool.alias, "My Pool")
            self.assertEqual(pool.temperature, 25.0)
            self.assertEqual(pool.current_ph, 7.2)
            self.assertIsNone(pool.salt_concentration)
            self.assertIsNone(pool.target_ph)
            self.assertIsNone(pool.current_orp)
            self.assertIsNone(pool.current_clppm)
            self.assertIsNone(pool.percentage_electrolysis)
            self.assertIsNone(pool.target_percentage_electrolysis)
            self.assertIsNone(pool.uv_available)
            self.assertIsNone(pool.binary_input_1_name)
            self.assertFalse(pool.waterflow_problem)
            self.assertEqual(pool.relays, [])

    async def test_sync_info_malformed_values(self):
        # Garbage values: parsing must yield None, not raise.
        self.session.post.return_value = MockResponse(200, {
            "alias": "My Pool",
            "vars": {
                "ta": "N/A", "cn": "-", "mp": "", "sp": "abc",
                "lu": "1", "bu": "0", "hu": "x", "xu": "y", "fu": "1",
                "pa": "?", "sn": "?",
            },
            "relays": [],
        })
        pool = Pool(self.session, "dummy_token", 123, logging.getLogger())
        with patch('pypoolstation.get_auth_headers', return_value=("a", "b")):
            await pool.sync_info()
            self.assertIsNone(pool.temperature)
            self.assertIsNone(pool.current_ph)
            self.assertIsNone(pool.target_ph)
            self.assertIsNone(pool.current_uv_timer)
            self.assertIsNone(pool.total_uv_timer)
            self.assertIsNone(pool.percentage_electrolysis)
            self.assertTrue(pool.uv_available)
            self.assertTrue(pool.uv_fuse_problem)

    async def test_sync_info_uv_states(self):
        cases = [
            # (bu, uv_on, uv_enabled, uv_ballast_problem)
            ("-", False, False, False),
            ("1", True, True, False),
            ("0", False, True, False),
            ("e1", False, False, True),  # unexpected error code
        ]
        for bu, expected_on, expected_enabled, expected_ballast in cases:
            self.session.post.return_value = MockResponse(200, {
                "alias": "My Pool",
                "vars": {"lu": "1", "bu": bu, "hu": "10", "xu": "20", "fu": "0"},
                "relays": [],
            })
            pool = Pool(self.session, "dummy_token", 123, logging.getLogger())
            with patch('pypoolstation.get_auth_headers', return_value=("a", "b")):
                await pool.sync_info()
                self.assertEqual(pool.uv_on, expected_on, f"bu={bu!r}")
                self.assertEqual(pool.uv_enabled, expected_enabled, f"bu={bu!r}")
                self.assertEqual(pool.uv_ballast_problem, expected_ballast, f"bu={bu!r}")

    async def test_sync_info_relay_updates(self):
        base = {
            "alias": "My Pool",
            "relays": [{"id": 1, "nombre": "Pump", "sign": "r1"}],
        }
        self.session.post.return_value = MockResponse(200, {
            **base, "vars": {"r1": "1"},
        })
        pool = Pool(self.session, "dummy_token", 123, logging.getLogger())
        with patch('pypoolstation.get_auth_headers', return_value=("a", "b")):
            await pool.sync_info()
            self.assertEqual(len(pool.relays), 1)
            self.assertTrue(pool.relays[0].active)

            # Second sync: relay 1 state changed, relay 2 appeared.
            self.session.post.return_value = MockResponse(200, {
                "alias": "My Pool",
                "vars": {"r1": "0", "r2": "1"},
                "relays": [
                    {"id": 1, "nombre": "Pump", "sign": "r1"},
                    {"id": 2, "nombre": "Light", "sign": "r2"},
                ],
            })
            await pool.sync_info()
            self.assertEqual(len(pool.relays), 2, "new relays must be added on resync")
            self.assertFalse(pool.relays[0].active, "relay state must be refreshed")
            self.assertEqual(pool.relays[0].name, "Pump")
            self.assertTrue(pool.relays[1].active)
            self.assertEqual(pool.relays[1].name, "Light")

if __name__ == '__main__':
    unittest.main()
