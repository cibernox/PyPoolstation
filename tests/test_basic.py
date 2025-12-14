import asyncio
import json
import logging
import sys
import os
import aiohttp

# Ensure pypoolstation is in path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from pypoolstation import Pool, Account

# Configure logging
logging.basicConfig(level=logging.DEBUG)

async def main():
    try:
        with open('credentials.json', 'r') as f:
            creds = json.load(f)
    except FileNotFoundError:
        print("Error: credentials.json not found. Please create it with your username and password.")
        return

    username = creds.get('username')
    password = creds.get('password')

    if not username or not password or "your_email" in username:
         print("Error: Please update credentials.json with valid credentials.")
         return

    print(f"Attempting to login with user: {username}")
    
    # Create session
    async with aiohttp.ClientSession() as session:
        account = Account(session, username=username, password=password)
        try:
            token = await account.token()
            print(f"Login successful. Token: {token[:10]}...")
        except Exception as e:
            print(f"Login failed: {e}")
            return

        print("Fetching pools...")
        pools = await Pool.get_all_pools(session, username=username, password=password, account=account)
        print(f"Found {len(pools)} pools.")

        if pools:
            pool = pools[0]
            print(f"Syncing info for pool ID: {pool.id}...")
            await pool.sync_info()
            print("Pool Info Synced.")
            print("-" * 20)
            print("Pool Attributes:")
            for key, value in vars(pool).items():
                if key == 'relays':
                    continue # Print relays separately
                if key.startswith('_') or key == 'logger':
                    continue # Skip private/internal attributes
                print(f"{key}: {value}")
            
            print("-" * 20)
            print(f"Relays ({len(pool.relays)}):")
            for relay in pool.relays:
                print(f"  - Relay {relay.id}: {relay.name} (Active: {relay.active})")

        else:
            print("No pools found.")

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
