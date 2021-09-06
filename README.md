## PyPoolstation

Python Library that acts as a wrapper to interact with the Poolstation platform (https://poolstation.net/)
for controlling pools.

#### Disclaimer

Poolstation is a domotic platform developed by Idegis (https://idegis.net/)
I'm the owner of an Idegis Chlorinator compatible with the platform, but I am
not associated with Idegis in any other way or form.

#### Usage

This library has a single public class: `Pool`.

You can list all your pools using `await Pool.all(username, password)`, which returns a `success, pools` tuple.
The for each pool you can use `await pool.sync_info` to refresh its information (temperature, salt concentration, its relays' state, target and current ph, etc...)
and `await pool.set_relay(relay_id, True)` or `await pool.set_relay(relay_id, False)` to turn on/off a relay.

```py
[pool] = await Pool.all('bob@burgers.com', 'secret') # who has several pools really?
await pool.sync_info()
print(vars(pool)) # {id: 123, alias: 'The name of your pool', current_ph: 7.11, target_ph: 7.2, relays: [{ id: 777, name: 'Pool lights', sign: 'mc', active: True }], ... }
await pool.set_relay(777, False) # Turns off the relay with the given ID
```