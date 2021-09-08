## PyPoolstation

Python Library that acts as a wrapper to interact with the Poolstation platform (https://poolstation.net/)
for controlling pools.

#### Disclaimer

Poolstation is a domotic platform developed by Idegis (https://idegis.net/)
I'm the owner of an Idegis Chlorinator compatible with the platform, but I am
not associated with Idegis in any other way or form.

#### Usage

This library has three public classes, `Account`, `Pool` and `Relay`, but for the most part you will only need the last two.

You can obtaining a list of all your pools calling `await Pool.all(username, password)`.
The for each pool you can use `await pool.sync_info()` to refresh its information (temperature, salt concentration, its relays' state, target and current ph, etc...).
Each pool as a `pool.relays` property containing an array of `Relay` objects. Each relay can be turned on and off with `await Relay.set_active(True)` and `await Relay.set_active(False)`.

```py
[pool] = await Pool.all('bob@burgers.com', 'secret') # who has several pools really?
await pool.sync_info()
print(vars(pool)) # {id: 123, alias: 'The name of your pool', current_ph: 7.11, target_ph: 7.2, relays: [{ id: 777, name: 'Pool lights', sign: 'mc', active: True }], ... }
await pool.relays[0].(False) # Turns off the relay with the given ID
```