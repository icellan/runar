"""DoS-bound input limits for the Python SDK.

Mirrors :data:`InputLimits.MAX_SCRIPT_BYTES` (4 MiB) from the TS schema
package. Any locking script larger than this is rejected at SDK entry
points (``deploy`` / ``call`` / ``Provider.get_utxos`` /
``Provider.get_contract_utxo``) BEFORE any signing or broadcast work
happens. Largest legitimate script measured is ``p384-wallet`` at
~1.87 MB; 4 MiB gives ~2× headroom.
"""

MAX_SCRIPT_BYTES: int = 4 * 1024 * 1024
