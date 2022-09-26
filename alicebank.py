import hashlib
from secp import PrivateKey, PublicKey, hash_to_curve

# Bank setup
priv_key_Bank = PrivateKey()
priv_key_Bank_str = priv_key_Bank.serialize()
pub_key_Bank = priv_key_Bank.pubkey
pub_key_Bank_str = pub_key_Bank.serialize().hex()

print(f"=== Welcome to {pub_key_Bank_str} Bank! ===")

secret_alice_str = "Alice has deposited 100sats to Bank plus random nonce:zagts1648"

print(f"Alice's secret that will be associated with the Bank's promise: {secret_alice_str}")

Y = hash_to_curve(secret_alice_str)
print(f"Y: {Y.serialize(compressed=True).hex()} is the hash to point of Alice's secret")
r = PrivateKey()
T = Y + r.pubkey
print(f"Alice sends T {T.serialize().hex()} along with payment of 100sats to Bank")
Q = T.mult(priv_key_Bank)
print(f"Bank accepts payment and registers 100sat liability on its and sends back to Alice Q: {Q.serialize().hex()} as a promise to Alice's secret")

# Alice now calculates the unblinded key as Z = Q - rK
Z = Q - pub_key_Bank.mult(r)
print(f"This is Z: {Z.serialize().hex()}")
print(f"Now Alice has ([{secret_alice_str}], {Z.serialize().hex()} to give to Carol")
# Carol now submits (secret_alice_str, Z) to Bank
# Bank needs to determine that promise is not yet honoured: 1) check if from Bank, and 2) not yet redeemed
bank_promise = hash_to_curve(secret_alice_str).mult(priv_key_Bank)

print(f"Bank promise: {bank_promise.serialize().hex()} should equal Z: {Z.serialize().hex()}")
# If bank_promise is equal to Z and Z is not previously honoured then it is a valid liability
assert bank_promise == Z
