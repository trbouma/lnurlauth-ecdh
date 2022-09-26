from secp256k1 import PrivateKey, PublicKey

from binascii import unhexlify
import binascii,os
import secp256k1

from simpleECDH import make_shared_secret

'''
Generate the private key from a new instance. The public key is an attribute of the new instance
Serialize into hex string variables. 

Note the difference between the private key serialization versus the public key serialization.
The hardest part is keeping straight the various instantiations, formats and encoding.
'''

privkey_wallet = PrivateKey()

privkey_str_wallet = privkey_wallet.serialize()
pubkey_str_wallet = privkey_wallet.pubkey.serialize().hex()

print("="*80)
# Display the serializations of the wallet keys
# print("Wallet:",privkey_str_wallet, pubkey_str_wallet)
print(f"Wallet Private Key: \t{privkey_str_wallet} \nWallet Public Key: \t{pubkey_str_wallet}")


privkey_verifier = PrivateKey()
privkey_str_verifier = privkey_verifier.serialize()
pubkey_str_verifier = privkey_verifier.pubkey.serialize().hex()

# print("Verifier:",privkey_str_wallet, pubkey_str_wallet)
print(f"Verifier Private Key: \t{privkey_str_verifier} \nVerifier Public Key: \t{pubkey_str_verifier}")

# This is to confirm that the keys can be reconstructed from the hex strings
print("="*80)
privkey_wallet2 = PrivateKey(bytes(bytearray.fromhex(privkey_str_wallet)), raw=True)

privkey_str_wallet2 = privkey_wallet2.serialize()
pubkey_str_wallet2 = privkey_wallet2.pubkey.serialize().hex()

privkey_verifier2 = PrivateKey(bytes(bytearray.fromhex(privkey_str_verifier)), raw=True)

privkey_str_verifier2 = privkey_verifier2.serialize()
pubkey_str_verifier2 = privkey_verifier2.pubkey.serialize().hex()



print(f"Wallet Private Key2: \t{privkey_str_wallet2} \nWallet Public Key2: \t{pubkey_str_wallet2}")
print(f"Verifier Private Key2: \t{privkey_str_verifier2} \nVerifier Public Key2: \t{pubkey_str_verifier2}")
print("="*80)
# Generate a k1
k1: str = binascii.hexlify(os.urandom(32)).decode()

print("k1", k1)

# Do the wallet signing

k1_bin = binascii.unhexlify(k1)
key_bin =binascii.unhexlify(pubkey_str_wallet)
b_sig = privkey_wallet.ecdsa_sign(k1_bin,raw=True)
sig_serialized=privkey_wallet.ecdsa_serialize(b_sig)

# wallet computes shared secret - needs a public key from verifier

sig = sig_serialized.hex()
print("sig_serialized", sig)

# Values are hex string that can be passed back
print("values to be sent back")
print("k1:", k1)
print("pubkey", pubkey_str_wallet)
print ("sig", sig)

# All are hex string now - need to convert to do the authentication
k1 =    unhexlify(k1)
key =   unhexlify(pubkey_str_wallet)
sig =   unhexlify(sig)

pubkey = PublicKey(key, raw=True)
sig_raw = pubkey.ecdsa_deserialize(sig)
r = pubkey.ecdsa_verify(k1, sig_raw, raw=True)

assert r == True
if r == True:
    print("yahoo, I did it!")


#OK let's try the ECDH
'''
This is the basic math for ECDH: multiply the public key of your counterparty with your private key.
If both parties do this, they should end up with the same shared secret.

shared_secret1 is wallet_public_key * verifier_private_key
shared_secret2 is verfifier_public_key * wallet_private_key

Steps:
Instantiate a public key with the hex of the counterparty

'''

shared_secret_1 = privkey_wallet.pubkey.ecdh(unhexlify(privkey_verifier.serialize())).hex()
shared_secret_2 = privkey_verifier.pubkey.ecdh(unhexlify(privkey_wallet.serialize())).hex()



shared_secret_1 = privkey_wallet.pubkey.ecdh(unhexlify(privkey_verifier.serialize())).hex()
shared_secret_2 = privkey_verifier.pubkey.ecdh(unhexlify(privkey_wallet.serialize())).hex()

print(f"Shared Secret 1: {shared_secret_1}\nShared Secret 2: {shared_secret_2}")

assert shared_secret_1 == shared_secret_2
if shared_secret_1 == shared_secret_2:
    print("I did it again!")

#print(shared_secret_1.hex(), shared_secret_2.hex())

# Create pubkey instances
pubkey_obj_verifier =   PublicKey(unhexlify(pubkey_str_verifier), raw=True)
pubkey_obj_wallet =     PublicKey(unhexlify(pubkey_str_wallet), raw=True)

# for wallet
# use public key instance of verifier and use ecdh method
ecdh_1_wallet = pubkey_obj_verifier.ecdh(unhexlify(privkey_wallet.serialize())).hex()

# for verifier
# create public key instance of wallet and use ecdh method
ecdh_1_verifier = pubkey_obj_wallet.ecdh(unhexlify(privkey_verifier.serialize())).hex()

print(f"ecdh_wallet: \t{ecdh_1_wallet} \necdh_verifier: \t{ecdh_1_verifier}")
if ecdh_1_wallet == ecdh_1_verifier:
    print("I did the ecdh thing!!")

'''
Now create a simple function that takes in the strings and returns a ecdh string
make_shared_secret(string of local private key and string of remote public key)


'''

make_secret_1 = make_shared_secret(privkey_str_wallet,pubkey_str_verifier)
make_secret_2 = make_shared_secret(privkey_str_verifier,pubkey_str_wallet )

print(f"make_secret_1: {make_secret_1} \nmake_secret_2: {make_secret_2}")
assert make_secret_1 == make_secret_2


# Experiment with tweaking
privkey_wallet.tweak_add(unhexlify(make_secret_1))

privkey_wallet.pubkey.tweak_add(unhexlify(make_secret_1))