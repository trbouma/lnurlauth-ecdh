from secp256k1 import PrivateKey, PublicKey

privkey = PrivateKey()
privkey_der = privkey.serialize()

print(privkey_der)
pubprkey = 
print (privkey.pubkey.serialize().hex)

sig = privkey.ecdsa_sign(b'hello')
verified = privkey.pubkey.ecdsa_verify(b'hello', sig)
assert verified

sig_der = privkey.ecdsa_serialize(sig)
sig2 = privkey.ecdsa_deserialize(sig_der)
vrf2 = privkey.pubkey.ecdsa_verify(b'hello', sig2)
assert vrf2

pubkey = privkey.pubkey
pub = pubkey.serialize()



pubkey2 = PublicKey(pub, raw=True)
assert pubkey2.serialize() == pub
assert pubkey2.ecdsa_verify(b'hello', sig)