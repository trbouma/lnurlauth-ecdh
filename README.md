# LNURLAuth Low Entropy
LNURLAuth Low Entropy
Low entropy version of LNURLAuth

This is in support of a proposed enhancement to [LUD-04: auth base spec](https://github.com/fiatjaf/lnurl-rfc/blob/luds/04.md)
#Rationale
The general idea is to support a secure authentication where k1 < LOW_ENTROPY_VALUE or k1 is a static value (read from a printed QR Code)

```
this is the code block
```Python
from binascii import unhexlify
from secp256k1 import PublicKey

k1 = unhexlify('e2af6254a8df433264fa23f67eb8188635d15ce883e8fc020989d5f82ae6f11e')
key = unhexlify('02c3b844b8104f0c1b15c507774c9ba7fc609f58f343b9b149122e944dd20c9362')
verkey = unhexlify('')
sig = unhexlify('304402203767faf494f110b139293d9bab3c50e07b3bf33c463d4aa767256cd09132dc5102205821f8efacdb5c595b92ada255876d9201e126e2f31a140d44561cc1f7e9e43d')

pubkey = PublicKey(key, raw=True)
sig_raw = pubkey.ecdsa_deserialize(sig)
r = pubkey.ecdsa_verify(k1, sig_raw, raw=True)

assert r == True
```
