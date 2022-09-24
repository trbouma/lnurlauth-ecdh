# LNURLAuth ECDH
LNURLAuth ECDH
ECDH version of LNURLAuth

This is in support of a proposed enhancement to [LUD-04: auth base spec](https://github.com/fiatjaf/lnurl-rfc/blob/luds/04.md)
#Rationale

The general idea is to support a secure authentication where k1 is not provably randrom or k1 is a static value (read from a printed QR Code)

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
```
python -m secp256k1 privkey -p
```

# Blinded tokens

[repo](https://gist.github.com/RubenSomsen/be7a4760dd4596d06963d67baf140406)

So, reviewing this again today after seeing @callebtc 's repo, I wanted to make some comments:

First, it's unfortunate that the notation here is kind of opposite to what Wagner originally wrote. Here, Bob is the 'customer' and Alice is the bank (whereas Wagner had it the other way round, probably more intuitive :) with Bob the Bank and Alice the customer). To summarize how Wagner presented it, but with EC additive notation:

Bank publishes K = kG
Alice (customer) picks x and sets Y = Hash-to-curve(x) (basically)
Alice sends to bank: T = Y + rG with r random nonce
Bank sends back kT = Q (these two steps are the blinded DH)
Alice can calculate the blinded DH key as Q - rK = kY + krG - krG = kY = Z
Alice can take the pair (x, Z) as a coin. She gives it to a shop as spending.
The shop can send (x, Z) to the bank who then checks that k* (hash-to-curve(x)) == Z, and if so treats it as a valid spend of a blinded coin, adding it to the spent list.
(as before, I agree with your idea that Alice, here should get a DLEQ proof of K/G vs Q/T to guarantee 'realness' of a coin, albeit since this scheme has to fully trust the bank wrt redemptions, it's debatable I guess?).

To get the security assumptions clear, I think we should first write down the set of properties required, something like:

Unforgeability/ one-more unforgeability - reduce the creation/existence of a spendable coin (including, given earlier ones, i.e. "one more") that hasn't been minted to a known hardness assumption
Anonymity - reduce more than random success in linking a coin spend with the corresponding minting event (as opposed to N other minting events) to a known hardness assumption
Inflation protection - I guess this is just directly implied by the first bullet point, in terms of defending against customers maliciously inflating. We aren't including anything in the security model about the bank; it's fully trusted here, it can censor, inflate, do whatever it wants. So one could look into auditability mechanisms but that's way out of scope I guess.
And finally, as far as I know, the current state of play in academia (and I guess, the real world!) is that "Schnorr blind signature are unsafe". See e.g. https://crypto.stackexchange.com/questions/83219/details-about-ros-attack-on-blind-schnorr-signatures ; the TLDR is "Wagner's attack ++", so it really only shows concretely that you can attack these schemes with parallel execution (as is briefly noted in BIP340 for example), but it's still hairy enough that it should cast big doubt on using them in any situation I guess. I know former and current Wasabi guys (nothingmuch) were aware of this too.

How does that last paragraph affect this kind of thing? I'm really not sure but I'd be surprised if it didn't apply.
