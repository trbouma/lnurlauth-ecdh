

import hashlib
from secp import PrivateKey, PublicKey, hash_to_curve




"""
Implementation of https://gist.github.com/RubenSomsen/be7a4760dd4596d06963d67baf140406
Alice:
A = a*G
return A
Bob:
Y = hash_to_curve(secret_message)
r = random blinding factor
B'= Y + r*G
return B'
Alice:
C' = a*B'
  (= a*Y + a*r*G)
return C'
Bob:
C = C' - r*A
 (= C' - a*r*G)
 (= a*Y)
return C, secret_message
Alice:
Y = hash_to_curve(secret_message)
C == a*Y
If true, C must have originated from Alice
"""

def step1_bob(secret_msg):
    secret_msg = secret_msg.encode("utf-8")
    Y = hash_to_curve(secret_msg)
    r = PrivateKey()
    B_ = Y + r.pubkey
    return B_, r


def step2_alice(B_, a):
    C_ = B_.mult(a)
    return C_

def step3_bob(C_, r, A):
    C = C_ - A.mult(r)
    return C

def verify(a, C, secret_msg):
    Y = hash_to_curve(secret_msg.encode("utf-8"))
    return C == Y.mult(a)

### Below is a test of a simple positive and negative case

# # Alice's keys
a = PrivateKey()
A = a.pubkey
secret_msg = "test timbouma"
B_, r = step1_bob(secret_msg)
C_ = step2_alice(B_, a)
C = step3_bob(C_, r, A)
print("C:{}, secret_msg:{}".format(C.serialize(compressed=True).hex(), secret_msg))
assert verify(a, C, secret_msg)
assert verify(a, C + C, secret_msg) == False  # adding C twice shouldn't pass
assert verify(a, A, secret_msg) == False  # A shouldn't pass

# # Test operations
# b = PrivateKey()
# B = b.pubkey
# assert -A -A + A == -A  # neg
# assert B.mult(a) == A.mult(b)  # a*B = A*b