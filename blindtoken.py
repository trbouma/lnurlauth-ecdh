import hashlib

from secp256k1 import PrivateKey, PublicKey

def hash_to_point(secret_msg: str):
    """Generates x coordinate from the message hash and checks if the point lies on the curve.
    If it does not, it tries computing again a new x coordinate from the hash of the coordinate."""
    
    point = None
    msg = secret_msg
    while point is None:
        _hash = hashlib.sha256(msg).hexdigest().encode("utf-8")
        try:
            # We construct compressed pub which has x coordinate encoded with even y
            _hash = list(_hash[:33])  # take the 33 bytes and get a list of bytes
            _hash[0] = 0x02  # set first byte to represent even y coord
            _hash = bytes(_hash)
            point = PublicKey(_hash, raw=True)
        except:
            msg = _hash
            print(msg)

    return point


secret_message = bytes("trbouma","utf-8")
print(secret_message)
secret_hash = hashlib.sha256(secret_message).hexdigest().encode("utf-8")
point = hash_to_point(secret_hash)
print(point.serialize().hex())