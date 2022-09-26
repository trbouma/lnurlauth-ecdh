from secp256k1 import PrivateKey, PublicKey
import hashlib


# We extend the public key to define some operations on points
# Picked from https://github.com/WTRMQDev/secp256k1-zkp-py/blob/master/secp256k1_zkp/__init__.py
class PublicKeyExt(PublicKey):
    def __add__(self, pubkey2):
        if isinstance(pubkey2, PublicKey):
            new_pub = PublicKey()
            new_pub.combine([self.public_key, pubkey2.public_key])
            return new_pub
        else:
            raise TypeError("Cant add pubkey and %s"%pubkey2.__class__)

    def __neg__(self):
        serialized=self.serialize()
        first_byte, remainder = serialized[:1], serialized[1:]
        # flip odd/even byte
        first_byte = {b'\x03':b'\x02', b'\x02':b'\x03'}[first_byte]
        return PublicKey(first_byte+ remainder, raw=True)

    def __sub__(self, pubkey2):
        if isinstance(pubkey2, PublicKey):
            return self + (-pubkey2)
        else:
            raise TypeError("Can't add pubkey and %s"%pubkey2.__class__)
    
    def mult(self, privkey):
        if isinstance(privkey, PrivateKey):
            return self.tweak_mul(privkey.private_key)
        else:
            raise TypeError("Can't multiply with non privatekey")
    
    def __eq__(self, pubkey2):
        if isinstance(pubkey2, PublicKey):
            seq1 = self.to_data()
            seq2 = pubkey2.to_data()
            return seq1 == seq2
        else:
            raise TypeError("Can't compare pubkey and %s" % pubkey2.__class__)
    
    def to_data(self):
        return [self.public_key.data[i] for i in range(64)]


# Horrible monkeypatching
PublicKey.__add__ = PublicKeyExt.__add__
PublicKey.__neg__ = PublicKeyExt.__neg__
PublicKey.__sub__ = PublicKeyExt.__sub__
PublicKey.mult = PublicKeyExt.mult
PublicKey.__eq__ = PublicKeyExt.__eq__
PublicKey.to_data = PublicKeyExt.to_data


def hash_to_curve(secret_msg):
    """Generates x coordinate from the message hash and checks if the point lies on the curve.
    If it does not, it tries computing again a new x coordinate from the hash of the coordinate."""
    secret_msg = secret_msg.encode("utf-8")
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
            

    return point