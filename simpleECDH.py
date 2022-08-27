from secp256k1 import PrivateKey, PublicKey

from binascii import unhexlify
import binascii,os
import secp256k1

def make_shared_secret(privkey_local_str : str, pubkey_remote_str: str):
    ''' Simple ECDH - accepts string versions of private key and public key
        privkey_local_str is the hex string of the wallet private key
        pubkey_remote_str is the hex string on the verifier public key
        returns the ecdh shared secret as a hex string
    '''

    privkey_local_obj = PrivateKey(bytes(bytearray.fromhex(privkey_local_str)), raw=True)
    pubkey_verifier_obj =   PublicKey(unhexlify(pubkey_remote_str), raw=True)

    return pubkey_verifier_obj.ecdh(unhexlify(privkey_local_obj.serialize())).hex()
