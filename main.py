import numpy as np
import sys
import secrets
import base64


def xor(data: bytes, key: bytes) -> bytes:
    """xor the byte arrays of same length"""
    key = np.frombuffer(key, np.int64)
    data = np.frombuffer(data, np.int64)
    xored = np.bitwise_xor(key, data)
    return xored.tobytes()


def genKey() -> bytes:
    """generate random 256 bit long key in ascii85"""
    tmp = np.empty(4)
    for i in range(4):
        tmp[i] = secrets.randbits(64)
    return (base64.a85encode(tmp))

def genNonce():
    return [np.uint32(secrets.randbits(32)) for _ in range(3)]

def genKeyBlock(key: np.uint32, nonce: np.uint32,counter: np.uint32) -> bytes:
    block = [np.int32(0x65787061), np.int32([0x6e642033]), np.int32([0x322d6279]), np.int32([0x7465206b]),  # "expand 32-byte k" constant
             key[0], key[1], key[2], key[3],
             key[4], key[5], key[6], key[7],
             nonce[0],nonce[1],nonce[2],counter]
    None


def decodekey(key: bytes) -> bytes:
    """decode the key encoded in ascii85"""
    return (base64.a85decode(key))


def lR(n: np.int64, d: np.int64) -> np.uint32:
    """left rotation of int32"""
    return(n << d) | (n >> (32-d))


def rR(n: np.int64, d: np.int64) -> np.uint32:
    """right rotation of int32"""
    return(n >> d) | (n << (32-d))


if __name__ == "__main__":
    nonce = genNonce()
    key = decodekey(genKey())
    key = np.frombuffer(key,dtype=np.uint32)
    genKeyBlock(key)
    print(sys.argv[1])
    if sys.argv[1] == "-g" or sys.argv[1] == "--generate":
        print(genkey())
    else:
        print(decodekey(sys.argv[1]))
