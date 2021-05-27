import numpy as np
import sys
import secrets
import base64
import time

ITERATIONS = 10
DECODER = np.vectorize(lambda x: x.decode('UTF-8'))


def xor(data: np.uint32, key: np.uint32) -> bytes:
    """xor the byte arrays of same length"""
    return np.bitwise_xor(key, data)


def genKey() -> bytes:
    """generate random 256-bit long key in ascii85"""
    tmp = np.empty(4)
    for i in range(4):
        tmp[i] = secrets.randbits(64)
    return (base64.a85encode(tmp))


def genNonce() -> np.uint32:
    """generate 96bit nonce"""
    return [np.uint32(secrets.randbits(32)) for _ in range(3)]


def genKeyBlock(key: np.uint32, nonce: np.uint32, counter: np.uint32) -> np.uint32:
    """generate 512-bit block for the specified segment"""

    def QR(a: np.uint32, b: np.uint32, c: np.uint32, d: np.uint32) -> None:
        """chachas quarter round function"""
        a += b
        d = np.bitwise_xor(a, d)
        d = lR(d, 16)
        c += d
        b = np.bitwise_xor(b, c)
        b = lR(b, 12)
        a += b
        d = np.bitwise_xor(d, a)
        d = lR(d, 8)
        c += d
        b = np.bitwise_xor(b, c)
        b = lR(b, 7)
        return (a, b, c, d)

    block = np.uint32([0x65787061, 0x6e642033, 0x322d6279, 0x7465206b,  # "expand 32-byte k" constant
                       key[0], key[1], key[2], key[3],
                       key[4], key[5], key[6], key[7],
                       nonce[0], nonce[1], nonce[2], counter])
    for _ in range(ITERATIONS):
        # odd round
        block[0], block[4], block[8], block[12] = QR(
            block[0], block[4], block[8], block[12])  # column 1
        block[1], block[5], block[9], block[13] = QR(
            block[1], block[5], block[9], block[13])  # column 2
        block[2], block[6], block[10], block[14] = QR(
            block[2], block[6], block[10], block[14])  # column 3
        block[3], block[7], block[11], block[15] = QR(
            block[3], block[7], block[11], block[15])  # column 4
        # even round - diagonals starting from main and then going up
        block[0], block[5], block[10], block[15] = QR(
            block[0], block[5], block[10], block[15])
        block[1], block[6], block[11], block[12] = QR(
            block[1], block[6], block[11], block[12])
        block[2], block[7], block[8], block[13] = QR(
            block[2], block[7], block[8], block[13])
        block[3], block[4], block[9], block[14] = QR(
            block[3], block[4], block[9], block[14])
    return (block)


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
    start = time.perf_counter()
    nonce = genNonce()
    key = np.frombuffer(decodekey(genKey()), np.uint32)
    secret = np.frombuffer(bytes(
        "Notice that this version updates each word twice, while Salsa20'", 'utf-8'), dtype=np.uint32)
    block = genKeyBlock(key, nonce, 0)

    coded = xor(secret, block)
    print(xor(coded, block).tobytes().decode())
    end = time.perf_counter()
    print(end - start)
    if sys.argv[1] == "-g" or sys.argv[1] == "--generate":
        print(genkey())
    else:
        print(decodekey(sys.argv[1]))
