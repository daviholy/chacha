# coding=utf-8
import numpy as np
import sys
import secrets
import base64
import time
import math

ROUNDS = 10

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
    for _ in range(ROUNDS):
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
    if len(sys.argv) < 2:
        exit()
    if sys.argv[1] == "-g" or sys.argv[1] == "--generate":
        print(genKey())
        exit()
    else:
        index =[i for i, s in enumerate(sys.argv) if "-k" in s or "--key" in s]
        if index == []:
            print("please specify key")
            exit()
        key = decodekey(sys.argv[index + 1])
        index = [i for i, s in enumerate(sys.argv) if "-f" in s or "--file" in s]
        if index ==[]:
            text = sys.argv[len(sys.argv) -1]
            if [i for i, s in enumerate(sys.argv) if "-d" in s or "--decode" in s] != []:
                nonce = text[0:13]
            else:
                nonce = genNonce()
                print(nonce.tobytes().encode("utf-8"), end="")
        else:
            with open(sys.argv[index + 1]) as file:
                if [i for i, s in enumerate(sys.argv) if "-d" in s or "--decode" in s] != []:
                    nonce = file.read(12)
                else:
                    nonce =  genNonce()
                    print(nonce.tobytes().decode("utf-8"), end="")
                text = file.read()

    res ="".encode("utf-8")
    iteration = len(text) / 64
    isFloat = False
    if not iteration.is_integer():
        isFloat = True
    iteration = math.floor(iteration)
    for i in range(iteration):
        block = genKeyBlock(key, nonce, i).view(np.uint8)
        res += np.bitwise_xor(np.bitwise_xor(secret[i*64:64*i+64], block),block).tobytes()
    if isFloat:
        block = genKeyBlock(key, nonce, iteration + 1).view(np.uint8)
        res += np.bitwise_xor(np.bitwise_xor(secret[iteration*64:64*iteration+(len(secret)-iteration *64)], block[:(len(secret)-iteration *64)]),block[:(len(secret)-iteration *64)]).tobytes()
    print(res.decode('utf-8'))
