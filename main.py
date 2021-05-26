import numpy as np
import sys
import secrets
import base64


def genkey() -> bytes:
    "generate random 256 bit long key in ascii85"
    tmp = np.empty(4)
    for i in range(4):
        tmp[i] = secrets.randbits(64)
    return (base64.a85encode(tmp))

def decodekey(key: bytes) ->bytes:
    "decode the key encoded in ascii85"
    return (base64.a85decode(key))

def lR(n: np.uint32,d: np.uint32) -> np.uint32:
    """left rotation of int32"""
    return(n<<d)|(n >>(32-d))

def rR(n: np.uint32,d: np.uint32) -> np.uint32:
    """right rotation of int32"""
    return(n>>d)|(n <<(32-d))


if __name__ == "__main__":
    print(sys.argv[1])
    if sys.argv[1] == "-g" or sys.argv[1] == "--generate":
        print(genkey())
    else:
        print(decodekey(sys.argv[1]))
        ((((((([[[[[[{{{{{{{[[]]}}}}}}}]]]]]])))))))
        