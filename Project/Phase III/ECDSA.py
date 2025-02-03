from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256
import random

def KeyGen(E):
    n = E.order
    P = E.generator  # Base point

    sA = random.randrange(1, n) # Private key
    QA = sA * P # Public key

    return sA, QA

def SignGen(message, E, sA):
    n = E.order
    P = E.generator

    k = random.randrange(1, n) # random k untill n-1

    R = k * P # R is genereted by the base point 
    r = R.x % n # R.x mod n ; x part of R 

    r_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big') # r to bytes
    hash_input = message + r_bytes # message || r

    h_ = SHA3_256.new(hash_input).digest()  # h = H(m || r) 
    h = int.from_bytes(h_, byteorder='big') % n # h = int(h) mod n 

    s = (k - sA * h) % n  # signature s = (k - sA * h) mod n

    return s, h  # return signature and hashed message  

def SignVer(message, s, h, E, QA):
    n = E.order
    P = E.generator # generator P

    V = s * P + h * QA # V = sP + hQA

    v = V.x % n # v = x mod n

    v_bytes = v.to_bytes((v.bit_length() + 7) // 8, byteorder='big')
    hash_input = message + v_bytes
    u_ = SHA3_256.new(hash_input).digest() # u = H(m || v) mod n
    u = int.from_bytes(u_, byteorder='big') % n

    if u == h: return 0  # accept signature if u == h
    else: return -1