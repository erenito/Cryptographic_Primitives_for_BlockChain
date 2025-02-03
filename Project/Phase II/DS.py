from hashlib import sha3_256
import secrets
import sys
import os
import string
import warnings
from Crypto.Util.number import getPrime, isPrime, inverse
from random import choices, randint

import sympy


def GenerateOrRead(file_name):
    if not os.path.isfile(file_name):
        (p, q, g) = generate_dsa_parameters()
        f = open(file_name, "w")
        f.write(str(q) + "\n")
        f.write(str(p) + "\n")
        f.write(str(g) + "\n")
        f.close()
    else:
        f = open(file_name, "r")
        q = int(f.readline())
        p = int(f.readline())
        g = int(f.readline())
        f.close()
    return (q, p, g)

def generate_dsa_parameters():
    # generate q as 224 bit prime
    q = getPrime(224)

    # generate p as p divides q+1 and p is 2048 bit prime
    while True:
        

        #gnerate a coefficent for q 
        a = 2048 - 224  # we know that p = kq + 1 and p is 2048 bit q is 224 bit k shoukd be this many bit
        k = randint(2**(a-1), 2**(a)- 1)  # k range 
        
        p = k * q + 1 #p bit number is 2048  and equation 
        #print(p.bit_length())
        #print(p)
        if p.bit_length() == 2048 and isPrime(p):  # Check if p is prime and bit number holds
            break # exit the loop

   
   # g generation g^q ≡1 mod p.
    while True:
        # alpha refers to secret  which is random 
    
        alpha = randint(2, p - 2)  # Random alpha in range [2, p-2] cannot be 1 
        b = (p - 1) // q
        g = pow(alpha,b , p)  # g = alpha^((p-1)/q) mod p
        if g != 1:
            break

 
    return p, q, g 

def KeyGen(q, p, g):
    # private key a 
    a = randint(1, q - 2)  # betwen 0 and q-1

    # public key beta
    beta = pow(g, a, p)
    
    return a, beta

def SignGen(message, q, p, g, alpha):
    # k in range [1, q-2]
    k = randint(1, q - 2)

    #  r = g^k mod p
    r = pow(g, k, p)

    # h = SHA3_256(m || r) (mod q)
    # first convert r to bytes
    r_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
    
    # hash input is the concetanation of message and r which is byte sum 
    hash_input = message + r_bytes

    #hashing the input
    hashh = sha3_256(hash_input).digest()
    #print(hashh) the outout need to converted to int
    h = int.from_bytes(hashh, 'big') % q  
  
    #  s = (k - alpha * h) (mod q)
    s = (k - alpha * h) % q
    
    return s, h


def SignVer(message, s, h, q, p, g, beta):
    # v = g^s * beta^h (mod p)
    v = (pow(g, s, p) * pow(beta, h, p)) % p
    
    # u = SHA3_256(m || v) (mod q)
    v_bytes = v.to_bytes((v.bit_length() + 7) // 8, byteorder='big')
    hash_input = message + v_bytes
    hashh = sha3_256(hash_input).digest()
    u = int.from_bytes(hashh, 'big') % q
    
    # accept signature if u == h
    if u == h: 
        return 0
    else:
        return -1

def random_string(length):
    lowercase_letters = "abcdefghijklmnopqrstuvwxyz"
    uppercase_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    digits = "0123456789"
    punctuation = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
    chars = lowercase_letters + uppercase_letters + digits + punctuation
    return ''.join(choices(chars, k=length))

