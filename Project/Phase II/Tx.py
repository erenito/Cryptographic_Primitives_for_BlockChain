import random
import os
import DS

def gen_random_tx(q, p, g):
    payer_alpha, payer_beta = DS.KeyGen(q, p, g)
    
    payee_beta = random.getrandbits(2048)  # 2048-bit random integer
    serial_number = random.getrandbits(128)  # 128-bit random integer
    amount = random.randint(1, 1000000)  # Random amount in range 1 to 1000000

    message2sign = (
        f"Serial number: {serial_number}\n"
        f"Amount: {amount}\n"
        f"Payee public key (beta): {payee_beta}\n"
        f"Payer public key (beta): {payer_beta}\n"
    )
    
    # Generate the signature
    sign_s, sign_h = DS.SignGen(message2sign.encode('UTF-8'), q, p, g, payer_alpha)

    # Return the transaction
    transaction = (
        "*** Bitcoin transaction ***\n"
        f"Signature (s): {sign_s}\n"
        f"Signature (h): {sign_h}\n"
        f"Serial number: {serial_number}\n"
        f"Amount: {amount}\n"
        f"Payee public key (beta): {payee_beta}\n"
        f"Payer public key (beta): {payer_beta}\n"
    )
    
    return transaction


def powerOf2(n): # check if n is a power of 2

    if n <= 0: # if its negative or zero return False
        return False
    while n % 2 == 0: # while n is divisible by 2
        n = n //  2  # integer division 
    return n == 1 # if n is 1 then it is a power of 2

def gen_random_txblock(q, p, g, TxCnt, filename):

    if (powerOf2(TxCnt)==False): # tx count must be power of 2
        print("TxCnt must be power of 2")
        return
    
    f = open(filename, "w")  # opening file for writing
    
    for i in range(TxCnt): # loop for TxCnt times
        f.write(gen_random_tx(q, p, g)) # calling function phase 1  to generate ranom transaction 
    f.close()


