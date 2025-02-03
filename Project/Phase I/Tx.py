import random
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

