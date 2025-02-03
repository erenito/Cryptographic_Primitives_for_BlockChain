from Crypto.Hash import SHA3_256
import random

def compute_merkle_root(transactions):
    transaction_hashes = []
    for tx in transactions: 
        hasher = SHA3_256.new() #  hash of each transaction
        hasher.update(tx.encode("utf-8")) # since transactions are strings encodeing them to bytes
        transaction_hashes.append(hasher.digest()) # adding the byte hash to the list

    while len(transaction_hashes) != 1: # when there is more than one hash in the list
        new_hashes = [] #  list to store the new hashes
        for i in range(0, len(transaction_hashes), 2): # Iterate transaction hashes in pairs two by two 
            hasher = SHA3_256.new()
            hasher.update(transaction_hashes[i] + transaction_hashes[i+1]) # calculate the hash of the concatenated hashes
            new_hashes.append(hasher.digest()) # append the new hash to the new list 
        transaction_hashes = new_hashes # replace the old list with the new list

    if transaction_hashes[0]: # if there is a hash in the list
        return transaction_hashes[0] # return the hash
    else: return b''   # else return an empty byte string 

def CheckPow(p, q, g, PoWLen, TxCnt, filename): 
    with open(filename, "r") as f: # open the file in read mode
        block = f.readlines()

    nonce = int(block[0][7:-1]) # extract the nonce from the first line of the block 

    transactions = []
    for i in range(1, len(block[1:]), 7):  # loop through each block and extract the transactions 
        tx_str = "".join(block[i:i+7]) # concatenate the lines in the block with join function
        transactions.append(tx_str)   # add the transaction to the list

    assert TxCnt == len(transactions)  # check if the number of transactions is equal to the TxCnt  if not raise an assertion error 

    root_hash = compute_merkle_root(transactions)  # compute hash root of the merkle tree of the transactions 
    print("H_r:", root_hash)
    
    hasher = SHA3_256.new() 
    hasher.update(root_hash + nonce.to_bytes((nonce.bit_length() + 7) // 8, byteorder='big')) # calculate the hash of the combined value
    hash_value = hasher.hexdigest()  # getting the hexdigest of the hash 

    target_prefix = "0" * PoWLen  #  target prefix is a string of 0s of length powlen 
    if hash_value.startswith(target_prefix):  # checks if the hash value starts with the target prefix
        return hash_value  # if so return the hash value
    else:
        return "" # else return an empty string 
    

def PoW(PoWLen, q, p, g, TxCnt, filename):  
    with open(filename, "r") as f: # open the file in read mode
        block = f.readlines()

    transactions = []   # list to store the transactions 
    for i in range(0, len(block), 7):  # loop through the block and extract the transactions
        tx_str = "".join(block[i:i+7])  # concatenate the lines in the block with join function
        transactions.append(tx_str) #  add the transaction to the list
    
    assert TxCnt == len(transactions)  # check if the number of transactions is equal to the TxCnt  if not raise an assertion error 
    
    root_hash = compute_merkle_root(transactions)  # compute the merkle root of the transactions 
    
    target_prefix = "0" * PoWLen  #  target prefix is a string of 0s of length powlen    

    while True: 
        nonce = random.getrandbits(256)   # generate a random 256 bit number  as a nonce 
        combined = root_hash + nonce.to_bytes((nonce.bit_length() + 7) // 8, byteorder='big')  # concatenate the root hash and nonce with bytes
        hasher = SHA3_256.new() # create a new hash object
        hasher.update(combined) # calculate the hash of the combined value
        hash_value = hasher.hexdigest()  # get the hexdigest of the hash

        if hash_value.startswith(target_prefix):    #  checks if the hash value starts with the target prefix
            return "Nonce: " + str(nonce) + "\n" + "".join(block)   # if so return the nonce and the block   