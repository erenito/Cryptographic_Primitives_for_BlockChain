from Crypto.Hash import SHA3_256

def compute_merkle_root(transactions):
    transaction_hashes = [] 
    for tx in transactions:
        hasher = SHA3_256.new()
        hasher.update(tx.encode("utf-8"))  # transactions are strings
        transaction_hashes.append(hasher.digest()) # convert their hashes to bytes

    while len(transaction_hashes) > 1: # keep hashing until we have a single hash (root hash)
        new_hashes = []
        for i in range(0, len(transaction_hashes), 2):
            hasher = SHA3_256.new()
            hasher.update(transaction_hashes[i] + transaction_hashes[i+1])
            new_hashes.append(hasher.digest())
        transaction_hashes = new_hashes

    if transaction_hashes:
        return transaction_hashes[0]
    else:
        return b''

def get_block_pow(TxCnt, lines):
    prevpow_line = lines.pop(0) 
    PrevPoW_ = prevpow_line.split(": ")[1].strip() # string PrevPoW

    nonce_line = lines.pop(0)
    nonce = int(nonce_line.split(": ")[1].strip()) # int nonce

    transactions = []
    for i in range(TxCnt):
        tx_str = "".join(lines[i*9 : (i+1)*9]) # 9 lines per transaction
        transactions.append(tx_str)

    root = compute_merkle_root(transactions) # bytes root hash

    digest = root + PrevPoW_.encode("utf-8") + nonce.to_bytes((nonce.bit_length()+7)//8, byteorder='big') # PoW = SHA256(H_r || PrevPoW || nonce)
    h_obj = SHA3_256.new()
    h_obj.update(digest)
    PoW = h_obj.hexdigest()
    return PoW

def AddBlock2Chain(PoWLen, TxCnt, block_candidate, PrevBlock):
    if PrevBlock == "" or len(PrevBlock) == 0: # if this is the first block
        PrevPoW_ = "0" * 64 # 64 hex characters
    else:
        PoW_prev = get_block_pow(TxCnt, PrevBlock) # get the PoW of the previous block
        PrevPoW_ = PoW_prev # set the previous PoW to the PoW of the previous block

    transactions = []
    for i in range(0, len(block_candidate), 9):
        tx_str = "".join(block_candidate[i : i+9]) 
        transactions.append(tx_str)

    assert len(transactions) == TxCnt, "Transaction count mismatch."

    root_hash = compute_merkle_root(transactions) # get the root hash of the transactions

    target_prefix = "0" * PoWLen 
    nonce = 0
    while True:
        digest = root_hash + PrevPoW_.encode("utf-8") + nonce.to_bytes((nonce.bit_length()+7)//8, byteorder='big')
        hasher = SHA3_256.new()
        hasher.update(digest)
        curr_pow = hasher.hexdigest()

        if curr_pow.startswith(target_prefix):
            break
        nonce += 1

    return "PrevPow: " + PrevPoW_ + "\n" + "nonce: " + str(nonce) + "\n" + "".join(block_candidate), curr_pow
