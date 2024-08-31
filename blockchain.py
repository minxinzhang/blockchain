import json
import hashlib
import threading
from pprint import pprint

class Blockchain():
    def  __init__(self):
        self.blockchain = []
        self.pool = []
        self.pool_limit = 3
        self.new_block('0' * 64)

        self.on_new_block = None

    def filter_block(self, block: dict):
        transactions = block['transactions']
        valid_transactions = []
        for tx in transactions:
            if not valid_transactions:
                valid_transactions.append(tx)
                # pprint(f"Added {tx}")
            else:
                same_nonce_sender = False
                for vtx in valid_transactions:
                    if (vtx['sender'] == tx['sender'] and vtx['nonce'] == tx['nonce']):
                        same_nonce_sender = True
                        break
                if not same_nonce_sender:
                   valid_transactions.append(tx) 
        #print(f"size of valid transactions {len(filtered_block)}")
        filtered_block = {'index':block['index'],\
                          'transactions': valid_transactions,\
                          'previous_hash':block['previous_hash'],\
                          'current_hash':block['current_hash']}
        return filtered_block
        
    def add_block(self, block: dict, lock: threading.Lock):
        filtered_block = self.filter_block(block)
        self.blockchain.append(filtered_block)
        if self.on_new_block is not None:
            self.on_new_block(filtered_block)
        
        ptx_to_remove = []

        for tx in filtered_block['transactions']:
            for ptx in self.pool:
                if tx['sender'] == ptx['sender'] and tx['nonce'] == ptx['nonce']:
                    ptx_to_remove.append(ptx)

        for ptx in ptx_to_remove:
            self.pool.remove(ptx)
        if self.pool:
            with lock:
                print("Transaction pool remaining: ")
                pprint(self.pool)

    def new_block(self, previous_hash=None):
        block = {
			'index': len(self.blockchain) + 1,
			'transactions': self.pool.copy(),
			'previous_hash': previous_hash or self.blockchain[-1]['current_hash'],
		}
        block['current_hash'] = self.calculate_hash(block)
        self.pool = []
        self.blockchain.append(block)

    def propose_a_block(self):
       
        block = {
            'index': len(self.blockchain) + 1,
            'transactions': self.pool.copy(),
            'previous_hash': self.blockchain[-1]['current_hash'],
        }
        block['current_hash'] = self.calculate_hash(block)
        return block

    def last_block(self):
        return self.blockchain[-1]

    def calculate_hash(self, block: dict):
        block_object: str = json.dumps({k: block.get(k) for k in ['index', 'transactions', 'previous_hash']}, sort_keys=True)
        block_string = block_object.encode()
        raw_hash = hashlib.sha256(block_string)
        hex_hash = raw_hash.hexdigest()
        return hex_hash

    def add_transaction(self, transaction):
        if len(self.pool) < self.pool_limit:
            self.pool.append(transaction)
            return True
        return False

    def set_on_new_block(self, on_new_block):
        self.on_new_block = on_new_block
