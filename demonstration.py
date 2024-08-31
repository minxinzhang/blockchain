from node import *
import threading
from pprint import pprint

PRINT_LOCK = threading.Lock()
#set stdout print lock
set_global_lock(PRINT_LOCK)
# private keys for transactions
# 1st identity
private_key1 = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex('6dee02b55d8914c145568cb3f3b84586ead2a85910f5b062d7f3f29ddcb4c7aa'))
# 2nd identity
private_key2 = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex('6dee02b55d8914c145568cb3f3b84586ead2a85910f5b062d7f3f29ddcb4c7ab'))
# 3rd identity
private_key3 = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex('6dee02b55d8914c145568cb3f3b84586ead2a85910f5b062d7f3f29ddcb4c7ac'))
# 4th identity
private_key4 = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex('6dee02b55d8914c145568cb3f3b84586ead2a85910f5b062d7f3f29ddcb4c7ad'))

# create 6 nodes tolerating 2 failures
runners = [ServerRunner('localhost', 9000 + i, f=2) for i in range(6)]

# start accepting incoming connections
for runner in runners:
	runner.start()

# connect other nodes
for i, runner in enumerate(runners):
	for j in range(6):
		if i != j:
			runner.append(RemoteNode('localhost', 9000 + j))

# create clients to send transactions
clients = [RemoteNode('localhost', 9000 + i) for i in range(6)]

# create testing transactions 
transaction10 = make_transaction('sender1', private_key1, 0)
transaction20 = make_transaction('sender2', private_key2, 0)
transaction30 = make_transaction('sender3', private_key3, 0)
transaction40 = make_transaction('sender4', private_key4, 0)
transaction10dup = make_transaction('sender1', private_key1, 0)

transaction11 = make_transaction('sender1', private_key1, 1)
transaction21 = make_transaction('sender2', private_key2, 1)
transaction31 = make_transaction('sender3', private_key3, 1)
transaction_wrong_signature = make_wrong_signature_transaction('hello1',private_key1,0)
too_long_message = '1' * 71
transaction_wrong_format1 = make_transaction(too_long_message,private_key1,0)

# set block callback
lock = threading.Lock()
cond = threading.Condition(lock)
blocks = []
def on_new_block(block):
	with lock:
		blocks.append(block)
		cond.notify()
for runner in runners:
	runner.blockchain.set_on_new_block(on_new_block)

# 1st consensus round
with PRINT_LOCK:
	print("======================")
	print("start deciding index 2")
	print("======================")
#wrong nonce
assert(clients[0].transaction(transaction11) == False)

assert(clients[0].transaction(transaction_wrong_signature) == False)
assert(clients[0].transaction(transaction_wrong_format1) == False)

#correct nonce
assert(clients[0].transaction(transaction10) == True)

#same user #same nonce
assert(clients[0].transaction(transaction10dup) == False)
assert(clients[1].transaction(transaction10dup) == True)

#different senders correct nonce multiple transactions in a block
assert(clients[0].transaction(transaction20) == True)
assert(clients[0].transaction(transaction30) == True)

#full pool
assert(clients[0].transaction(transaction40) == False)


# wait for the block from all nodes
with lock:
	cond.wait_for(lambda: len(blocks) == len(runners))


#only transaction10 dup block got accepted because of its lower hash
assert(all([len(block['transactions']) == 1 for block in blocks]))
assert(all([block['transactions'][0] == transaction10dup for block in blocks]))

#two transactions remaining in server 0 pool while other pools are empty
assert(len(runners[0].blockchain.pool) == 2)
assert(all(len(runners[i].blockchain.pool) == 0 for i in range(1,6)))

#round 3
with PRINT_LOCK:
	print("===================================")
	print("start deciding index 3 in 5 seconds")
	print("===================================")
time.sleep(5)
lock = threading.Lock()
cond = threading.Condition(lock)
blocks = []
def on_new_block(block):
	with lock:
		blocks.append(block)
		cond.notify()
for runner in runners:
	runner.blockchain.set_on_new_block(on_new_block)

#wrong nonce
assert(clients[0].transaction(transaction10) == False)
assert(clients[0].transaction(transaction21) == False)

#transaction20 still in server 0 pool
assert(clients[0].transaction(transaction20) == False)

#correct nonce
assert(clients[1].transaction(transaction11) == True)
assert(clients[5].transaction(transaction30) == True)

with lock:
	cond.wait_for(lambda: len(blocks) == len(runners))

#transaction11 accepted
assert(all([len(block['transactions']) == 1 for block in blocks]))
assert(all([block['transactions'][0] == transaction11 for block in blocks]))

#transaction 20 and 30 still in server 0 pool
assert(len(runners[0].blockchain.pool) == 2)

#transaction 30 in server 5 pool
assert(len(runners[5].blockchain.pool) == 1)


#round 4
with PRINT_LOCK:
	print("===================================")
	print("start deciding index 4 in 5 seconds")
	print("===================================")
time.sleep(5)
lock = threading.Lock()
cond = threading.Condition(lock)
blocks = []
def on_new_block(block):
	with lock:
		blocks.append(block)
		cond.notify()
for runner in runners:
	runner.blockchain.set_on_new_block(on_new_block)

#wrong nonce for transaction 21
assert(clients[4].transaction(transaction21) == False)

#transaction40 is accepted
assert(clients[0].transaction(transaction40) == True)

with lock:
	cond.wait_for(lambda: len(blocks) == len(runners))

#decided block has only 1 transaction transaction 30
assert(all([len(block['transactions']) == 1 for block in blocks]))
assert(all([block['transactions'][0] == transaction30 for block in blocks]))


# transaction 20 40 in pool 0
assert(len(runners[0].blockchain.pool) == 2 )
assert(all(len(runners[i].blockchain.pool) == 0 for i in range(1,6)))

# round 5 #1 node failure

lock = threading.Lock()
cond = threading.Condition(lock)
blocks = []
def on_new_block(block):
	with lock:
		blocks.append(block)
		cond.notify()
for runner in runners:
	runner.blockchain.set_on_new_block(on_new_block)

#kill one server
with PRINT_LOCK:
	print("==============================================================")
	print("start deciding index 5 in 5 seconds one node has been disabled")
	runners[4].stop()
	print("==============================================================")
time.sleep(5)


#transaction31 has a correct nonce this round
assert(clients[0].transaction(transaction21) == False)
assert(clients[0].transaction(transaction31) == True)

with lock:
	cond.wait_for(lambda: len(blocks) == len(runners) - 1)

#only 5 blocks decided a block of 3 transactions
assert(len(blocks) == len(runners) - 1)

assert(all([block['transactions'][0] == transaction20 for block in blocks]))
assert(all([block['transactions'][1] == transaction40 for block in blocks]))
assert(all([block['transactions'][2] == transaction31 for block in blocks]))

# ronud 6: 2 nodes failure
lock = threading.Lock()
cond = threading.Condition(lock)
blocks = []
def on_new_block(block):
	with lock:
		blocks.append(block)
		cond.notify()
for runner in runners:
	runner.blockchain.set_on_new_block(on_new_block)

with PRINT_LOCK:
	print("================================================================")
	print("start deciding index 6 in 5 seconds two nodes have been disabled")
	runners[3].stop()
	print("================================================================")
time.sleep(5)

assert(clients[0].transaction(transaction21) == True)

with lock:
	cond.wait_for(lambda: len(blocks) == len(runners) - 2)

# 4 nodes decided blocks
assert(len(blocks) == len(runners) - 2)


# shut down
for runner in runners:
	runner.stop()





