from blockchain import *
import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
import socket
import threading
from network import *
import json
import re
from pprint import pprint
import time

TIMEOUT = 5
RETRY_COUNT = 1
SENDER_PATTERN = re.compile('^[a-fA-F0-9]{64}$')
SIGNATURE_PATTERN = re.compile('^[a-fA-F0-9]{128}$')

PRINT_LOCK = None

def set_global_lock(lock: threading.Lock):
	global PRINT_LOCK
	PRINT_LOCK = lock


def transaction_bytes(transaction: dict):
	"""converts a Python dict to a serialized json string in bytes"""
	return json.dumps({k: transaction.get(k) for k in ['sender', 'message','nonce']}, sort_keys=True).encode()

def make_transaction(message: str, private_key: ed25519.Ed25519PrivateKey, nonce: int):
	"""make a transaction dictionary"""
	transaction = {'sender': private_key.public_key().public_bytes_raw().hex(), 'message': message, 'nonce': nonce}
	signature = private_key.sign(transaction_bytes(transaction)).hex()
	transaction['signature'] = signature
	return transaction

def make_wrong_signature_transaction(message: str, private_key: ed25519.Ed25519PrivateKey, nonce: int):
	"""for testing invalid transaction format"""
	transaction = {'sender': private_key.public_key().public_bytes_raw().hex(), 'message': message, 'nonce': nonce}
	private_key_wrong = ed25519.Ed25519PrivateKey.generate()
	signature = private_key_wrong.sign(transaction_bytes(transaction)).hex()
	transaction['signature'] = signature
	return transaction


def transaction_to_message_bytes(transaction: dict):
	"""wraps transaction information to send"""
	message_dict = {'type':'transaction','payload':transaction}
	return json.dumps(message_dict).encode()

def message_bytes_to_dict(message: bytes):
	return json.loads(message.decode())
	
def validate_nonce(nonce_transaction: int, blocks: list, sender: str):
	"""
	check if the received nonce @nonce_transaction 
	in the transaction is valid
	"""
	for i in reversed(range(len(blocks))):
		for tx in blocks[i]['transactions']:
			if tx['sender'] == sender:
				if tx['nonce'] + 1== nonce_transaction:
					return True
				else:
					return False	
	if nonce_transaction == 0:
		return True
	return False

def validate_transaction(transaction: dict, blockchain: Blockchain):
	"""
	check if the received @transaciton 
	is valid
	"""
	sender_validation = False
	message_validation = False
	signature_validation = False
	nonce_validation = False
	blocks = blockchain.blockchain
	tx_pool = blockchain.pool

	#saturation
	if len(tx_pool) == blockchain.pool_limit:
		print("Invalid transacion: Pool full")
		return False
	
	#sender format
	if transaction.get('sender') and isinstance(transaction['sender'], str):
		if SENDER_PATTERN.search(transaction['sender']):
			sender_validation = True
		else:
			print("Invalid transacion: Wrong sender pattern")
			return False

	#check signature format
	if transaction.get('signature') and isinstance(transaction['signature'], str):
		signature_validation = SIGNATURE_PATTERN.search(transaction['signature'])

	#message size limitation
	if transaction.get('message') and isinstance(transaction['message'], str):
		message_validation = len(transaction['message']) <= 70 and transaction['message'].isalnum()

	#nonce validation
	if  isinstance(transaction['nonce'], int):
		nonce_validation = validate_nonce(transaction['nonce'], blocks, transaction['sender'])
	
	#verify identity
	if sender_validation and message_validation and signature_validation and nonce_validation:
		try:
			public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(transaction['sender']))
			public_key.verify(bytes.fromhex(transaction['signature']), transaction_bytes(transaction))
			#same user same nonce
			for tx in tx_pool:
				if transaction['sender'] == tx['sender'] and transaction['nonce'] == tx['nonce']:
					return False
			return True
		except:
			return False
	else:
		return False

def respond_to_transaction_request(client_socket: socket.socket, result: bool):
	message = 'false'
	if result:
		message = 'true'
	send_prefixed(client_socket, json.dumps(message).encode())

def server_not_in_remote_nodes(server):
	for remote_node in server.remote_nodes:
		if remote_node:
			if server.host == remote_node.host and server.port == remote_node.port:
				return False
	return True
	

def min_block(blocks: list):
	"""computes the minimum block in from the list of proposed blocks"""
	min_idx = -1
	min_hash = None
	for idx, block in enumerate(blocks):
		if block['transactions']:
			if min_hash:
				if block['current_hash'] < min_hash:
					min_idx = idx
					min_hash = block['current_hash']
			else:
				min_idx = idx
				min_hash = block['current_hash']
	if min_idx == -1:
		return None
	return blocks[min_idx]
	
class RemoteNode():
	def __init__(self, remote_host, remote_port) -> None:
		self.host = remote_host
		self.port = remote_port
		self.remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.remote_socket.connect((remote_host, remote_port))
		self.remote_socket.settimeout(None)  

	def transaction(self, transaction):
		self.remote_socket.settimeout(5)
		try:
			# a round of message exchange
			send_prefixed(self.remote_socket, transaction_to_message_bytes(transaction))
			message_bytes = recv_prefixed(self.remote_socket)
			message = json.loads(message_bytes.decode())
			assert(isinstance(message,str))
			if message == 'true':
				return True
			elif message == 'false':
				return False
			else:
				assert(False)
		except (socket.timeout, ConnectionResetError, ValueError, RuntimeError):
			# If the connection is broken or timed out, retry once
			self.remote_socket.close()
			
			self.remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.remote_socket.settimeout(5)
			try:
				
				self.remote_socket.connect((self.host,self.port))
			except:
				# If retry fails, consider remote node as crashed
				self.remote_socket.close()
		

class ServerRunner():
	def __init__(self, host, port, f) -> None:
		self.blockchain = Blockchain()
		self.host = host
		self.port = port
		self.max_failure = f
		self.server_TCP_thread = None
		self.consensus_thread = None
		self.stop_server = threading.Event()
		self.pool_ready= threading.Event()
		self.pool_ready_time = None
		self.has_waited = False
		self.remote_nodes = []
		self.private_key = ed25519.Ed25519PrivateKey.generate()
		self.proposed_blocks = []
		self.proposed_blocks_lock = threading.Lock()
		global PRINT_LOCK
		if not PRINT_LOCK:
			PRINT_LOCK = threading.Lock()

	def start(self):
		self.server_TCP_thread = threading.Thread(target=self.server_TCP)
		self.server_TCP_thread.start()
		self.consensus_thread = threading.Thread(target=self.consensus_loop)
		self.consensus_thread.start()

	def stop(self):
		if self.stop_server.is_set():
			return
		self.stop_server.set()
		self.server_TCP_thread.join()
		print(f"Port [{self.port}]TCP thread has been closed")
		self.consensus_thread.join()
		print(f"Port [{self.port}]consensus thread has been closed")

	def append(self, remote_node: RemoteNode):
		self.remote_nodes.append(remote_node)

	def server_TCP(self):
		#for server thread logics
		server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server_socket.bind((self.host,self.port))
		server_socket.listen(100)
		print(f"Port [{self.port}] is listening")
		server_socket.settimeout(1)
		while not self.stop_server.is_set():
			try:
				client_socket, _ = server_socket.accept()
				client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
				client_thread.start()
			except socket.timeout:
				pass
		server_socket.close()

	def handle_client(self, client_socket):
		#creates a pipe per incoming connection
		client_socket.settimeout(1)
		while not self.stop_server.is_set():
			try:
				recv_bytes = recv_prefixed(client_socket)
				request = message_bytes_to_dict(recv_bytes)
				self.handle_request(request, client_socket)
			except socket.timeout:
				pass
		

	def handle_request(self,request: dict, client_socket):
		#deals with messages
		if request['type'] == 'transaction':
			transaction = request['payload']
			with PRINT_LOCK:
				print("--------------------------------------------------")
				print(f"Port [{self.port}] received a transaction request")
				pprint(transaction)
			result = validate_transaction(transaction, self.blockchain)
			respond_to_transaction_request(client_socket, result)
			if result:
				self.blockchain.add_transaction(transaction)
				if not self.pool_ready.is_set():
					self.pool_ready.set()
					self.pool_ready_time = time.time()
					with PRINT_LOCK:
						print(f"Port [{self.port}] will wait 2.5s")
			else:
				with PRINT_LOCK:
					print(f"Port [{self.port}] rejected the transaction")
		elif request['type'] == 'values':
			index = request['payload']

			#set flag
			if not self.pool_ready.is_set() and index == len(self.blockchain.blockchain) + 1:
				self.pool_ready.set()
				self.pool_ready_time = time.time()
				with PRINT_LOCK:
					print(f"Port [{self.port}] will wait 2.5s")
			
			#wait for more transactions temporarily
			while time.time() - self.pool_ready_time < 2.5:
				continue
			if self.blockchain.pool:
				proposed_block = self.blockchain.propose_a_block()
				with self.proposed_blocks_lock:
					self.update_proposed_blocks(proposed_block)
			#respond
			with self.proposed_blocks_lock:
				send_prefixed(client_socket, json.dumps(self.proposed_blocks).encode())
			
		
			

	def consensus_loop(self):
		#execute consensus if a trigger is received
		while not self.stop_server.is_set():
			if self.pool_ready.is_set():
				self.consensus_algorithm()
				self.pool_ready.clear()

	def consensus_algorithm(self):
		#handles the consensus logic.
		#modified on the tutorial template
		assert(server_not_in_remote_nodes(self))
		number_of_other_nodes = len(self.remote_nodes)
		assert(number_of_other_nodes >= 2* self.max_failure)
		response_counts = [0] * number_of_other_nodes
		for _ in range(self.max_failure + 1):
			for idx, node in enumerate(self.remote_nodes):
				if node:
					if (not self.request_values(node, response_counts, idx)):
						self.remote_nodes[idx] = None
		can_decide = response_counts.count(self.max_failure + 1) >= number_of_other_nodes - self.max_failure
		if can_decide:
			if not (block:= min_block(self.proposed_blocks)):
				print("No valid block")
			else:
				with PRINT_LOCK:
					print("-------------------------------------")
					print(f"Port [{self.port}] decided a block")
				#print("-----------")
				self.blockchain.add_block(block,PRINT_LOCK)
				self.proposed_blocks = []
		else:
			print("can't decide")

	def update_proposed_blocks(self, block: dict):
		#update the block union
		if block not in self.proposed_blocks:
			self.proposed_blocks.append(block)
			with PRINT_LOCK:
				print("-----------------------------------------------------------")
				print(f"Port [{self.port}] added a block to the proposed block list")
				pprint(block)	
				print(f"Port [{self.port}]'s proposed block list has {len(self.proposed_blocks)} block(s)")
				
	def removed_added_transactions(self, block_decided: dict):
		#remove the transactions decided from the pool 
		decided_transactions = block_decided['transactions']
		for tx_decided in decided_transactions:
			if tx_decided in self.blockchain.pool:
				self.blockchain.pool.remove(tx_decided)


	def request_values(self, node: RemoteNode, response_counts: list, idx: int):
		sock = node.remote_socket
		sock.settimeout(5)

		message = {'type': 'values','payload':len(self.blockchain.blockchain) + 1}
		
		try:
			send_prefixed(sock,json.dumps(message).encode())
			response = recv_prefixed(sock)
			values = json.loads(response.decode())
			if not isinstance(values,list):
				raise ValueError('values not a list')

			if response:
				for block in values:
					with self.proposed_blocks_lock:
						self.update_proposed_blocks(block)
				response_counts[idx] += 1
			#success
			return 1

		except (socket.timeout, ConnectionResetError, ValueError, RuntimeError):
			# If the connection is broken or timed out, retry once
			sock.close()
			node.remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			node.remote_socket.settimeout(5)
			try:
				node.remote_socket.connect((node.host,node.port))
			except:
				# If retry fails, consider remote node as crashed
				node.remote_socket.close()
				return 0
