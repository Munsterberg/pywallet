import binascii
import hashlib
import json
from time import time
from collections import OrderedDict
from flask import Blueprint, jsonify, request, jsonify
from uuid import uuid4
from urllib.parse import urlparse
import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

blockchain_blueprint = Blueprint('blockchain', __name__)

MINING_SENDER = 'BLOCKCHAIN'
MINING_REWARD = 1
MINING_DIFFICULTY = 2

class Blockchain:
	def __init__(self):
		self.transactions = []
		self.chain = []
		self.nodes = set()
		self.node_id = str(uuid4()).replace('-', '')
		self.create_block(0, '00')

	def register_node(self, node_url):
		parsed_url = urlparse(node_url)
		if parsed_url.netloc:
			self.nodes.add(parsed_url.netloc)
		elif parsed_url.path:
			self.nodes.add(parsed_url.path)
		else:
			raise ValueError('Invalid URL')

	def verify_transaction_signature(self, sender_address, signature, transaction):
		public_key = RSA.importKey(binascii.unhexlify(sender_address))
		verifier = PKCS1_v1_5.new(public_key)
		h = SHA.new(str(transaction).encode('utf8'))
		return verifier.verify(h, binascii.unhexlify(signature))

	def submit_transaction(self, sender_address, receive_address, value, signature):
		transaction = OrderedDict({
			'sender_address': sender_address,
			'receive_address': receive_address,
			'value': value
		})
		if sender_address == MINING_SENDER:
			self.transactions.append(transaction)
			return len(self.chain) + 1
		else:
			transaction_verification = self.verify_transaction_signature(
				sender_address,
				signature,
				transaction
			)
			if transaction_verification:
				self.transactions.append(transaction)
				return len(self.chain) + 1
			else:
				return False

	def create_block(self, nonce, previous_hash):
		block = {
			'block_number': len(self.chain) + 1,
			'timestamp': time(),
			'transactions': self.transactions,
			'nonce': nonce,
			'previous_hash': previous_hash
		}

		self.transactions = []
		self.chain.append(block)
		return block

	def hash(self, block):
		block_string = json.dumps(block, sort_keys=True).encode()
		return hashlib.sha256(block_string).hexdigest()

	def proof_of_work(self):
		last_block = self.chain[-1]
		last_hash = self.hash(last_block)
		nonce = 0

		while self.valid_proof(self.transactions, last_hash, nonce) is False:
			nonce += 1

		return nonce

	def valid_proof(self, transactions, last_hash, nonce, difficulty=MINING_DIFFICULTY):
		guess = (str(transactions) + str(last_hash) + str(nonce)).encode()
		guess_hash = hashlib.sha256(guess).hexdigest()
		return guess_hash[:difficulty] == '0' * difficulty

	def valid_chain(self, chain):
		last_block = chain[0]
		current_index = 1

		while current_index < len(chain):
			block = chain[current_index]
			if block['previous_hash'] != self.hash(last_block):
				return False
			transactions = block['transactions'][:-1]
			transaction_elements = ['sender_address', 'receive_address', 'value']
			transactions = [
				OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in transactions
			]

			if not self.valid_proof(transactions, block['previous_hash'], block['nonce'], MINING_DIFFICULTY):
				return False

			last_block = block
			current_index += 1

		return True

	def resolve_conflicts(self):
		neighbours = self.nodes
		new_chain = None
		max_length = len(self.chain)

		for node in neighbours:
			print('http://' + node + '/chain')
			response = requests.get('http://' + node + '/chain')

			if response.status_code == 200:
				length = response.json()['length']
				chain = response.json()['chain']

				if length > max_length and self.valid_chain(chain):
					max_length = length
					new_chain = chain

		if new_chain:
			self.chain = new_chain
			return True

		return False

blockchain = Blockchain()

@blockchain_blueprint.route('/transactions/new', methods=['POST'])
def new_transaction():
	post_data = request.get_json()
	response = {
		'status': 'fail'
	}
	if not post_data:
		return jsonify(response), 400
	sender_address = post_data.get('send_address')
	receive_address = post_data.get('receive_address')
	amount = post_data.get('amount')
	signature = post_data.get('signature')

	transaction_result = blockchain.submit_transaction(sender_address, receive_address, amount, signature)
	if transaction_result == False:
		response['message'] = 'Invalid transaction!'
		return jsonify(response), 406
	else:
		response['message'] = f'Transaction added to block {str(transaction_result)}'

@blockchain_blueprint.route('/transactions', methods=['GET'])
def get_transactions():
	transactions = blockchain.transactions
	response = {'transactions', transactions}
	return jsonify(response), 200

@blockchain_blueprint.route('/chain', methods=['GET'])
def chain():
	response = {
		'chain': blockchain.chain,
		'length': len(blockchain.chain)
	}
	return jsonify(response), 200

@blockchain_blueprint.route('/mine', methods=['POST'])
def mine():
	last_block = blockchain.chain[-1]
	nonce = blockchain.proof_of_work()

	blockchain.submit_transaction(
		sender_address=MINING_SENDER,
		receive_address=blockchain.node_id,
		value=MINING_REWARD,
		signature=''
	)
	previous_hash = blockchain.hash(last_block)
	block = blockchain.create_block(nonce, previous_hash)

	response = {
		'message': 'New block created',
		'block_number': block['block_number'],
		'transactions': block['transactions'],
		'nonce': block['nonce'],
		'previous_hash': block['previous_hash']
	}
	return jsonify(response), 200

@blockchain_blueprint.route('/nodes/register', methods=['POST'])
def register_nodes():
	pass

@blockchain_blueprint.route('/nodes/resolve', methods=['GET'])
def resolve_block():
	replaced = blockchain.resolve_conflicts()
	if replaced:
		response = {
			'message': 'Our chain was replaced',
			'new_chain': blockchain.chain
		}
	else:
		response = {
			'message': 'Our chain is authoritative',
			'chain': blockchain.chain
		}
	return jsonify(response), 200

@blockchain_blueprint.route('/nodes/get', methods=['GET'])
def get_nodes():
	nodes = list(blockchain.nodes)
	response = {'nodes', nodes}
	return jsonify(response), 200
