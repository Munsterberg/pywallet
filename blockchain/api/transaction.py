from flask import Blueprint, jsonify, request
from collections import OrderedDict
import binascii
import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

transaction_blueprint = Blueprint('transaction', __name__)

class Transaction:
	def __init__(self, sender_address: str, sender_priv_key: str, receive_address: str, value: int) -> None:
		self.sender_address = sender_address
		self.sender_priv_key = sender_priv_key
		self.receive_address = receive_address
		self.value = value

	def __getattr__(self, attr: str):
		return self.data[attr]

	def to_dict(self):
		return OrderedDict({
			'sender_address': self.sender_address,
			'receive_address': self.receive_address,
			'value': self.value
		})

	def sign_transaction(self):
		private_key = RSA.importKey(binascii.unhexlify(self.sender_priv_key))
		signer = PKCS1_v1_5.new(private_key)
		h = SHA.new(str(self.to_dict()).encode('utf8'))
		return binascii.hexlify(signer.sign(h)).decode('ascii')

@transaction_blueprint.route('/wallet/new', methods=['GET'])
def new_wallet():
	random_gen = Crypto.Random.new().read
	private_key = RSA.generate(1024, random_gen)
	public_key = private_key.publickey()

	response = {
		'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
		'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
	}
	return jsonify(response), 200

@transaction_blueprint.route('/generate/transaction', methods=['POST'])
def generate_transaction():
	post_data = request.get_json()
	response = {
		'status': 'fail'
	}
	if not post_data:
		return jsonify(response), 400
	sender_address = post_data.get('sender_address')
	sender_priv_key = post_data.get('sender_priv_key')
	receive_address = post_data.get('receive_address')
	value = post_data.get('value')

	transaction = Transaction(sender_address, sender_priv_key, receive_address, value)

	response = {
		'status': 'success',
		'transaction': transaction.to_dict(),
		'signature': transaction.sign_transaction()
	}
	return jsonify(response), 200
