from flask import Flask

def create_app():
	app = Flask(__name__)

	from blockchain.api.transaction import transaction_blueprint
	app.register_blueprint(transaction_blueprint)
	from blockchain.api.blockchain import blockchain_blueprint
	app.register_blueprint(blockchain_blueprint)

	return app
