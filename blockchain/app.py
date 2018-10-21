from flask import Flask

def create_app():
	app = Flask(__name__)

	from blockchain.api.transaction import transaction_blueprint
	app.register_blueprint(transaction_blueprint)

	return app
