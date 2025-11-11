from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
# INSECURE: permissive CORS
CORS(app)

# INSECURE: debug left enabled for demonstration (DO NOT use in production)
def create_app():
    app.config.from_object('app.config')
    return app

if __name__ == '__main__':
    # insecure: debug True
    create_app().run(debug=True)