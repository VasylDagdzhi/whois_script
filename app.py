import os
import sys
import main

sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask

app = Flask(__name__)


@app.route('/')
def hello():
    return 'Hello, World!'


main.begin("ljnero.us")
