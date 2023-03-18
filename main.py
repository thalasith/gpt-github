from flask import Flask
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
import os

app = Flask(__name__)

@app.route("/")
def home():
    return "Hi there!"

if __name__ == '__main__':
    app.run(debug=True, port=os.getenv("PORT", default=5000))
