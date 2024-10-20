import os
from flask import Flask, request
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
import base64

app = Flask(__name__)
CORS(app)

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "postgresql+psycopg2://{user}:{passwd}@{host}:{port}/{table}".format(
        user=os.getenv("POSTGRES_USER"),
        passwd=os.getenv("POSTGRES_PASSWORD"),
        host=os.getenv("POSTGRES_HOST"),
        port=5432,
        table=os.getenv("POSTGRES_DB"),
    )
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)


class UserModel(db.Model):
    __tablename__ = "users"
    userID = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)

    def __repr__(self):
        return f"<User {self.username}>"


class Journal(db.Model):
    __tablename__ = "journal"

    postId = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    author_ID = db.Column(db.Integer, db.ForeignKey("users.userID"), nullable=False)
    rela = db.relationship("UserModel", backref="post", lazy=True)

    def serialize(self):
        return {
            "id": self.postId,
            "author_ID": self.author_ID,
            "title": self.title,
            "body": self.body,
            "created_at": self.created_at,
        }


@app.route("/api/savetoday", methods=["POST"])
def create_journal():
    if "authorization" not in request.headers:
        return {"error": "No authorization header detected"}, 403

    encoded = request.headers["authorization"]
    try:
        data = base64.b64decode(encoded).decode("utf-8")
        username, password = data.strip().split(":")
    except (ValueError, base64.binascii.Error):
        return {"error": "Invalid authorization format"}, 400

    user = UserModel.query.filter_by(username=username).first()
    if user is None or not check_password_hash(user.password, password):
        return {"error": "Invalid user"}, 403

    content = request.json
    title = content.get("title")
    body = content.get("body")

    if not title:
        return {"error": "Title is required"}, 400
    if not body:
        return {"error": "Body is required"}, 400

    new_journal = Journal(title=title, body=body, author_ID=user.userID)
    db.session.add(new_journal)
    db.session.commit()

    return {"response": f"{title} posted successfully"}


@app.route("/api/register", methods=["POST"])
def register():
    content = request.json
    username = content.get("username")
    password = content.get("password")

    if not username:
        return {"error": "Username is required"}, 400
    if not password:
        return {"error": "Password is required"}, 400
    if UserModel.query.filter_by(username=username).first():
        return {"error": f"User {username} is already registered"}, 400

    new_user = UserModel(username=username, password=generate_password_hash(password))
    db.session.add(new_user)
    db.session.commit()

    return {"response": f"User {username} created successfully"}


@app.route("/api/login", methods=["POST"])
def login():
    content = request.json
    username = content.get("username")
    password = content.get("password")

    user = UserModel.query.filter_by(username=username).first()
    if user is None or not check_password_hash(user.password, password):
        return {"error": "Invalid credentials"}, 403

    return {"response": "Login Successful"}


@app.route("/api/logs", methods=["GET"])
def get_logs():
    date = request.args.get("date")  # date format = d-m-y

    if "authorization" not in request.headers:
        return {"error": "No authorization header detected"}, 403

    encoded = request.headers["authorization"]
    try:
        data = base64.b64decode(encoded).decode("utf-8")
        username, password = data.strip().split(":")
    except (ValueError, base64.binascii.Error):
        return {"error": "Invalid authorization format"}, 400

    user = UserModel.query.filter_by(username=username).first()
    if user is None or not check_password_hash(user.password, password):
        return {"error": "Invalid user"}, 403

    posts = Journal.query.filter_by(author_ID=user.userID).all()

    data = {}
    for post in posts:
        datetime_str = post.created_at.strftime("%d-%m-%y-%H:%M:%S")
        data[datetime_str] = {"title": post.title, "content": post.body}

    if date in data:
        return {"response": data[date]["content"], "title": data[date]["title"]}
    return {"error": "No post found for the specified date"}, 404


@app.route("/api/dates", methods=["GET"])
def get_dates():
    if "authorization" not in request.headers:
        return {"error": "No authorization header detected"}, 403

    encoded = request.headers["authorization"]
    try:
        data = base64.b64decode(encoded).decode("utf-8")
        username, password = data.strip().split(":")
    except (ValueError, base64.binascii.Error):
        return {"error": "Invalid authorization format"}, 400

    user = UserModel.query.filter_by(username=username).first()
    if user is None or not check_password_hash(user.password, password):
        return {"error": "Invalid user"}, 403

    posts = Journal.query.filter_by(author_ID=user.userID).all()

    output = [{"day": post.created_at.strftime("%d-%m-%y-%H:%M:%S")} for post in posts]
    return {"response": output}


if __name__ == "__main__":
    app.run(debug=True)

