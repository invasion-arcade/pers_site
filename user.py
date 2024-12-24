from flask_login import UserMixin

from db import get_db

class User(UserMixin):
    def __init__(self, id_, name):
        self.id = id_
        self.name = name

    @staticmethod
    def get(user_id):
        db = get_db()
        user = db.execute(
            "SELECT * FROM user WHERE id = ?", (user_id,)
        ).fetchone()
        if not user:
            return None

        user = User(
            id_=user[0], name=user[1]
        )
        return user

    @staticmethod
    def create(id_, name):
        db = get_db()
        db.execute(
            "INSERT INTO user (id, name) "
            "VALUES (?, ?)",
            (id_, name),
        )
        db.commit()