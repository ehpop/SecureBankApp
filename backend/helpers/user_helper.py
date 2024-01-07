from database import db, Users


class UserHelper:
    def __init__(self):
        pass

    @staticmethod
    def get_user(username: str):
        return Users.query.where(Users.us_lgn == username).first()

    def get_user_by_account_number(self, account_number: str):
        return Users.query.where(Users.us_act_nb == account_number).first()

    def save_user(self, user: Users):
        db.session.add(user)
        db.session.commit()

    def update_user(self, user: Users):
        db.session.commit()

    def delete_user(self, user: Users):
        db.session.delete(user)
        db.session.commit()

    def get_all_users(self) -> [Users]:
        return Users.query.all()

    def get_all_usernames(self):
        return [user.us_lgn for user in Users.query.all()]
