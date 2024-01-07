from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Users(db.Model):
    us_nme = db.Column(db.String, nullable=False)
    us_hsh = db.Column(db.String, nullable=False)
    us_lgn = db.Column(db.String, primary_key=True)
    us_act_nb = db.Column(db.String, unique=True, nullable=False)
    us_crd_nb = db.Column(db.String, unique=True, nullable=False)
    us_blnc = db.Column(db.Integer, nullable=False)


class UserCredentials(db.Model):
    cmb_id = db.Column(db.Integer, primary_key=True)
    usr_id = db.Column(db.String, nullable=False)
    pswd_ltrs_nmbrs = db.Column(db.String, nullable=False)
    hsh_val = db.Column(db.String, nullable=False)
    slt_id = db.Column(db.Integer, db.ForeignKey("salts.slt_id"))


class Salts(db.Model):
    slt_id = db.Column(db.Integer, primary_key=True)
    slt_vl = db.Column(db.String, nullable=False)


class Transactions(db.Model):
    trns_id = db.Column(db.Integer, primary_key=True)
    act_frm = db.Column(db.String, db.ForeignKey("users.us_act_nb"))
    act_to = db.Column(db.String, db.ForeignKey("users.us_act_nb"))
    trns_amt = db.Column(db.Integer, nullable=False)
    trns_dt = db.Column(db.String, nullable=False)
    trns_ttl = db.Column(db.String, nullable=False)


class Documents(db.Model):
    dcm_id = db.Column(db.Integer, primary_key=True)
    dcm_cnt = db.Column(db.String, nullable=False)
    dcm_sze = db.Column(db.Integer, nullable=False)
    dcm_ad_dt = db.Column(db.String, nullable=False)
    dcm_ttl = db.Column(db.String, nullable=False)
    own_id = db.Column(db.String, db.ForeignKey("users.us_lgn"))
    # owner = db.relationship("User", backref="documents")
