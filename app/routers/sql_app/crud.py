from sqlalchemy.orm import Session

from . import models, schema

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()


def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()


def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit).all()

def get_items(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Item).offset(skip).limit(limit).all()

def create_user(db: Session, user: schema.UserCreate):
    hashed_password = get_password_hash(user.password)
    db_user = models.User(username=user.username, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_item(db: Session, title : str):
    return db.query(models.Item).filter(models.Item.title == title).first()

def create_user_item(db: Session, item: schema.ItemCreate, sections : str, user_id: int):
    db_item = models.Item(**item.dict(), owner_id=user_id, sections =  sections)
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item
