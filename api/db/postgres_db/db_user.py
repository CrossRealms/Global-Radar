
from sqlalchemy import Column, String, Enum
from schemas.schema_user import User, UserList, GetUser, UserRoles
from .db_base import Base


class UserModel(Base):
    __tablename__="users"

    username = Column(String(255), primary_key=True)
    email = Column(String(255))
    hashed_password = Column(String(255))
    role = Column(Enum(UserRoles))


    
async def get_with_name(db, name):
    user = db.query(UserModel).get(name)
    user_obj = None
    if user:
        user_obj = User(user.username, user.email, user.hashed_password, user.role)
    return user_obj


async def get_user_list(db):
    users_from_db = db.query(UserModel).all()
    users = UserList(user_list=list())
    for u in users_from_db:
        users.user_list.append(
            GetUser(
                username=u.username, email=u.email, role=u.role
            )
        )
    return users


async def add(db, user):
    db.add(UserModel(
        username=user.username,
        email=user.email,
        hashed_password=user.hashed_password,
        role=user.role,
    ))
    db.commit()


async def remove(db, username):
    # TODO - Need to delete all cascaded tables, like ip_location, malicious_ip_sources, and their dependencies if not cascaded already
    #      - Need to test
    db.query(UserModel).get(username).delete()
    db.commit()
