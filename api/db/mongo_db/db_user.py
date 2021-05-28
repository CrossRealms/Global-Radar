
from schemas.user import User, UserList, GetUser

class DBUsers:
    COLLECTION = 'users'
    FIELD_USERNAME = '_id'
    FIELD_EMAIL = 'email_id'
    FIELD_PASSWORD = 'hashed_password'
    FIELD_ROLE = 'role'
    FAKE_PASSWORD = '******'
    

async def get_with_name(db, name):
    user =  await db[DBUsers.COLLECTION].find_one({DBUsers.FIELD_USERNAME: name})
    user_obj = None
    if user:
        user_obj = User(user[DBUsers.FIELD_USERNAME], user[DBUsers.FIELD_EMAIL], user[DBUsers.FIELD_PASSWORD], user[DBUsers.FIELD_ROLE])
    return user_obj


async def get_user_list(db):        
    users_from_db = db[DBUsers.COLLECTION].find({})
    users = UserList(user_list=list())
    async for u in users_from_db:
        users.user_list.append(GetUser(username=u.get(DBUsers.FIELD_USERNAME), email=u[DBUsers.FIELD_EMAIL], role=u[DBUsers.FIELD_ROLE]))
    return users


async def add(db, user):
    return await db[DBUsers.COLLECTION].insert_one({
        DBUsers.FIELD_USERNAME: user.username,
        DBUsers.FIELD_EMAIL: user.email,
        DBUsers.FIELD_PASSWORD: user.hashed_password,
        DBUsers.FIELD_ROLE: user.role
    })


async def remove(db, username):
    return await db[DBUsers.COLLECTION].delete_one({
        DBUsers.FIELD_USERNAME: username
    })
