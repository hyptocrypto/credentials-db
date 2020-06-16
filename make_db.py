from peewee import *


db = SqliteDatabase('credentials.db')


class Credentials(Model):
    service = CharField(null = True)
    username = CharField()
    password = CharField()
    
    class Meta:
        database = db
        table_name = 'credentials'
        
db.connect()
db.create_tables([Credentials])
db.close()