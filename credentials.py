#!/opt/anaconda3/bin/python

'''
This program lets you store login credentials in an encrypted database. 
Upon each entry you are prompted for a password, this password is used to encypt and decrypt the credentials. 
Make sure you remember this password because without it you can not decrypt the saved credentials!!
'''


import os
import sys
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from peewee import *


db = SqliteDatabase('credentials.db')


class Credentials(Model):
    service = CharField(null = True)
    username = CharField()
    password = CharField()
    
    class Meta:
        database = db
        table_name = 'credentials'
        
#db.connect()
#db.create_tables([Credentials])


## This function prompts for a password (used to encrypt credentials), service (reddit, youtube, facebook, bank etc.), a username and password.
def encrypt_creds():
    db.connect()
    # Make a list of saved services so there can be no two entries with the same service name
    service_list = []
    for row in Credentials.select():
        service_list.append(row.service)

    # Prompt for password, encode it and hash it into the encryption key to be used later.
    pass_given = input('Please enter an encryption password:  ')
    password = pass_given.encode()
    salt = b'Y\xa8B\x85\x8d\x95\xe1\xb9\x0e\x19\x11\x17\x03.\n\x9d'
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length =32, 
        salt = salt,
        iterations = 100000,
    backend = default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    
    # Prompt for name of service, check for exit and check if the name already exists in the db 
    service_input = input('Please enter a service: ').lower()
    service_input = service_input.strip()
    if service_input == 'exit':
        return
    if service_input in service_list:
        print('\n Sorry, service already exists. Please try again.')
        db.close()
        encrypt_creds()
        return
    
    # Prompt for username and encrypt it
    username = input('Please enter username: ')
    encoded_username = username.encode()
    f = Fernet(key)
    encrypted_username = f.encrypt(encoded_username)

    # Prompt for password and encrypt it
    password = input('Please enter a password: ')
    encoded_password = password.encode()
    encrypted_password = f.encrypt(encoded_password)

    # Create new entry in the db
    Credentials.create(
        service = service_input,
        username = encrypted_username,
        password = encrypted_password
    )
    db.close()
    print(f'\nInput for service {service_input} successfully saved! ')

## This fuction prompts for a service and password and querries the db for that service name (returns decrypted username and password)
def decrypt_creds():
    db.connect()
    # Prompt for service name, check for exit and checks if the service name is in the db. 
    service_input = input('Please enter a service: ').lower()
    service_input = service_input.strip()
    if service_input == 'exit':
        return
    try:
        service = Credentials.get(Credentials.service == service_input)
    except Credentials.DoesNotExist:
        print('\n ----- Sorry, please enter a valid service -----\n')
        db.close()
        decrypt_creds()
        return

    # Encoding encrypted username and password to bytes 
    encrypted_username = service.username
    encrypted_password = service.password
    encrypted_username = bytes(encrypted_username, 'utf-8')
    encrypted_password = bytes(encrypted_password, 'utf-8')
    
    # Prompt for password used to encrypt username and password.
    pass_given = input('\nPlease enter password:  ')
    password = pass_given.encode()
    salt = b'Y\xa8B\x85\x8d\x95\xe1\xb9\x0e\x19\x11\x17\x03.\n\x9d'

    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length =32, 
        salt = salt,
        iterations = 100000,
    backend = default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(password)) 
    f = Fernet(key)

    # Tries to decrypt with given password. If successful, decrypted username and password and displayed. 
    # If the password was incorrect the progrma terminates to deter spamming password atempts. 
    try:
        decrypted_username = f.decrypt(encrypted_username)
        decrypted_password = f.decrypt(encrypted_password)
        username = decrypted_username.decode()
        password = decrypted_password.decode()
        print(f'\n Service: {service_input} \n Username: {username} \n password: {password}')
        db.close()
    except:
        print('\n----- Incorrect Password ------')
        return

## Function to delete a service in the database. 
def delete_service():
    db.connect()
    # Prompt for service name, check for exit and checks if the service name is in the db. 
    service_input = input('What service would you like to delete?: ').lower()
    service_input = service_input.strip()
    if service_input == 'exit':
        return
    try:
        service = Credentials.get(Credentials.service == service_input)
    except Credentials.DoesNotExist:
        print('\n ------ Sorry, please enter a valid service ------')
        db.close()
        decrypt_creds()
        return
    # Encoding encrypted username and password to bytes   
    encrypted_username = service.username
    encrypted_password = service.password
    encrypted_username = bytes(encrypted_username, 'utf-8')
    encrypted_password = bytes(encrypted_password, 'utf-8')
    
    # Prompt for password used to encrypt username and password.
    pass_given = input('Please enter password:  ')
    password = pass_given.encode()
    salt = b'Y\xa8B\x85\x8d\x95\xe1\xb9\x0e\x19\x11\x17\x03.\n\x9d'

    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length =32, 
        salt = salt,
        iterations = 100000,
    backend = default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(password)) 
    f = Fernet(key)

    # Tries to decrypt with given password. If successful, password was correct. 
    # If the password was incorrect the progrma terminates to deter spamming password atempts. 
    try:
        decrypted_username = f.decrypt(encrypted_username)
        decrypted_password = f.decrypt(encrypted_password)
        username = decrypted_username.decode()
        password = decrypted_password.decode()
        print(f'\n Service: {service_input} \n Username: {username} \n password: {password}\n' +
             '- Successfully Deleted -')
        db.close()
    except:
        print('\n\n ------ Incorect Password ------')
        return
    # Check to see if service exits in database, if so, service is deleted.   
    try:
        delete =Credentials.delete().where(Credentials.service == service_input)
        delete.execute()
    except Credentials.DoesNotExist:
        print('\n ----- Sorry, please enter a valid service -----')
        db.close()
        delete_service()
        return





# This function lists the service name of all saved entries
def show_services():    
    db.connect()
    print('\n\n--------\n')
    for row in Credentials.select():
        print(row.service)
    print('\n--------')
    db.close()   


    

  
# Main logic of program. Prompt user to choose to make an entry, a querry or list saved services. 
# Call the correct function acoriding to user input. 
if __name__ == '__main__':
    choices = ['a','b','c','d','q','e']
    
    
    while True:
        answer = input('Welcome! \n\nWould you like to save an input? (A) \n' +
                   'Would you like you like to make a querry? (B) \n'+
                      'Would you like to see all saved services? (C) \n' + 
                      'Would you like to delete a service? (D)\n' +
                       '---(Q or E to exit )--- \n')
            
        if answer.lower() not in choices:
            print('\n --------!! Sorry, Please make a' + 
                  'valid choice of either (A),(B),(C) !!----------')
            continue
        elif answer.lower() == 'a':
            encrypt_creds()
            db.close()
            continue
        elif answer.lower() == 'b':
            decrypt_creds()
            db.close()
            continue
        elif answer.lower() == 'c':
            show_services()
            continue
        elif answer.lower() == 'd':
            show_services()
            delete_service()
            db.close()
            continue
        elif answer[0].lower() == 'q' or 'e':
            break
       