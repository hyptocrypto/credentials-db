# Credentials_DB

## Intro 
This program acts as a password and username manager. A light-weight database is created and inputs stored one entry at a time. 
The user is prompted for a password used to encrypt the data. Then prompted for a service name (Reddit, Facebook, bank account, etc.), a username, and a password.


### Setup 
Run the make_db file to create the database in the same directory. Then just run the credentials program whenever you need to interact with the db. 

### Security
Currently, the encryption salt is hardcoded. This isn't the most secure solution since a rainbow table for the given salt could be made
and reduce the difficulty to crack the password for a given entry. To eliminate this risk I plan to prompt the user for a salt on every entry,
this reduces the ease of use for the user giventhat they need to provide a password and slat every time they want to make a query.
Saving an encrypted version of the salt that the user provides could be the right solution. 










