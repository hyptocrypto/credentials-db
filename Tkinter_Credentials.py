'''
This program lets you store login credentials in an encrypted database. 
Upon each entry you are prompted for a password, this password is used to encypt and decrypt the credentials. 
Make sure you remember this password because without it you can not decrypt the saved credentials!!
'''

from tkinter import *
import os
import sys
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from peewee import *

## Initalize Database
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



## Initialize a main instance of Tk()
class Credentials_DB(Tk):
    def __init__(self):
        Tk.__init__(self)
        self._frame = None
        self.switch_frame(StartPage)
## Function to switch between pages
    def switch_frame(self, frame_class):
        new_frame = frame_class(self)
        if self._frame is not None:
            self._frame.destroy()
        self._frame = new_frame
        self._frame.pack()

## Setup main page
class StartPage(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)

        ## Title
        welcome_label = Label(self, text = 'Welcome! \n Please make a selection', font = ("Helvetica", 30))
        welcome_label.pack()
        space_label = Label(self, text = '- - - - - - - - - - - - - - - - - - - - - - - - - ', padx = 50, font = ("Helvetica", 20) )
        space_label.pack()
        space_label = Label(self, text = '  ' )
        space_label.pack()
        
        ## Label and Button to add to database
        add_button_label = Label(self, text = 'Add a new service', font = ("Helvetica", 22))
        add_button_label.pack()
        add_button = Button(self, text = 'ADD', height = 1, width = 5, padx = 50, pady = 15, command = lambda: master.switch_frame(AddPage))
        add_button.pack()
        space_label = Label(self, text = '  ' )
        space_label.pack()

        ## Label and Button to query database
        querry_button_label = Label(self, padx = 5, text = 'Retrieve credentials for a service', font = ("Helvetica", 22))
        querry_button_label.pack()
        querry_button = Button(self, text = 'QUERY', height = 1, width = 5, padx = 50, pady = 15, command = lambda: master.switch_frame(QuerryPage))
        querry_button.pack()
        space_label = Label(self, text = '  ' )
        space_label.pack()

        ## Label and Button to delete a service from the database
        delete_button_label = Label(self, text = 'Delete a saved service', font = ("Helvetica", 22))
        delete_button_label.pack()
        delete_button = Button(self, text = 'DELETE', height = 1, width = 5, padx = 50, pady = 15, command = lambda: master.switch_frame(DeletePage))
        delete_button.pack()
        space_label = Label(self, text = '  ' )
        space_label.pack()

        ## Label and Button to list all services saved in the database
        list_button_label = Label(self, text = 'List all saved services', font = ("Helvetica", 22))
        list_button_label.pack()        
        list_button = Button(self, text = 'LIST', height = 1, width = 5, padx = 50, pady = 15, command = lambda: master.switch_frame(ShowSavedServices))
        list_button.pack()
        space_label = Label(self, text = '  ' )
        space_label.pack()

## Page to show all saved services 
class ShowSavedServices(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)

        ## Back button
        back_button = Button(self, text = 'BACK', command = lambda: master.switch_frame(StartPage), height = 2, width = 5)
        back_button.pack(anchor = NW)

        ## Title
        list_label = Label(self, text = 'Saved Services', font = ("Helvetica", 30))
        list_label.pack()

        db.connect()

        ## Initialze a list box to list all the saved servieces 
        list_box = Listbox(self, font = ("Helvetica", 25))
        list_box.pack()

        ## Create list of saved service by querying databse
        service_list = []
        for row in Credentials.select():
            service_list.append(row.service.capitalize())
        service_list.sort()

        ## List saved services into the list box initalized above
        for item in service_list:
            list_box.insert(END, item)
        db.close()
        
        def double_clicked(event):
            decrypt_pop_up(self, f'Please enter the password used to save "{list_box.get(ANCHOR).lower()}" service')
        list_box.bind('<Double-Button-1>', double_clicked)




        select_button = Button(self, text = 'Select', command = lambda: decrypt_pop_up(self, f'Please enter the password used to save "{list_box.get(ANCHOR).lower()}" service'), height = 3, width = 15)
        select_button.pack(side = LEFT)

        delete_button = Button(self, text = 'Delete', command = lambda: delete_pop_up(self, f'Please enter the password used to save "{list_box.get(ANCHOR).lower()}" service'), height = 3, width = 15)
        delete_button.pack(side = RIGHT)


        def decrypt_pop_up(self,msg):
            pop_up = Tk()
            pop_up.geometry('600x180')
            
            pop_up.wm_title('Retrieve Credentials')
            label = Label(pop_up, text = msg, font = ("Helvetica", 20), padx = 50)
            label.pack(side = 'top', fill = 'x', pady = 10)
            space_label = Label(pop_up, '', padx = 10)
            space_label.pack()
            pass_entry = Entry(pop_up, width = 30, font = ('Helvetica', 15))
            pass_entry.pack()
            
            def enter_key(event):
                QuerryPage.decrypt_creds(self, list_box.get(ANCHOR), pass_entry.get())
                pop_up.destroy
            pass_entry.bind('<Return>', enter_key)
            
            

            select_button = Button(pop_up, text = 'Submit', command = lambda: [pop_up.destroy, QuerryPage.decrypt_creds(self, list_box.get(ANCHOR), pass_entry.get())], height = 3, width = 15)
            select_button.pack()
            db.close()
            pop_up.mainloop()


        def delete_pop_up(self,msg):
            pop_up = Tk()
            pop_up.geometry('600x180')
            
            pop_up.wm_title('Delete Service')
            label = Label(pop_up, text = msg, font = ("Helvetica", 20), padx = 50)
            label.pack(side = 'top', fill = 'x', pady = 10)
            space_label = Label(pop_up, '', padx = 10)
            space_label.pack()
            pass_entry = Entry(pop_up, width = 30, font = ('Helvetica', 15))
            pass_entry.pack()
            

            select_button = Button(pop_up, text = 'Delete', command = lambda: [pop_up.destroy, DeletePage.delete_service(self, list_box.get(ANCHOR), pass_entry.get())], height = 3, width = 15)
            select_button.pack()
            db.close()
            pop_up.mainloop()

    def success_pop_up(self, service, username, password):
        pop_up = Tk()
        pop_up.geometry('600x200')


        pop_up.wm_title(' SUCCESS !')
        label = Label(pop_up, text = f'{service.capitalize()} Credentials', font = ("Helvetica", 25))
        label.pack(side = 'top', fill = 'x', pady = 10)

        list_box = Listbox(pop_up, font = ("Helvetica", 20), height = 4, width = 40)
        list_box.pack()
        cred_list = [f'Username:   {username}', f'Password:   {password}']
        
        for item in cred_list:
            list_box.insert(END, item)
        


        button1 = Button(pop_up, text = 'Okay', command = pop_up.destroy, height = 3, width = 15)
        button1.pack()
        db.close()
        pop_up.mainloop()         



    ## Error popup window
    def pop_up(self,msg):
        pop_up = Tk()
        pop_up.geometry('600x180')
        
        pop_up.wm_title(' ERROR !')
        label = Label(pop_up, text = msg, font = ("Helvetica", 20))
        label.pack(side = 'top', fill = 'x', pady = 10)
        button1 = Button(pop_up, text = 'Okay', command = pop_up.destroy, height = 3, width = 15)
        button1.pack()
        db.close()
        pop_up.mainloop()  


## Page to add service to database
class AddPage(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)

        ## Button to return to StartPage 
        back_button = Button(self, height = 1, width = 5, padx = 50, pady = 15, text = '<-- BACK  ', command = lambda: master.switch_frame(StartPage))
        back_button.pack(anchor = NW)

        ## Spacing to give page a wider layout
        space_label = Label(self, text = '     ')
        space_label.pack()

        ## Title
        add_page_label = Label(self, text = 'Add Service To DataBase', font = ('Helvetica', 26))
        add_page_label.pack()
        space_label = Label(self, text = '  ')
        space_label.pack()

        ## Title and text feild for the name of a service 
        service_entry_label = Label(self, text = 'Please enter a service name', font = ('Helvetica', 18))
        service_entry_label.pack()
        service_entry = Entry(self, width = 40, font = ('Helvetica', 18))
        service_entry.pack()
        space_label = Label(self, text = '  ')
        space_label.pack()
       
        ## Title and text feild for the encryption password 
        encrypt_pass_label = Label(self, text = 'Please enter an encryption password (REMEMBER THIS PASSWORD!!!)', padx = 50, font = ('Helvetica', 18))
        encrypt_pass_label.pack()
        encrypt_pass_entry = Entry(self, width = 40, font = ('Helvetica', 18))
        encrypt_pass_entry.pack()
        space_label = Label(self, text = '  ')
        space_label.pack()        
  
        ## Title and text feild for the username
        username_label = Label(self, text = 'Please enter a service username', font = ('Helvetica', 18))
        username_label.pack()
        username_entry = Entry(self,width = 40, font = ('Helvetica', 18))
        username_entry.pack()
        space_label = Label(self, text = '  ')
        space_label.pack()

        ## Title and text feild for the password
        password_label = Label(self, text = 'Please enter a service password', font = ('Helvetica', 18))
        password_label.pack()
        password_entry = Entry(self, width = 40, font = ('Helvetica', 18))
        password_entry.pack()
        space_label = Label(self, text = '  ')
        space_label.pack()

        ## Function to submit the form when pressing enter in the final text feild 
        def enter_key(event):
            self.encrypt_creds(service_entry.get(), encrypt_pass_entry.get(), username_entry.get(), password_entry.get())
            master.switch_frame(ShowSavedServices)
        password_entry.bind('<Return>', enter_key)

        ## Button to submit info and run the encrypt_creds funciton
        sumbit_button = Button(self, text = 'SUBMIT', height = 1, width = 5, padx = 50, pady = 15, command = lambda: [self.encrypt_creds(service_entry.get(), encrypt_pass_entry.get(), username_entry.get(), password_entry.get()), 
                                                                         master.switch_frame(ShowSavedServices) ] )
        sumbit_button.pack()

        
    ## Error popup window
    def pop_up(self,msg):
        pop_up = Tk()
        pop_up.geometry('600x180')
        
        pop_up.wm_title(' ERROR !')
        label = Label(pop_up, text = msg, font = ("Helvetica", 20))
        label.pack(side = 'top', fill = 'x', pady = 10)
        button1 = Button(pop_up, text = 'Okay', command = pop_up.destroy, height = 3, width = 15)
        button1.pack()
        db.close()
        pop_up.mainloop()        

    ## Function encrypt and save the credentials
    def encrypt_creds(self, service_entry, encrypt_pass_entry, username_entry, password_entry):
        service = service_entry.lower()
        service = service.strip()
 
        db.connect()
        
        # Make a list of saved services so there can be no two entries with the same service name
        service_list = []
        for row in Credentials.select():
            service_list.append(row.service)

        # Encode encrypt_pass, hash it into the encryption key to be used later
        password = encrypt_pass_entry.encode()
        salt = b'Y\xa8B\x85\x8d\x95\xe1\xb9\x0e\x19\x11\x17\x03.\n\x9d'
        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length =32, 
            salt = salt,
            iterations = 100000,
        backend = default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))

        
        # Check if the service name already exists in the data base  
        if service_entry in service_list:
            self.pop_up('Sercive already exists!! please try again!')
            db.close()
            return

        # Encode and encrypt username
        encoded_username = username_entry.encode()
        f = Fernet(key)
        encrypted_username = f.encrypt(encoded_username)

        # Encode and encrypt password 
        encoded_password = password_entry.encode()
        encrypted_password = f.encrypt(encoded_password)
        
        # Create new entry in the database
        Credentials.create(
            service = service,
            username = encrypted_username,
            password = encrypted_password
        )
        db.close()

        

## Page to querry the database for credentials
class QuerryPage(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)

        ## Button to go back to StartPage
        back_buttion = Button(self, height = 1, width = 4, padx = 50, pady = 15, text = '<-- BACK  ', command = lambda: master.switch_frame(StartPage))
        back_buttion.pack(anchor = NW)

        ## Title
        title_label = Label(self, text = 'Retrieve Credentials', font = ('Helvetica', 26))
        title_label.pack()
        space_label = Label(self, text = '  ')
        space_label.pack()

        ## Title and text feild for name of service
        query_label = Label(self, text = 'Please enter a service name', font = ('Helvetica', 18))
        query_label.pack()
        query_entry = Entry(self, width = 40, font = ('Helvetica', 18))
        query_entry.pack()
        space_label = Label(self, text = '  ')
        space_label.pack()        

        ## Title and text feild for encryption password
        pass_label = Label(self, text = 'Please enter the encryption password used to save this service', padx = 50, font = ('Helvetica', 18))
        pass_label.pack()
        pass_entry = Entry(self, width = 40, font = ('Helvetica', 18))
        pass_entry.pack() 
        space_label = Label(self, text = '  ')
        space_label.pack()

        def enter_key(event):
            self.decrypt_creds(query_entry.get(), pass_entry.get())
            pop_up.destroy
        pass_entry.bind('<Return>', enter_key)

        ## Button to submit and fun decrypt_creds function 
        sumbit_button = Button(self, height = 1, width = 5, padx = 50, pady = 15, text = 'SUBMIT', command = lambda: self.decrypt_creds(query_entry.get(), pass_entry.get()))
        sumbit_button.pack()

    ## Eorro popup window 
    def pop_up(self,msg):
        pop_up = Tk()
        pop_up.geometry('600x180')


        pop_up.wm_title(' ERROR !')
        label = Label(pop_up, text = msg, font = ("Helvetica", 20))
        label.pack(side = 'top', fill = 'x', pady = 10)
        button1 = Button(pop_up, text = 'Okay', command = pop_up.destroy, height = 3, width = 15)
        button1.pack()
        db.close()
        pop_up.mainloop()  
    
    def success_pop_up(self, service, username, password):
        pop_up = Tk()
        pop_up.geometry('600x200')


        pop_up.wm_title(' SUCCESS !')
        label = Label(pop_up, text = f'{service.capitalize()} Credentials', font = ("Helvetica", 25))
        label.pack(side = 'top', fill = 'x', pady = 10)

        list_box = Listbox(pop_up, font = ("Helvetica", 20), height = 4, width = 40)
        list_box.pack()
        cred_list = [f'Username:   {username}', f'Password:   {password}']
        
        for item in cred_list:
            list_box.insert(END, item)
        


        button1 = Button(pop_up, text = 'Okay', command = pop_up.destroy, height = 3, width = 15)
        button1.pack()
        db.close()
        pop_up.mainloop()  

    ## This fuction prompts for a service and password and querries the db for that service name (returns decrypted username and password)
    def decrypt_creds(self, query_entry, pass_entry):
        db.connect()
        # Prompt for service name, check for exit and checks if the service name is in the db. 
        service_input = query_entry.lower()
        service_input = service_input.strip()
        
        try:
            service = Credentials.get(Credentials.service == service_input)
        except Credentials.DoesNotExist:
            self.pop_up(f'Sorry, service "{service_input}" does not exist')
            db.close()
            return
        

        # Encoding encrypted username and password to bytes 
        encrypted_username = service.username
        encrypted_password = service.password
        encrypted_username = bytes(encrypted_username, 'utf-8')
        encrypted_password = bytes(encrypted_password, 'utf-8')
        
        # Prompt for password used to encrypt username and password.
        
        password = pass_entry
        password = password.encode()
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
            self.success_pop_up(service_input, username, password)
            db.close()
        except Exception as e:
            self.pop_up(f'Password "{pass_entry}" incorrect!')
            db.close()
            return

        




class DeletePage(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        back_buttion = Button(self, height = 1, width = 5, padx = 50, pady = 15, text = '<-- BACK  ', command = lambda: master.switch_frame(StartPage))
        back_buttion.pack(anchor = NW)

        title_label = Label(self, text = 'Delete Credentials', font = ('Helvetica', 26))
        title_label.pack()
        space_label = Label(self, text = '  ')
        space_label.pack()

        delete_label = Label(self, text = 'Please enter the name of the service you would like to delete', padx = 50, font = ('Helvetica', 18))
        delete_label.pack()
        delete_entry = Entry(self, width = 40)
        delete_entry.pack()
        space_label = Label(self, text = '  ')
        space_label.pack()

        pass_label = Label(self, text = 'Please enter the encryption password used to save this service', padx = 50, font = ('Helvetica', 18))
        pass_label.pack()
        pass_entry = Entry(self, width = 40)
        pass_entry.pack() 
        space_label = Label(self, text = '  ')
        space_label.pack()

        sumbit_button = Button(self, height = 1, width = 5, padx = 50, pady = 15, text = 'SUBMIT', command = lambda: self.delete_service(delete_entry.get(), pass_entry.get()))
        sumbit_button.pack()

    def pop_up(self,msg):
        pop_up = Tk()
        pop_up.geometry('600x180')


        pop_up.wm_title(' ERROR !')
        label = Label(pop_up, text = msg, font = ("Helvetica", 20))
        label.pack(side = 'top', fill = 'x', pady = 10)
        button1 = Button(pop_up, text = 'Okay', command = pop_up.destroy, height = 3, width = 15)
        button1.pack()
        db.close()
        pop_up.mainloop()  
    
    def success_pop_up(self, service, username, password):
        pop_up = Tk()
        pop_up.geometry('600x200')


        pop_up.wm_title(' SUCCESS !')
        label = Label(pop_up, text = f'{service.capitalize()} Credentials Deleted', font = ("Helvetica", 25))
        label.pack(side = 'top', fill = 'x', pady = 10)

        list_box = Listbox(pop_up, font = ("Helvetica", 20), height = 4, width = 40)
        list_box.pack()
        cred_list = [f'Username: {username}', f'Password: {password}']
        
        for item in cred_list:
            list_box.insert(END, item)

        button1 = Button(pop_up, text = 'Okay', command = pop_up.destroy, height = 3, width = 15)
        button1.pack()
        db.close()
        pop_up.mainloop()  

    ## Function to delete a service in the database. 
    def delete_service(self, service, password):
        db.connect()
        # Prompt for service name, check for exit and checks if the service name is in the db. 
        service_input = service.lower()
        service_input = service_input.strip()
        
        
        try:
            service = Credentials.get(Credentials.service == service_input)
        except Credentials.DoesNotExist:
            self.pop_up(f'Sorry, service "{service_input}" does not exist')
            db.close()
            return
        # Encoding encrypted username and password to bytes   
        encrypted_username = service.username
        encrypted_password = service.password
        encrypted_username = bytes(encrypted_username, 'utf-8')
        encrypted_password = bytes(encrypted_password, 'utf-8')
        
        # Prompt for password used to encrypt username and password.
        pass_given = password
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
            delete =Credentials.delete().where(Credentials.service == service_input)
            delete.execute()
            self.success_pop_up(service_input, username, password)
            db.close()
        except:
            self.pop_up('Incorect Password!')
            return
   

if __name__ == '__main__':

    app = Credentials_DB()
    app.mainloop()
