from tkinter import *
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
        
db.connect()
db.create_tables([Credentials])
db.close()




class Credentials_DB(Tk):
    def __init__(self):
        Tk.__init__(self)
        self._frame = None
        self.switch_frame(StartPage)

    def switch_frame(self, frame_class):
        new_frame = frame_class(self)
        if self._frame is not None:
            self._frame.destroy()
        self._frame = new_frame
        self._frame.pack()

class ServiceExistsError(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)

        home_button = Button(self, text = 'HOME', command = lambda: master.switch_frame(StartPage))
        home_button.grid(row = 4, column = 0, padx = 0, pady = 0)

        back_buttion = Button(self, text = '<-- BACK  ', command = lambda: master.switch_frame(AddPage))
        back_buttion.grid(row = 0, column = 0, padx = 0, pady = 0)
        

        error_label = Label(self, text = 'Error! Service already exists. Please try again.', font = ("Helvetica", 18))
        error_label.grid(row = 1, column = 2)

        space_label = Label(self, text = '          ')
        space_label.grid(row = 4, column = 3)



class ShowSavedServices(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)

        list_label = Label(self, text = 'Saved Services', font = ("Helvetica", 30))
        list_label.grid(row = 0, column = 0)

        db.connect()

        list_box = Listbox(self, font = ("Helvetica", 25))
        list_box.grid(row = 2, column = 0)

        service_list = []
        for row in Credentials.select():
            service_list.append(row.service.capitalize())
        service_list.sort()

        for item in service_list:
            list_box.insert(END, item)
        db.close()
        

        home_button = Button(self, text = 'HOME', command = lambda: master.switch_frame(StartPage), height = 3, width = 15)
        home_button.grid(row = 4, column = 0, padx = 0, pady = 0)

        # print('\n\n--------\n')
        # for service in service_list:
        #     print(service)
        # print('\n--------')
        # db.close()   


class StartPage(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        

        #window = Tk()
        #window.title('Credentials_DB')
        #window.geometry('700x500')

        space_label = Label(self, text = '     ')
        space_label.grid(row = 1, column = 3)

        welcome_label = Label(self, text = 
        'Welcome!\nPlease make a selection\n\n\n', font = ("Helvetica", 30))
        welcome_label.grid(row = 1, column = 2, padx = 20)

        add_button = Button(self, text = 'ADD', padx = 50, pady = 15, command = lambda: master.switch_frame(AddPage))
        add_button.grid(row = 2, column = 3, padx = (100, 100))
        add_button_label = Label(self, text = 'Add a service to the DataBase --->', font = ("Helvetica", 22))
        add_button_label.grid(row = 2, column = 1)

        querry_button = Button(self, text = 'QUERY', padx = 50, pady = 15, command = lambda: master.switch_frame(ServiceExistsError))
        querry_button.grid(row = 3, column = 3)
        querry_button_label = Label(self, text = 'Retrieve credentials form the DataBase --->', font = ("Helvetica", 22))
        querry_button_label.grid(row = 3, column = 1)

        delete_button = Button(self, text = 'DELETE', padx = 50, pady = 15)
        delete_button.grid(row = 4, column = 3)
        delete_button_label = Label(self, text = 'Delete a saved service --->', font = ("Helvetica", 22))
        delete_button_label.grid(row = 4, column = 1)

        list_button = Button(self, text = 'LIST', padx = 50, pady = 15, command = lambda: master.switch_frame(ShowSavedServices))
        list_button.grid(row = 5, column = 3)
        list_button_label = Label(self, text = 'List all saved services --->', font = ("Helvetica", 22))
        list_button_label.grid(row = 5, column = 1)



class AddPage(Frame):
    def pop_up(self,msg):
        pop_up = Tk()
        pop_up.geometry('600x200')


        pop_up.wm_title('! ERROR !')
        label = Label(pop_up, text = msg, font = ("Helvetica", 20))
        label.pack(side = 'top', fill = 'x', pady = 10)
        button1 = Button(pop_up, text = 'Okay', command = pop_up.destroy, height = 5, width = 20)
        button1.pack()
        db.close()
        pop_up.mainloop()        

    def encrypt_creds(self, master, service_entry, encrypt_pass_entry, username_entry, password_entry):
        service = service_entry.lower()
        service = service.strip()

        
        db.connect()
        print('connected')
        # Make a list of saved services so there can be no two entries with the same service name
        service_list = []
        for row in Credentials.select():
            service_list.append(row.service)
        print('madelist')
        print(service_list)

        # encode encrypt_pass, hash it into the encryption key to be used later.
        
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
        print('encrypted key')
        
        # Prompt for name of service, check for exit and check if the name already exists in the db 

        if service_entry in service_list:
            self.pop_up('Sercive already exists!! please try again!')
            db.close()
            return

    
        print('checked if service exists')
        # Prompt for username and encrypt it
        
        encoded_username = username_entry.encode()
        f = Fernet(key)
        encrypted_username = f.encrypt(encoded_username)
        print('encrypted username0')

        # Prompt for password and encrypt it
        
        encoded_password = password_entry.encode()
        encrypted_password = f.encrypt(encoded_password)
        print('encrypted pass')
        # Create new entry in the db
        Credentials.create(
            service = service,
            username = encrypted_username,
            password = encrypted_password
        )
        print('creds saved')
        db.close()

        lambda: self.master.switch_frame(ShowSavedServices)
        



    def __init__(self, master):
        Frame.__init__(self, master)

        back_buttion = Button(self, text = '<-- BACK  ', command = lambda: master.switch_frame(StartPage))
        back_buttion.grid(row = 0, column = 0, padx = 0, pady = 0)

        space_label = Label(self, text = '     ')
        space_label.grid(row = 1, column = 3)

        add_page_label = Label(self, text = 'Add Service To DataBase', font = ('Helvetica', 26))
        add_page_label.grid(row = 1 , column = 2)

        service_entry_label = Label(self, text = 'Please enter a service name --->', font = ('Helvetica', 18))
        service_entry_label.grid(row = 3, column = 1)
        service_entry = Entry(self, width = 40)
        service_entry.grid(row = 3, column = 3, padx = 10)
        # service = service_entry.get()
        # service = service.lower()
        # service_input = service.strip()

        encrypt_pass_label = Label(self, text = 'Please enter an encryption password (REMEMBER THIS PASSWORD!!!) --->', font = ('Helvetica', 18))
        encrypt_pass_label.grid(row = 4, column = 1)
        encrypt_pass_entry = Entry(self, width = 40)
        encrypt_pass_entry.grid(row = 4, column = 3, padx = 10)
        # encrypt_pass = encrypt_pass_entry.get()
        # encrypt_pass = encrypt_pass.lower()
        # encrypt_pass = encrypt_pass.strip()

        username_label = Label(self, text = 'Please enter a service username --->', font = ('Helvetica', 18))
        username_label.grid(row = 5, column = 1)
        username_entry = Entry(self,width = 40)
        username_entry.grid(row = 5, column = 3, padx = 10)
        # username = username_entry.get()
        # username = username.lower()
        # input_username = username.strip()

        password_label = Label(self, text = 'Please enter a service password --->', font = ('Helvetica', 18))
        password_label.grid(row = 6, column = 1)
        password_entry = Entry(self, width = 40)
        password_entry.grid(row = 6, column = 3, padx = 20)
        # password = password_entry.get()
        # password = password.lower()
        # input_password = password.strip()


        sumbit_button = Button(self, text = 'SUBMIT', command = lambda: [self.encrypt_creds(self, service_entry.get(), encrypt_pass_entry.get(), username_entry.get(), password_entry.get()), 
                                                                         master.switch_frame(ShowSavedServices) ] )
        sumbit_button.grid(row = 7, column = 2)






# entry_lable = Label(window, text='Please enter your name -->').grid(row = 2, column = 0)
# e = Entry(window, width=30).grid(row = 2, column = 1)

# def myClick():
#     hello = 'Thank you for your submition of ' + e.get()
#     myLabel = Label(window, text=hello)
#     myLabel.grid(row = 4, column = 1)

# myButton = Button(window, text='Enter your name', command=myClick)
# myButton.grid(row = 2, column = 2)

if __name__ == '__main__':

    app = Credentials_DB()
    app.mainloop()
