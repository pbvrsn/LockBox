from tkinter import * 
from tkinter import filedialog, simpledialog
from functools import partial
from db import Db
from pass_tools import *
from enc import *
from threading import Timer

import webbrowser
import os

class App():

    def __init__(self):
        # Initializing Database Module
        self.db = Db()
        self.configuration = self.db.get_configuration()

        # Initializing GUI
        self.window = Tk()
        self.window.eval("tk::PlaceWindow . center")
        self.window.update()

        logo = PhotoImage(file="mystery-box.png")
        self.window.iconphoto(True, logo)
        self.window.resizable(False, False)
        self.window.geometry("500x250")
        self.window.title("LockBox")

        self.openeye = PhotoImage(file="oe12.png")
        self.closedeye = PhotoImage(file="ce12.png")
        self.showpass = False
    
    def new_user(self):
        """
        This will create a new database for new users.
        """
        self.window.geometry("500x250")
        self.window.title("Creating new Database")

        master_pass_label = Label(self.window, text="Master Password")
        master_pass_label.config(anchor="center")
        master_pass_label.pack(pady=10)

        master_pass_entry = Entry(self.window, width=30, show="*")
        master_pass_entry.pack()
        master_pass_entry.focus()

        confirm_label = Label(self.window, text="Confirm Master Boot")
        confirm_label.config(anchor="center")
        confirm_label.pack(pady=10)

        confirm_label_entry = Entry(self.window, width=30, show="*")
        confirm_label_entry.pack()

        self.feedback = Label(self.window)
        self.feedback.anchor(anchor="center")
        self.feedback.pack()

        keyfile_variable = IntVar(value=1)
        keyfile_checkbox = Checkbutton(
            self.window,
            text="Keyfile",
            variable=keyfile_variable,
            onvalue=1,
            offvalue=0,
        )
        keyfile_checkbox.pack()

        help_button = Button(
            text="Need Help?",
            command=self.get_help
        )
        help_button.config(anchor="center")
        help_button.pack()

        create_button = Button(
            self.window,
            text="Create Database",
            command=partial(self.save_info, master_pass_entry, confirm_label_entry, keyfile_variable)
        )
        create_button.config(anchor="center")
        create_button.pack()
    
    def login_with_keyfile(self):
        """
        Login to the database.
        """
        for widget in self.window.winfo_children():
            widget.destroy()

        self.window.geometry("500x250")
        self.window.title("Login")

        password = Label(self.window, text="Enter Password")
        password.config(anchor="center")
        password.pack(pady=(50,10))

        password_entry = Entry(self.window, width=30, show="*")
        password_entry.pack()
        password_entry.focus()

        self.feedback = Label(self.window)
        self.feedback.anchor(anchor="center")
        self.feedback.pack()

        #displayed_name = [i for i in self.configuration.get("keyfile_path", "").split("/")]

        #if len(displayed_name) > 3:
        #    minimal_filepath = f"../{'/'.join(displayed_name[-3::])}"
        #else:
        #    minimal_filepath = f"..{'/'.join(displayed_name[-3::])}"

        self.keyfile_path = Label(self.window, text=self.configuration.get("keyfile_path", ""), fg="green")
        self.keyfile_path.anchor(anchor="center")
        self.keyfile_path.pack()

        keyfile_button = Button(
            self.window,
            text="Select KEYFILE",
            command=self.browse_file
        )
        keyfile_button.config(anchor="center")
        keyfile_button.pack()

        login_button = Button(
            self.window,
            text="Login",
            command=partial(
                self.check_login_with_keyfile,
                password_entry
            )
        )
        login_button.config(anchor="center")
        login_button.pack(pady=(10,0))

        access = self.check_login_with_keyfile(password_entry)

    def login_without_keyfile(self):
        """
        Login to the database.
        """
        for widget in self.window.winfo_children():
            widget.destroy()

        self.window.geometry("500x250")
        self.window.title("Login")

        password = Label(self.window, text="Enter Password")
        password.config(anchor="center")
        password.pack(pady=(50,10))

        password_entry = Entry(self.window, width=30, show="*")
        password_entry.pack()
        password_entry.focus()

        self.feedback = Label(self.window)
        self.feedback.anchor(anchor="center")
        self.feedback.pack()

        login_button = Button(
            self.window,
            text="Login",
            command=partial(
                self.check_login_without_keyfile,
                password_entry
            )
        )
        login_button.config(anchor="center")
        login_button.pack(pady=(10,0))


    def check_login_with_keyfile(self, password) -> bool:
        """
        This function will let you login to the database, and if set's up the encryption.
        """
        # Cheking Password
        password_hash_check: bool = Hasher().check_hash(password.get(), self.configuration.get("password_hash"))

        # Cheking KEYFILE
        with open(self.configuration.get("keyfile_path"), "r") as file:
            content = file.read()
        
        keyfile_hash_check: bool = Hasher().check_hash(content, self.configuration.get("keyfile_hash"))

        if password_hash_check == True and keyfile_hash_check == True:
            self.enc = Cypher(bytes(f"{password.get()}{content}", "utf-8"), self.configuration.get("salt"))
            self.database_screen()
            return True
        else:
            if password.get() != "":
                if keyfile_hash_check == True and password_hash_check == False:
                    self.feedback.config(text="Wrong Password!", fg="red")
                    return False
                elif keyfile_hash_check == False and password_hash_check == True:
                    self.feedback.config(text="Wrong KEYFILE!", fg="red")
                    return False
                else:
                    self.feedback.config(text="Wrong Password and KEYFILE!", fg="red")
                    return False
            return False

    def check_login_without_keyfile(self, password) -> bool:
        """
        This function will let you login to the database, and if set's up the encryption.
        """
        # Cheking Password
        password_hash_check: bool = Hasher().check_hash(password.get(), self.configuration.get("password_hash"))

        if password_hash_check == True:
            self.enc = Cypher(bytes(password.get(), "utf-8"), self.configuration.get("salt"))
            self.database_screen()
            return True
        else:
            self.feedback.config(text="Wrong Password!", fg="red")
            return False

    def save_info(self, master_password: str, confirmed_master_password: str, keyfile: int):
        """
        Saves the password's hash in the database.
        and it creates a keyfile if needed.
        """
        master_password = master_password.get()
        confirmed_master_password = confirmed_master_password.get()
        keyfile = keyfile.get()

        if len(master_password) < 8:
            self.feedback.config(text="Password Too Short!\nAt Least 8 Characters.", fg="red")
            return 1

        if master_password == confirmed_master_password:
            if keyfile == 1:
                # Keyfile
                keyfile: str = Generator().gen_key()
                keyfile_hash: str = Hasher().create_hash(keyfile)

                with open("KEYFILE", "w") as file:
                    file.write(keyfile)
                
                keyfile_path = os.path.abspath("KEYFILE")
                print(keyfile_path)
                
                # Password
                password_hash: str = Hasher().create_hash(master_password)

                # salt
                salt: bytes = Generator().gen_salt()
                
                config_dict: dict = {
                    "password_hash": password_hash,
                    "keyfile_hash": keyfile_hash,
                    "keyfile_path": keyfile_path,
                    "salt": salt,
                }

                self.db.set_configuration(config_dict)
            else:
                # Password
                password_hash: str = Hasher().create_hash(master_password)

                # salt
                salt: bytes = Generator().gen_salt()

                config_dict: dict = {
                    "password_hash": password_hash,
                    "salt": salt
                }
                
                self.db.set_configuration(config_dict)
            
            self.configuration = self.db.get_configuration()

            if self.configuration.get("keyfile_path", "") != None:
                self.login_with_keyfile()
                self.feedback.config(text="")
            else:
                self.login_without_keyfile()
                self.feedback.config(text="")

        else:
            self.feedback.config(text="Passwords Do Not Match", fg="red")
            return 1

    def database_screen(self):
        """
        Database Screen
        """
        for widget in self.window.winfo_children():
            widget.destroy()

        self.window.geometry("835x250")
        self.window.minsize(835, 250)
        self.window.resizable(True, True)
        self.window.title("LockBox")
        
        frame = Frame(self.window)
        frame.pack(fill=BOTH, expand=1)

        canvas = Canvas(frame)
        canvas.pack(side=LEFT, expand=1, fill=BOTH)

        scrollbar = Scrollbar(
            frame,
            orient=VERTICAL,
            command=canvas.yview
        )
        scrollbar.pack(side=RIGHT, fill=Y)

        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        frame_ = Frame(canvas)
        canvas.create_window(
            (0,0),
            window=frame_,
            anchor="nw"
        )

        generator_password_button = Button(
            frame_,
            text="Generate Password",
            command=Generator_GUI
        )
        generator_password_button.grid(
            row=1,
            column=0,
            pady=(10,0)
        )


        add_password_button = Button(
            frame_,
            text="Add New Password",
            command=self.add_password
        )
        add_password_button.grid(row=1, column=1, pady=(10,0))

        content_label = Label(frame_, text="Website")
        content_label.grid(row=2, column=0, padx=40, pady=5)

        content_label = Label(frame_, text="Email/Username")
        content_label.grid(row=2, column=1, padx=40, pady=5)
        
        content_label = Label(frame_, text="Password")
        content_label.grid(row=2, column=2, padx=40, pady=5)

        data = self.db.get_passwords()
        tmp = {}
        for i, kv in enumerate(data.items()):
          tmp[i+1] = kv[1]

        if tmp != {}:
            x = 1
            while True:

                website = Label(
                    frame_,
                    text=tmp[x].get("link")
                )
                website.grid(column=0, row=x +3)


                username = Label(
                    frame_,
                    text=tmp[x].get("username")
                )
                username.grid(column=1, row=x +3)

                password = Entry(frame_)
                password.insert(0, self.enc.decrypt_text(tmp[x].get("password_hash")))
                password.configure(state="readonly", show="*", selectborderwidth=0, relief=FLAT)
                password.grid(column=2, row=x + 3)

                show_password_button = Button(frame_)
                show_password_button.config(borderwidth=0, image=self.openeye,
                                            command=partial(self.show_password, password, show_password_button))
                show_password_button.image = self.openeye
                show_password_button.grid(row=x + 3, column=2, sticky='e', padx=(160, 5))

                copy_button = Button(
                    frame_,
                    text="Copy Password",
                    command=partial(
                        self.copy_password,
                        tmp[x].get("password_hash")
                    )
                )
                copy_button.grid(column=3, row=x+ 3)

                remove_password_button = Button(
                    frame_,
                    text="Remove Password",
                    command=partial(
                        self.remove_password,
                        tmp[x].get("password_id")
                    )
                )
                remove_password_button.grid(column=4, row=x + 3)

                go_to_website_button = Button(
                    frame_,
                    text="Website",
                    command=partial(
                        self.go_to_website,
                        tmp[x].get("link")
                    )
                )
                go_to_website_button.grid(column=5, row=x +3)

                x += 1

                if len(tmp) < x:
                    break
    
    def hide_password(self, password, button):
        """
        Hides the password.
        """
        try:
            button.image = self.openeye
            button.config(borderwidth=0, image=self.openeye)
            password.configure(state="readonly", show="*")
            self.showpass = False
        except:
            pass

    def show_password(self, password, spbutton):
        """
        Show the password for 5 seconds.
        """
        self.showpass = not self.showpass
        if self.showpass:
            password.configure(state="readonly", show="")
            spbutton.image = self.closedeye
            spbutton.config(borderwidth=0, image=self.closedeye)

            timer = Timer(3.0, partial(self.hide_password, password, spbutton))
            timer.start()
        else:
            spbutton.image = self.openeye
            spbutton.config(borderwidth=0, image=self.openeye)
            password.configure(state="readonly", show="*")

    def copy_password(self, which):
        """
        Copy Password to clipboard.
        """
        self.window.clipboard_clear()
        self.window.clipboard_append(self.enc.decrypt_text(which))

    def go_to_website(self, which):
        """
        Open Website Value in the default Browser.
        """
        webbrowser.open(which, new=2)

    def remove_password(self, which):
        """
        Removes the password from the database and sync the database screen.
        """
        self.db.delete_password(which)
        self.database_screen()

    def add_password(self):
        """
        add the password to the database encrypted.
        """
        website = self.popup_en("Website")
        if website == None:
            return False
        username = self.popup_en("Username OR Email")
        if username == None:
            return False
        password = self.popup_en("Password")
        if password == None:
            return False

        new_password_dict = {
            "username": username,
            "password_hash": self.enc.encrypt_text(self.enc.to_bytes(password)),
            "link": website
        }

        self.db.insert_password(new_password_dict)
        self.database_screen()
    
    def popup_en(self, X):
        """
        Asks the user the details.
        """
        an = simpledialog.askstring("Enter Info:", X)
        return an

    def get_help(self):
        """
        This will open the help guide in browser.
        """
        webbrowser.open("https://github.com/r3veal/LockBox/wiki", new=2)

    def browse_file(self):
        """
        Let's you insert the KEYFILE
        """
        file = filedialog.askopenfile(
            mode="r",
        )
        if file:
            filepath = os.path.abspath(file.name)

            #displayed_name = [i for i in filepath.split("/")]

            #if len(displayed_name) > 3:
            #    minimal_filepath = f"../{'/'.join(displayed_name[-3::])}"
            #else:
            #    minimal_filepath = f"..{'/'.join(displayed_name[-3::])}"

            self.keyfile_path.config(text=file.name, fg="green")

            # Update Database
            self.configuration["keyfile_path"] = filepath

            new_config_dict: dict = {
                "password_hash": self.configuration["password_hash"],
                "keyfile_hash": self.configuration["keyfile_hash"],
                "keyfile_path": self.configuration["keyfile_path"],
                "salt": self.configuration["salt"]
            }

            self.db.set_configuration(new_config_dict)
