from tkinter import *
from time import sleep

import random
import os
import hashlib
import string

class Generator():
    """
    Generates a custom password, keyfile, and salt.
    """
    def __init__(self):
        self.digits = string.digits
        self.letters = string.ascii_letters
        self.punctuation = string.punctuation
        self.default_settings = {
            "Digits": True,
            "Punctuation": True,
            "Letters": True,
            "Number of Spaces": 2,
            "Length": 20
        }
        self.keyfile_settings = {
            "Digits": True,
            "Punctuation": True,
            "Letters": True,
            "Number of Spaces": random.randint(1, 25),
            "Length": 256
        }

    def gen_password(self, settings: dict = None) -> str:
        """
        Generates a Password with custom settings.
        """
        settings = settings or self.default_settings
        password = []

        settings_ = [key for key, value in settings.items() if value == True]

        if settings.get("Number of Spaces") != 0:
            for i in range(settings.get("Number of Spaces")):
                password.append(" ")
        
        while len(password) < settings.get("Length"):
            setting = random.choice(settings_)
            if setting == "Digits":
                password.append(random.choice(self.digits))
            elif setting == "Letters":
                password.append(random.choice(self.letters))
            elif setting == "Punctuation":
                password.append(random.choice(self.punctuation))
        
        random.shuffle(password)

        return "".join(password)

    def gen_key(self) -> str:
        """
        Generates a 256 bytes key for the KEYFILE
        """
        return self.gen_password(self.keyfile_settings)
    
    def gen_salt(self) -> bytes:
        """
        Generates a permanent salt for the encryption.
        """
        return os.urandom(32)

class Hasher():
    """
    Generates and checks a hash.
    """
    def create_hash(self, password: str) -> str:
        """
        Generates a SHA256 hash.
        """
        return hashlib.sha256(password.encode("utf-8")).hexdigest()
    
    def check_hash(self, password: str, hashed_version: str) -> bool:
        """
        Checks the password and the hash.
        """
        if hashlib.sha256(password.encode("utf-8")).hexdigest() == hashed_version:
            return True
        else:
            return False

class Generator_GUI(Generator):
    """
    GUI Generator Window.
    """
    def __init__(self):
        super().__init__()
        self.window = Toplevel()
        self.window.title("Password Generator")
        self.window.update()

        logo = PhotoImage(file="mystery-box.png")
        self.window.iconphoto(True, logo)
        self.window.geometry("500x250")
        self.window.resizable(False, False)

        # Label Frame
        self.configuration_frame = LabelFrame(self.window, text="Settings")
        self.configuration_frame.pack(pady=5)

        self.letter_variable = IntVar(value=1)
        self.letter_checkbox = Checkbutton(
            self.configuration_frame,
            text="Letters    ",
            variable=self.letter_variable,
            onvalue=1,
            offvalue=0,
        )
        self.letter_checkbox.grid(column=0, row=0, sticky="w")

        self.punctuation_variable = IntVar(value=1)
        self.punctuation_checkbox = Checkbutton(
            self.configuration_frame,
            text="Punctuation",
            variable=self.punctuation_variable,
            onvalue=1,
            offvalue=0,
        )
        self.punctuation_checkbox.grid(column=1, row=0, sticky="w")

        self.digits_variable = IntVar(value=1)
        self.digits_checkbox = Checkbutton(
            self.configuration_frame,
            text="Digits",
            variable=self.digits_variable,
            onvalue=1,
            offvalue=0,
        )
        self.digits_checkbox.grid(column=2, row=0, sticky="w")

        self.length_label = Label(
            self.configuration_frame,
            text="  Length:"
        )
        self.length_label.grid(column=0, row=1, sticky="w")

        self.length = Entry(
            self.configuration_frame,
            width="3",
        )
        self.length.insert(0, "22")
        self.length.grid(column=0, row=1, sticky="e")

        self.space_label = Label(
            self.configuration_frame,
            text="  Space:"
        )
        self.space_label.grid(column=1, row=1, sticky="w")

        self.space = Entry(
            self.configuration_frame,
            width="3",
        )
        self.space.insert(0, "2")
        self.space.grid(column=1, row=1, padx=(20,0))
    
        self.label_frame = Frame(self.window)
        self.label_frame.pack(pady=20)

        # Entry box for password
        self.password_entry_box = Entry(
            self.label_frame,
            width=50
        )
        self.password_entry_box.grid(
            columnspan=2,
            row=0,
        )

        self.copy_button = Button(
            self.label_frame,
            text="❐",
            command=self.copy_password
        )
        self.copy_button.grid(
            row=0,
            column=3,
            sticky='e'
        )

        self.generate_button = Button(
            self.label_frame,
            text="Generate Password",
            command=self.gen_pass
        )
        self.generate_button.grid(
            columnspan=3,
            row=1,
            pady=(10,0)
        )

        self.feedback = Label(self.label_frame)
        self.feedback.grid(columnspan=3, row=2)

    def gen_pass(self):
        """
        Generates Password and Inserts it in the entry.
        """
        check_boxes: set = set([self.digits_variable.get(), self.punctuation_variable.get(), self.letter_variable.get()])
        if check_boxes == {False}:
            self.feedback.config(text="At least check one setting!", fg="red")
            return 0

        if self.space.get().isdigit() == False and self.length.get().isdigit() == True:
            self.feedback.config(text="Please Insert Integer Type in The 'Space' Field.", fg="red")
            return 0
        elif self.space.get().isdigit() == True and self.length.get().isdigit() == False:
            self.feedback.config(text="Please Insert Integer Type in The 'Length' Field.", fg="red")
            return 0
        elif self.space.get().isdigit() == False and self.length.get().isdigit() == False:
            self.feedback.config(text="Please Insert Integer Type in The 'Length' and 'Space' Fields.", fg="red")
            return 0
        
        if int(self.space.get()) >= int(self.length.get()):
            self.feedback.config(text="Too Much Spaces...", fg="red")
            return 0
    
        settings: dict = {
            "Digits": self.digits_variable.get(),
            "Punctuation": self.punctuation_variable.get(),
            "Letters": self.letter_variable.get(),
            "Number of Spaces": int(self.space.get()),
            "Length": int(self.length.get())
        }
        
        self.password_entry_box.delete(0, "end")
        password = self.gen_password(settings)
        self.password_entry_box.insert(0, password)

        self.feedback.config(text="")

    def copy_password(self):
        self.window.clipboard_clear()
        self.window.clipboard_append(self.password_entry_box.get())
