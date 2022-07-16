from app import *
from enc import *

import os

# Change the directory to the running file's directory to avoid import errors
file_directory_path = os.path.dirname(os.path.realpath(__file__))
current_working_directory = os.getcwd()

if current_working_directory != file_directory_path:
    os.chdir(file_directory_path)
    current_working_directory = os.getcwd()

# Run the app
app = App()
if app.configuration == None:
    app.new_user()
else:
    if app.configuration.get("keyfile_path", "") == None:
        access = app.login_without_keyfile()
    else:
        access = app.login_with_keyfile()

app.window.mainloop()