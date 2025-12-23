you must have these libraries installed: Flask, Flask-SQLAlchemy, Flask-Login, pywebview, winotify

on terminal paste "pip install (name of each library)"


Folder contents:
`app.py`: main application code (Flask + Pywebview)
`templates\`: HTML files for the user interface
`static\`: CSS, JavaScript, and images
`dist\`: includes the .exe file and its database
`StudySpacePlus\dist\instance\studyspace.db`: database that has reservations and accounts of the .exe app (created automatically on first run)
`StudySpacePlus\instance\studyspace.db`: database of reservations and accounts you make when you use the pop up app from running the python code
`StudySpacePlus.spec`: automatically created when you run PyInstaller, the app will create it again if it is deleted
`build\`: automatically created when you run PyInstaller, the app will create it again if it is deleted



the StudySpacePlus app is located in `StudySpacePlus\dist\StudySpacePlus.exe`

When the application starts for the first time, a default admin account is already created
Username:`admin`
Password:`admin123`

StudySpacePlus.exe already exists but if you would like to rebuild it paste:
pyinstaller --name StudySpacePlus --onefile --noconsole --add-data "templates;templates" --add-data "static;static" app.py   in powershell inside the folder 

both database files have the reservations and users of our tests, if you want to see them sign in as admin and go to the admin panel. 
if you would like you can delete them and a new clean database will be created when you run the app or the code

you can move StudySpacePlus.exe to any directory you want and it will still work by itself, it doesnt need the rest of the files to work. but in the new directory it will create a new empty database file and it will be independant from the rest meaning that that you wont have the other users and reservations.
