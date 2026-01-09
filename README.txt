for using app.py you must install required libraries
run this on your terminal: """    pip install -r requirements.txt    """

Folder contents:
`app.py`: main application code (Flask + Pywebview)
`templates\`: HTML files for the user interface
`static\`: CSS, JavaScript, and images
`dist\`: includes the .exe file and its database
`StudySpacePlus\dist\instance\studyspace.db`: database that has reservations and accounts of the .exe app (created automatically on first run)
`StudySpacePlus\instance\studyspace.db`: database of reservations and accounts you make when you use the pop up app from running the python code
`StudySpacePlus.spec`: automatically created when you run PyInstaller, the app will create it again if it is deleted
`build\`: automatically created when you run PyInstaller, the app will create it again if it is deleted



StudySpacePlus.exe already exists but if you would like to rebuild it paste this in powershell inside the folder:
""" pyinstaller --noconfirm --onefile --windowed --add-data "templates;templates" --add-data "static;static" --add-data ".env;.env" --hidden-import "psycopg2" --hidden-import "dotenv" --name "StudySpacePlus" app.py    """ 


the StudySpacePlus app is located in `StudySpacePlus\dist\StudySpacePlus.exe`

you can move StudySpacePlus.exe to any directory you want and it will still work by itself, it doesnt need the rest of the files to work.

By default, this uses a local test database. If you want to connect to the real cloud database, contact me for the .env credentials.

we use a cloud based database so when connected to it you are able to see all reservations and users ever created anywhere.

credentials of the default admin account:
Username: `admin`
Password: `admin123`