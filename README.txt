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


online webapp version:
StudySpacePlus is also available as a webapp so you dont need to download anything.
you can access it here: https://studyspaceplus.onrender.com
(since its on the free tier, it might take a minute to load correctly if no one has used it in a while)


the app connects to the shared public cloud database so everyone sees the same reservations.
NOTE: Database credentials are included in the source code for ease of access as this is a student project, if implemented in a production environment, the database credentials would be stored in a secure environment variable.


credentials of the default admin account:
Username: `admin`
Password: `admin123`
