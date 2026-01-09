# StudySpacePlus 📚

**StudySpacePlus** is a desktop reservation system for university study rooms, built with **Python**, **Flask**, and **PyWebview**.

## ☁️ Cloud & Local Database
This application features a **Smart Database System**:
- **Authentication**: Uses a centralized **Supabase Cloud Database** when the `.env` configuration is present (Production).
- **Zero-Config**: Falls back to a **Local SQLite Database** automatically if credentials are missing. This allows anyone to clone and run the app immediately for testing.

## 🚀 Getting Started

### Option 1: Run the Executable
If you have the `StudySpacePlus.exe` file in the `dist/` folder:
1. Double-click to launch.
2. It connects to the Cloud Database automatically (if built with secrets) or runs locally.

### Option 2: Run from Source (Developers)
1. **Clone the repository**:
   ```bash
   git clone https://github.com/selimbesir/StudySpacePlus.git
   cd StudySpacePlus
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the app**:
   ```bash
   python app.py
   ```
   *Note: This will use the local SQLite database by default.*

## 🔒 Configuration (Optional)
To connect to the **Production Cloud Database**, create a `.env` file in the root directory (see `.env.example`):
```ini
SECRET_KEY=your_secret_key
DATABASE_URL=postgresql://...
```
*(Contact the maintainer for credentials)*

## 🛠️ Building the .exe
To bundle the application into a standalone executable:

```powershell
pyinstaller --noconfirm --onefile --windowed --add-data "templates;templates" --add-data "static;static" --add-data ".env;.env" --hidden-import "psycopg2" --hidden-import "dotenv" --name "StudySpacePlus" app.py
```

## 🔑 Default Admin Credentials
- **Username**: `admin`
- **Password**: `admin123`

## 📬 Contact
Have questions or want to contribute?
- **GitHub**: [@selimbesir](https://github.com/selimbesir)
- **Email**: [Add your email here]
- **LinkedIn**: [Add your LinkedIn here]


