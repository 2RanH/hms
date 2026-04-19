# 🏥 Hospital Management System (HMS)

A lightweight backend-driven Hospital Management System built with Python.
Designed for managing core medical workflows with simple deployment and easy maintenance.

---

## 🚀 Features

* User authentication (secure login system)
* Patient data management
* Modular backend structure (auth, models, routes, services)
* File-based database (SQLite)
* Simple deployment on Linux server (DigitalOcean)
* Git-based update workflow

---

## 🧱 Project Structure

```
hms/
│
├── main.py
├── database.py
├── models/
├── routes/
├── services/
├── auth/
├── static/
├── templates/
├── backups/
├── venv/        (ignored)
├── .env         (ignored)
└── README.md
```

---

## ⚙️ Installation (Local Setup)

### 1. Clone repository

```
git clone https://github.com/YOUR_USERNAME/hms.git
cd hms
```

---

### 2. Create virtual environment

```
python -m venv venv
```

Activate:

Windows:

```
venv\Scripts\activate
```

Linux:

```
source venv/bin/activate
```

---

### 3. Install dependencies

```
pip install -r requirements.txt
```

---

### 4. Run the app

```
python main.py
```

---

## 🌐 Deployment (DigitalOcean)

### Update workflow

On your PC:

```
git add .
git commit -m "update"
git push
```

On server:

```
cd /root/hms
git pull
pm2 restart all
```

---

## 💾 Database & Backups

* Uses SQLite (file-based database)
* Database file is NOT tracked in Git
* Backups should be done manually or via cron jobs

---

## ⚠️ Important Notes

* Do NOT commit:

  * `.env`
  * database files (`*.db`)
  * `venv/`
* Always backup DB before major updates

---

## 📈 Future Improvements

* Move DB outside project folder
* Add automated backups
* Add staging environment
* Switch to PostgreSQL

---

## 👤 Author

Turan Hasanli
