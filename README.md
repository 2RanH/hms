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
pip install -r requirements.txt
python db/migrate.py
pm2 restart all
```

`db/migrate.py` is safe to run repeatedly. It only creates missing tables and adds missing columns, so existing production records are preserved.

### Production security environment

Create or edit the production environment file:

```
cd /root/hms
nano .env
```

Add:

```
HSM_COOKIE_SECURE=true
HSM_ENABLE_HSTS=true
HSM_SESSION_DAYS=1
HSM_LOGIN_MAX_ATTEMPTS=5
HSM_LOGIN_WINDOW_SECONDS=900
HSM_MAX_ATTACHMENT_MB=10
HSM_MAX_ATTACHMENTS_PER_RECORD=10
```

Then restart the app:

```
pm2 restart all --update-env
```

`HSM_COOKIE_SECURE=true` requires HTTPS. Keep it enabled on DigitalOcean production. For local HTTP testing, leave it unset or set it to `false`.

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
