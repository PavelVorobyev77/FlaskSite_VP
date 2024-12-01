from flask import Flask, render_template, redirect, request, url_for, flash, session, Response, send_file
from passlib.hash import sha256_crypt
from flask_session import Session
from sqlalchemy import create_engine, text
from sqlalchemy.orm import scoped_session, sessionmaker
from flask import request, redirect, url_for, flash
from werkzeug.security import generate_password_hash
import base64
from base64 import b64encode
import smtplib
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String, ForeignKey, LargeBinary, Text
from email.mime.text import MIMEText
from random import randint

# Подключение к MS SQL Server с Windows Authentication
engine = create_engine(
    "mssql+pyodbc://@DESKTOP-BK1T0PD\\SQLEXPRESS/ProjectServer_VP?driver=ODBC+Driver+17+for+SQL+Server"
)

db = scoped_session(sessionmaker(bind=engine))

app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

app.secret_key = "951753123456987"  # Секретный ключ для сессий

# Хранилище временных кодов сброса паролей
reset_codes = {}



Base = declarative_base()

class User(Base):
    __tablename__ = 'Users'

    Id_User = Column(Integer, primary_key=True, autoincrement=True)
    Name = Column(String(150), nullable=False)
    Phone = Column(String(50), nullable=False)
    Email = Column(String(100), nullable=False)
    Password = Column(String(256), nullable=False)
    Id_Role = Column(Integer, ForeignKey('Roles.Id_Role'), nullable=True)
    Id_News = Column(Integer, ForeignKey('News.Id_News'), nullable=True)
    Image = Column(LargeBinary, nullable=True)
    Description = Column(Text, nullable=True)

def send_email(user_email, code):
    from_email = "pascha27_05@mail.ru"
    password = "RgWnhXtdxuN42dhLFPRG"  # Замените на пароль приложения Mail.ru

    # Фиксированный email получателя
    to_email = "pascha27_05@mail.ru"

    subject = f"Код для сброса пароля (запрошено для {user_email})"
    body = f"Ваш код для сброса пароля: {code}\nЗапрос был сделан для {user_email}"
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    try:
        with smtplib.SMTP_SSL("smtp.mail.ru", 465) as server:
            server.login(from_email, password)
            server.sendmail(from_email, [to_email], msg.as_string())
        print(f"Письмо успешно отправлено на {to_email}")
    except Exception as e:
        print(f"Ошибка при отправке письма: {e}")
        flash("Ошибка при отправке письма. Проверьте настройки.", "danger")


# Главная страница
@app.route("/")
def home():
    return render_template("home.html")

# Регистрация пользователя
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        phone = request.form.get("phone")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        secure_password = sha256_crypt.encrypt(str(password))

        if password == confirm_password:
            query = text("""
                INSERT INTO Users (Name, Phone, Email, Password, Id_Role, Id_News, Image, Description)
                VALUES (:name, :phone, :email, :password, NULL, NULL, NULL, NULL)
            """)
            db.execute(query, {
                "name": name,
                "phone": phone,
                "email": email,
                "password": secure_password
            })
            db.commit()
            flash("Registration successful!", "success")
            return redirect(url_for("login"))
        else:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")

    return render_template("register.html")

# Авторизация пользователя
@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        # Проверяем наличие пользователя по email
        email_query = text("SELECT Id_User, Password, Id_Role FROM Users WHERE Email = :email")
        user_data = db.execute(email_query, {"email": email}).fetchone()

        if user_data is None:
            flash("Email not found or incorrect", "danger")
            return render_template("login.html")

        # Извлекаем данные пользователя
        user_id, hashed_password, role_id = user_data

        # Проверяем пароль
        if sha256_crypt.verify(password, hashed_password):
            session["user_id"] = user_id
            session["role_id"] = role_id  # Сохраняем роль в сессии
            flash("Login successful", "success")

            # Перенаправляем пользователя в зависимости от роли
            if role_id == 1:  # Администратор
                return redirect(url_for("admin_page"))
            elif role_id == 2:  # Менеджер
                return redirect(url_for("manager_page"))
            elif role_id == 3:  # Клиент
                return redirect(url_for("client_page"))
        else:
            flash("Incorrect email or password", "danger")
            return render_template("login.html")

    return render_template("login.html")



# Сброс пароля
@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        email = request.form.get("email")

        user = db.execute(text("SELECT Id_User FROM Users WHERE Email = :email"), {"email": email}).fetchone()
        if user is None:
            flash("Email не найден.", "danger")
            return render_template("reset_password.html")

        code = randint(100000, 999999)
        reset_codes[email] = code
        send_email(email, code)
        flash("Код подтверждения отправлен на вашу почту.", "success")
        return redirect(url_for("verify_code", email=email))

    return render_template("reset_password.html")

# Проверка кода сброса
@app.route("/verify_code/<email>", methods=["GET", "POST"])
def verify_code(email):
    if request.method == "POST":
        entered_code = int(request.form.get("code"))

        if email in reset_codes and reset_codes[email] == entered_code:
            return redirect(url_for("set_new_password", email=email))
        else:
            flash("Неверный код подтверждения.", "danger")
            return render_template("verify_code.html", email=email)

    return render_template("verify_code.html", email=email)

# Установка нового пароля
@app.route("/set_new_password/<email>", methods=["GET", "POST"])
def set_new_password(email):
    if request.method == "POST":
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if password != confirm_password:
            flash("Пароли не совпадают.", "danger")
            return render_template("set_new_password.html", email=email)

        hashed_password = sha256_crypt.encrypt(str(password))
        db.execute(text("UPDATE Users SET Password = :password WHERE Email = :email"),
                   {"password": hashed_password, "email": email})
        db.commit()
        reset_codes.pop(email, None)
        flash("Пароль успешно изменен!", "success")
        return redirect(url_for("login"))

    return render_template("set_new_password.html", email=email)

# Выход из аккаунта
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("home"))


@app.route("/admin_page")
def admin_page():
    if "user_id" not in session:
        flash("Please log in", "danger")
        return redirect(url_for("login"))

    # Получаем данные пользователя из сессии
    user_id = session["user_id"]
    user = db.execute(
        text("SELECT Id_Role FROM Users WHERE Id_User = :user_id"),
        {"user_id": user_id}).fetchone()

    if user and user[0] == 1:  # Проверяем, что роль == 1 (админ)
        # Получаем список всех пользователей
        users = db.execute(
            text("SELECT Id_User, Name, Phone, Email, Image, Description FROM Users")
        ).fetchall()

        # Преобразуем изображения в base64
        users_list = []
        for user in users:
            image_base64 = b64encode(user.Image).decode("utf-8") if user.Image else None
            users_list.append({
                "Id_User": user.Id_User,
                "Name": user.Name,
                "Phone": user.Phone,
                "Email": user.Email,
                "Image": image_base64,
                "Description": user.Description
            })

        return render_template("admin_page.html", user=user, users=users_list)
    else:
        flash("Access denied", "danger")
        return redirect(url_for("home"))


@app.route("/manager_page")
def manager_page():
    if "user_id" not in session:
        flash("Please log in", "danger")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    user = db.execute(
        text("SELECT Id_Role FROM Users WHERE Id_User = :user_id"),
        {"user_id": user_id}).fetchone()

    if user and user[0] == 2:  # Проверяем, что роль == 2 (менеджер)
        # Получаем новости для менеджера
        news = db.execute(
            text("SELECT Id_News, Text FROM News")
        ).fetchall()
        return render_template("manager_page.html", user=user, news=news)
    else:
        flash("Access denied", "danger")
        return redirect(url_for("home"))


@app.route("/client_page")
def client_page():
    if "user_id" not in session:
        flash("Please log in", "danger")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    user_query = text("""
        SELECT Id_Role, Id_User, Name, Phone, Email, Image, Description
        FROM Users WHERE Id_User = :user_id
    """)
    user = db.execute(user_query, {"user_id": user_id}).fetchone()

    if user and user[0] == 3:  # Роль клиента
        # Преобразуем BLOB-изображение в Base64 для отображения
        image_base64 = b64encode(user.Image).decode("utf-8") if user.Image else None
        user_dict = {
            "Id_User": user[1],
            "Role": user[0],
            "Name": user[2],
            "Phone": user[3],
            "Email": user[4],
            "Image": image_base64,
            "Description": user[6]
        }
        return render_template("client_page.html", user=user_dict)
    else:
        flash("Access denied", "danger")
        return redirect(url_for("home"))


@app.route('/update_user/<int:user_id>', methods=['POST'])
def update_user(user_id):
    # Получаем данные из формы
    name = request.form.get('name')
    phone = request.form.get('phone')
    email = request.form.get('email')
    password = request.form.get('password')  # Новый пароль
    description = request.form.get('description')
    image_file = request.files.get('image')

    # Если файл изображения был загружен, читаем его
    image_data = None
    if image_file and image_file.filename:
        image_data = image_file.read()  # Получаем бинарные данные изображения

    # Хэшируем пароль, если он введён
    hashed_password = None
    if password:
        hashed_password = sha256_crypt.encrypt(str(password))  # Хэшируем пароль

    # Обновляем пользователя в базе данных
    query = text("""
        UPDATE Users
        SET Name = :name, 
            Phone = :phone, 
            Email = :email, 
            Description = :description, 
            Image = COALESCE(:image, Image),      -- Если новое изображение не передано, оставляем старое
            Password = COALESCE(:password, Password) -- Если новый пароль не передан, оставляем старый
        WHERE Id_User = :user_id
    """)

    # Передаем параметры
    db.execute(query, {
        "name": name,
        "phone": phone,
        "email": email,
        "description": description,
        "image": image_data,  # Передаем изображение, если оно есть
        "password": hashed_password,  # Передаем хэшированный пароль, если он есть
        "user_id": user_id
    })

    db.commit()

    flash("Данные пользователя успешно обновлены.", "success")
    return redirect(url_for('admin_page'))



@app.route("/update_news/<int:news_id>", methods=["POST"])
def update_news(news_id):
    news_text = request.form.get("text")

    # Обновляем текст новости
    query = text("""
        UPDATE News 
        SET Text = :text 
        WHERE Id_News = :news_id
    """)
    db.execute(query, {"text": news_text, "news_id": news_id})
    db.commit()
    flash("Changes saved successfully", "success")
    return redirect(url_for("manager_page"))


@app.route("/update_profile/<int:user_id>", methods=["POST"])
def update_profile(user_id):

    name = request.form.get("name")
    phone = request.form.get("phone")
    email = request.form.get("email")
    password = request.form.get('password')  # Новый пароль
    description = request.form.get("description")
    image_file = request.files.get("image")

    # Если файл изображения был загружен, читаем его
    image_data = None
    if image_file and image_file.filename:
        image_data = image_file.read()  # Получаем бинарные данные изображения

    # Хэшируем пароль, если он введён
    hashed_password = None
    if password:
        hashed_password = sha256_crypt.encrypt(str(password))  # Хэшируем пароль

    # Обновляем пользователя в базе данных
    query = text("""
        UPDATE Users
        SET Name = :name, 
            Phone = :phone, 
            Email = :email, 
            Description = :description, 
            Image = COALESCE(:image, Image),      -- Если новое изображение не передано, оставляем старое
            Password = COALESCE(:password, Password) -- Если новый пароль не передан, оставляем старый
        WHERE Id_User = :user_id
    """)

    # Передаем параметры
    db.execute(query, {
        "name": name,
        "phone": phone,
        "email": email,
        "description": description,
        "image": image_data,  # Передаем изображение, если оно есть
        "password": hashed_password,  # Передаем хэшированный пароль, если он есть
        "user_id": user_id
    })

    db.commit()

    flash("Profile updated successfully!", "success")
    return redirect(url_for("client_page"))


@app.route("/get_image/<int:user_id>")
def get_image(user_id):
    # Получаем бинарные данные изображения из базы данных
    image = db.execute(
        text("SELECT Image FROM Users WHERE Id_User = :user_id"),
        {"user_id": user_id}
    ).scalar()

    if image:
        return Response(image, mimetype="image/jpeg")  # Убедитесь, что формат соответствует вашему изображению
    else:
        # Если изображения нет, возвращаем placeholder
        return send_file("static/photo.jpg", mimetype="image/jpeg")


if __name__ == "__main__":
    app.run(debug=True)
