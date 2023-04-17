from werkzeug.security import generate_password_hash


# для создания пользователей через базу данных
print(generate_password_hash("1234"))
