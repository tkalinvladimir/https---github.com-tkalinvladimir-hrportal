import os

class Config:
    SECRET_KEY = '123124421421'  # Замените на случайный ключ
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False