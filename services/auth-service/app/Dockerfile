# Dockerfile
FROM python:3.9-slim

# Установка зависимостей
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Копируем все файлы приложения
COPY . /app

# Открываем порт
EXPOSE 8000

# Команда запуска приложения
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
