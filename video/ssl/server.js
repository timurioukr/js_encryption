const https = require('https');
const fs = require('fs');
const path = require('path');
const express = require('express');

const app = express();

// Завантаження сертифіката та ключа

const options = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem')
};

// Вказуємо шлях до статичних файлів (ваш HTML, CSS, JS файли)
app.use(express.static(path.join(__dirname, 'public')));

// Відповідь на GET запит для домашньої сторінки
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Створення HTTPS сервера
https.createServer(options, app).listen(3000, () => {
  console.log('Сервер працює за адресою https://localhost:3000');
});