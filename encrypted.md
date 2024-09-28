Типи шифрування у веб-розробці: види, використання та приклади

Шифрування є ключовим компонентом безпеки у веб-розробці. Воно забезпечує конфіденційність, цілісність та автентичність даних, що передаються між клієнтом і сервером, або зберігаються в базах даних. Нижче описано основні типи шифрування, які використовуються у веб-розробці, їх застосування та приклади.
1. Симетричне шифрування
Опис

Симетричне шифрування використовує один і той самий ключ для шифрування та дешифрування даних. Це швидкий і ефективний спосіб шифрування великих обсягів даних.
Алгоритми

    AES (Advanced Encryption Standard): Широко використовується у веб-додатках для шифрування даних.
    DES (Data Encryption Standard): Застарілий алгоритм, замінений на більш безпечні, такі як AES.
    3DES (Triple DES): Покращена версія DES, але також вважається застарілою.

Використання

    Шифрування даних у базах даних: Захист конфіденційних даних, таких як паролі або особиста інформація.
    Шифрування файлів: Захист файлів, що зберігаються на сервері або передаються між сервером і клієнтом.
    Сесійні токени: Іноді використовуються для шифрування даних сесії.

Приклад (AES у Node.js)

javascript

const crypto = require('crypto');

const algorithm = 'aes-256-cbc';
const secretKey = 'ваш_секретний_ключ_32_байти';
const iv = crypto.randomBytes(16);

function encrypt(text) {
  const cipher = crypto.createCipheriv(algorithm, Buffer.from(secretKey), iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(hash) {
  const parts = hash.split(':');
  const iv = Buffer.from(parts.shift(), 'hex');
  const encryptedText = Buffer.from(parts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv(algorithm, Buffer.from(secretKey), iv);
  const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
  return decrypted.toString();
}

2. Асиметричне шифрування
Опис

Асиметричне шифрування використовує пару ключів: публічний та приватний. Публічний ключ використовується для шифрування, а приватний — для дешифрування.
Алгоритми

    RSA (Rivest–Shamir–Adleman): Один із найпоширеніших асиметричних алгоритмів.
    ECC (Elliptic Curve Cryptography): Більш сучасний і ефективний метод, що використовує еліптичні криві.

Використання

    SSL/TLS: Захищене з'єднання між клієнтом і сервером.
    Електронні цифрові підписи: Підтвердження автентичності та цілісності даних.
    Керування ключами: Обмін секретними ключами для симетричного шифрування.

Приклад (RSA для шифрування повідомлення)

javascript

const crypto = require('crypto');

// Генерація пари ключів
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

// Шифрування повідомлення
const message = 'Секретне повідомлення';
const encryptedData = crypto.publicEncrypt(
  publicKey,
  Buffer.from(message)
);

// Дешифрування повідомлення
const decryptedData = crypto.privateDecrypt(
  privateKey,
  encryptedData
);

console.log('Розшифроване повідомлення:', decryptedData.toString());

3. Хешування
Опис

Хешування — це одностороннє перетворення даних у фіксований рядок символів. Воно використовується для зберігання паролів та перевірки цілісності даних.
Алгоритми

    SHA-256, SHA-512: Безпечні алгоритми хешування.
    bcrypt: Алгоритм хешування з солью, спеціально розроблений для зберігання паролів.
    scrypt: Подібний до bcrypt, але більш ресурсомісткий для підвищення безпеки.
    Argon2: Сучасний алгоритм хешування паролів, визнаний переможцем конкурсу Password Hashing Competition.

Використання

    Зберігання паролів: Замість зберігання паролів у відкритому вигляді зберігаються їх хеші.
    Перевірка цілісності файлів: Хеш файлу можна використовувати для перевірки, чи не був файл змінений.

Приклад (bcrypt у Node.js)

javascript

const bcrypt = require('bcrypt');

const password = 'мій_секретний_пароль';
const saltRounds = 10;

// Хешування паролю
bcrypt.hash(password, saltRounds, function(err, hash) {
  // Зберегти хеш у базі даних
});

// Перевірка паролю
bcrypt.compare(password, hashFromDb, function(err, result) {
  if (result) {
    // Пароль правильний
  } else {
    // Пароль неправильний
  }
});

4. SSL/TLS (Transport Layer Security)
Опис

SSL/TLS забезпечує безпечне шифрування даних, що передаються між клієнтом і сервером через протокол HTTPS.
Використання

    Захист веб-трафіку: Шифрування всіх даних, що передаються між браузером і веб-сайтом.
    Перевірка автентичності сервера: Клієнт може бути впевнений, що підключається до справжнього сервера.

Приклад (Налаштування HTTPS сервера на Node.js)

javascript

const https = require('https');
const fs = require('fs');

const options = {
  key: fs.readFileSync('privateKey.pem'),
  cert: fs.readFileSync('certificate.pem')
};

https.createServer(options, (req, res) => {
  res.writeHead(200);
  res.end('Привіт, захищений світе!');
}).listen(443);

5. HMAC (Hash-based Message Authentication Code)
Опис

HMAC — це механізм для перевірки цілісності повідомлень та автентифікації, що використовує секретний ключ та хеш-функцію.
Використання

    Підписання API запитів: Забезпечує безпечний обмін даними між клієнтом і сервером.
    Перевірка цілісності даних: Захист від зміни даних під час передачі.

Приклад (HMAC з використанням SHA-256)

javascript

const crypto = require('crypto');

const secretKey = 'ваш_секретний_ключ';
const message = 'Дані для підпису';

const hmac = crypto.createHmac('sha256', secretKey);
hmac.update(message);
const signature = hmac.digest('hex');

console.log('Підпис:', signature);

6. JSON Web Tokens (JWT)
Опис

JWT — це стандарт для створення токенів, які можуть бути використані для автентифікації та передачі інформації між сторонами у безпечний спосіб.
Використання

    Автентифікація користувачів: Замість традиційних сесійних ідентифікаторів.
    Авторизація API запитів: Перевірка прав доступу до ресурсів.

Приклад (Створення та перевірка JWT)

javascript

const jwt = require('jsonwebtoken');

const payload = { userId: 123 };
const secretKey = 'ваш_секретний_ключ';

// Створення токена
const token = jwt.sign(payload, secretKey, { expiresIn: '1h' });

// Перевірка токена
jwt.verify(token, secretKey, (err, decoded) => {
  if (err) {
    // Токен недійсний
  } else {
    // Токен дійсний, доступ до decoded.payload
  }
});

7. Протоколи обміну ключами
Опис

Протоколи обміну ключами дозволяють двом сторонам безпечно обмінятися секретними ключами по незахищеному каналу.
Алгоритми

    Diffie-Hellman: Один із перших протоколів обміну ключами.
    ECDH (Elliptic Curve Diffie-Hellman): Більш ефективний варіант на основі еліптичних кривих.

Використання

    SSL/TLS: Використовується для обміну симетричними ключами під час встановлення з'єднання.
    VPN: Безпечний обмін ключами для шифрування трафіку.

Приклад (ECDH у Node.js)

javascript

const crypto = require('crypto');

// Сторона А
const alice = crypto.createECDH('secp256k1');
alice.generateKeys();

// Сторона Б
const bob = crypto.createECDH('secp256k1');
bob.generateKeys();

// Обмін публічними ключами та генерація спільного секрету
const aliceSecret = alice.computeSecret(bob.getPublicKey());
const bobSecret = bob.computeSecret(alice.getPublicKey());

console.log('Секрет Аліси:', aliceSecret.toString('hex'));
console.log('Секрет Боба:', bobSecret.toString('hex'));

8. Шифрування на стороні клієнта
Опис

Шифрування даних безпосередньо в браузері перед відправкою на сервер. Використовується для підвищення конфіденційності даних.
Використання

    Захист даних від перехоплення: Навіть якщо HTTPS не використовується, дані шифруються перед відправкою.
    Зберігання зашифрованих даних у локальному сховищі: Наприклад, у IndexedDB або LocalStorage.

Приклад (Використання CryptoJS для шифрування на клієнті)

html

<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
<script>
  const message = 'Секретне повідомлення';
  const secretKey = 'мій_секретний_ключ';

  const encrypted = CryptoJS.AES.encrypt(message, secretKey).toString();
  const decrypted = CryptoJS.AES.decrypt(encrypted, secretKey).toString(CryptoJS.enc.Utf8);

  console.log('Зашифровано:', encrypted);
  console.log('Розшифровано:', decrypted);
</script>

9. TLS Pinning
Опис

Механізм, при якому клієнт (наприклад, мобільний додаток) зберігає відомий публічний ключ сервера і перевіряє його під час встановлення з'єднання, щоб запобігти атакам типу "людина посередині".
Використання

    Мобільні додатки: Підвищення безпеки мережевих з'єднань.
    Критичні веб-додатки: Додаткова перевірка сертифіката сервера.

10. Обфускація та мініфікація коду
Опис

Хоча це не є шифруванням в строгому сенсі, обфускація та мініфікація використовуються для ускладнення аналізу та читання коду.
Використання

    Захист JavaScript-коду: Ускладнення розуміння логіки для зловмисників.
    Зменшення розміру файлів: Прискорення завантаження веб-сторінок.

Приклад

Використання інструментів типу UglifyJS або Terser для мініфікації коду.
Висновок

У веб-розробці використовуються різні типи шифрування для забезпечення безпеки даних на різних рівнях: під час передачі, зберігання та обробки. Вибір конкретного методу залежить від вимог безпеки, продуктивності та специфіки додатка.

Важливо враховувати останні рекомендації та стандарти безпеки, а також використовувати перевірені бібліотеки та алгоритми для запобігання вразливостям.