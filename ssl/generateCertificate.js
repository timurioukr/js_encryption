const forge = require('node-forge');
const fs = require('fs');

// Генерація RSA ключів
function generateKeyPair() {
    const keypair = forge.pki.rsa.generateKeyPair(2048);
    return keypair;
}

// Генерація самопідписаного сертифіката
function generateSelfSignedCertificate() {
    const keypair = generateKeyPair();

    // Створення сертифіката
    const cert = forge.pki.createCertificate();
    cert.publicKey = keypair.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1); // Сертифікат дійсний 1 рік

    const attrs = [{
        name: 'commonName',
        value: 'localhost'
    }, {
        name: 'countryName',
        value: 'UA'
    }, {
        shortName: 'ST',
        value: 'Kyiv'
    }, {
        name: 'localityName',
        value: 'Kyiv'
    }, {
        name: 'organizationName',
        value: 'Localhost'
    }, {
        shortName: 'OU',
        value: 'Localhost Cert'
    }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);

    // Додавання розширень
    cert.setExtensions([{
        name: 'basicConstraints',
        cA: true
    }, {
        name: 'keyUsage',
        keyCertSign: true,
        digitalSignature: true,
        nonRepudiation: true,
        keyEncipherment: true,
        dataEncipherment: true
    }, {
        name: 'extKeyUsage',
        serverAuth: true,
        clientAuth: true,
        codeSigning: true,
        emailProtection: true,
        timeStamping: true
    }, {
        name: 'subjectAltName',
        altNames: [{
            type: 2, // DNS
            value: 'localhost'
        }]
    }]);

    // Підписання сертифіката приватним ключем
    cert.sign(keypair.privateKey, forge.md.sha256.create());

    // Експорт приватного ключа та сертифіката в PEM формат
    const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);
    const certPem = forge.pki.certificateToPem(cert);

    // Запис у файли
    fs.writeFileSync('key.pem', privateKeyPem);
    fs.writeFileSync('cert.pem', certPem);

    console.log("Сертифікат і ключ згенеровані та збережені у файли 'key.pem' і 'cert.pem'");
}

// Генерація сертифіката
generateSelfSignedCertificate();