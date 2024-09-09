const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// Secret key (192-bit)
const secretKeys = {
  '01': Buffer.from('0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF', 'hex'), // 24 byte
  '02': Buffer.from('89ABCDEF012345670123456789ABCDEF0123456789ABCDEF', 'hex'), // 24 byte
};

// Fungsi enkripsi dengan 3DES-ECB
function encrypt3DESECB(data, keyId) {
  const secretKey = secretKeys[keyId];
  if (!secretKey) {
    throw new Error('Invalid key ID');
  }

  // Convert data to Buffer
  let paddedData = Buffer.from(data);

  // Pad data to multiple of 8 bytes
  while (paddedData.length % 8 !== 0) {
    paddedData = Buffer.concat([paddedData, Buffer.from([0xFF])]);
  }

  const cipher = crypto.createCipheriv('des-ede3', secretKey, null);
  let encrypted = cipher.update(paddedData);
  encrypted = Buffer.concat([encrypted, cipher.final()]);

  return encrypted;
}

// Fungsi dekripsi dengan 3DES-ECB
function decrypt3DESECB(encryptedData, keyId) {
  const secretKey = secretKeys[keyId];
  if (!secretKey) {
    throw new Error('Invalid key ID');
  }

  const decipher = crypto.createDecipheriv('des-ede3', secretKey, null);
  let decrypted = decipher.update(Buffer.from(encryptedData, 'hex'));
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  // Remove padding
  let end = decrypted.length;
  while (end > 0 && decrypted[end - 1] === 0xFF) {
    end--;
  }

  return decrypted.slice(0, end).toString('utf8');
}

// Membuat MAC (Message Authentication Code)
function createMAC(encryptedBody, keyId) {
  const secretKey = secretKeys[keyId];
  const lastByte = encryptedBody.slice(-2); // Ambil byte terakhir
  const footer = Buffer.from(`${lastByte}FFFFFFFFFFFFFF`, 'hex');

  const cipher = crypto.createCipheriv('des-ede3', secretKey, null);
  let mac = cipher.update(footer);
  mac = Buffer.concat([mac, cipher.final()]);

  return mac;
}

// Membentuk header (3-byte)
function createHeader(encryptedBodyLength, keyId) {
  const totalLength = (1 + encryptedBodyLength + 8).toString(16).padStart(4, '0'); // Panjang total dalam hex
  const header = `${totalLength}${keyId}`;
  return header;
}

// Endpoint untuk mengenkripsi data
app.post('/api/encrypt', (req, res) => {
  const { data, keyId } = req.body;

  try {
    const encryptedBody = encrypt3DESECB(data, keyId);
    const mac = createMAC(encryptedBody, keyId);
    const header = createHeader(encryptedBody.length, keyId);
    
    const encryptedString = `${header}${encryptedBody.toString('hex')}${mac.toString('hex')}`;
    res.json({ encrypted: encryptedString });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Endpoint untuk mendekripsi data
app.post('/api/decrypt', (req, res) => {
  const { encryptedData, keyId } = req.body;

  try {
    // Memisahkan header, body, dan MAC dari encryptedData
    const headerLength = parseInt(encryptedData.slice(0, 4), 16);
    const keyIdIndex = encryptedData.slice(4, 6);
    const encryptedBody = encryptedData.slice(6, -16); // -16 karena MAC panjangnya 16 karakter hex (8 byte)
    const mac = encryptedData.slice(-16);

    if (keyIdIndex !== keyId) {
      throw new Error('Invalid key ID');
    }

    const decryptedData = decrypt3DESECB(encryptedBody, keyId);
    res.json({ decrypted: decryptedData, header: encryptedData.slice(0, 6), mac });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// jalanin server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
