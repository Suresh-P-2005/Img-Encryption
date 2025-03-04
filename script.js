const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const PORT = 3000;
app.use(cors({origin: 'https://67c6b97ca413c7357c8acf64--ephemeral-otter-97c723.netlify.app/'}))
app.use(cors({ origin: '*' }));
    

// 🔹 Increase Request Size Limit
app.use(express.json({ limit: '50mb' }));  // Increase JSON payload limit
app.use(express.urlencoded({ limit: '50mb', extended: true })); // Increase form data limit

const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 50 * 2160 * 3840 } // Allow up to 50MB
});

const ALGORITHM = 'aes-256-cbc';

// Function to derive encryption key
function deriveKey(password) {
    return crypto.createHash('sha256').update(password).digest();
}

// **Encrypt Image**
app.post('/encrypt', upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    if (!req.body.password) return res.status(400).json({ error: 'No password provided' });

    try {
        const password = req.body.password;
        const key = deriveKey(password);
        const iv = crypto.randomBytes(16);

        const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
        let encrypted = cipher.update(req.file.buffer);
        encrypted = Buffer.concat([encrypted, cipher.final()]);

        const encryptedData = iv.toString('hex') + ':' + encrypted.toString('hex');

        console.log("Encrypted Data:", encryptedData);
        res.json({ encryptedText: encryptedData });

    } catch (error) {
        console.error("Encryption error:", error);
        res.status(500).json({ error: 'Encryption failed' });
    }
});

// **Decrypt Image**
app.post('/decrypt', (req, res) => {
    const { encryptedText, password } = req.body;
    if (!encryptedText) return res.status(400).json({ error: 'No encrypted data provided' });
    if (!password) return res.status(400).json({ error: 'No password provided' });

    try {
        const key = deriveKey(password);
        const textParts = encryptedText.split(':');

        if (textParts.length !== 2) {
            console.error("❌ Invalid encrypted text format!");
            return res.status(400).json({ error: 'Invalid encrypted data format' });
        }

        const iv = Buffer.from(textParts[0], 'hex');
        const encryptedBuffer = Buffer.from(textParts[1], 'hex');

        console.log("🔍 Extracted IV:", iv.toString('hex'));
        console.log("🔍 Encrypted Buffer Length:", encryptedBuffer.length);

        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        let decrypted = decipher.update(encryptedBuffer);
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        const imageBase64 = `data:image/png;base64,${decrypted.toString('base64')}`;
        console.log("✅ Successfully decrypted!");

        res.json({ imageBase64 });

    } catch (error) {
        console.error("❌ Decryption error:", error.message);
        res.status(500).json({ error: 'Decryption failed' });
    }
});

// **Start Server**
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
