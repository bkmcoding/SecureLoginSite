const express = require('express');
const router = express.Router();
const { createNewUser } = require('../utils/userUtils.js');
const { deriveKey, decryptText } = require('../utils/cryptoUtils.js');
const { doesUserExistAsync } = require('../utils/userData.js'); // <-- 1. Import it
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcrypt');

router.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!email || !password || password.length < 8) {
        return res.status(400).send('Email/password invalid.');
    }

    if (await doesUserExistAsync(email)) {
        return res.status(409).send('User with this email already exists.');
    }
    
    // If validation passes, create the user
    const wasSuccessful = await createNewUser(username, email, password);
    
    if (wasSuccessful) {
        res.redirect('/'); 
    } else {
        return res.status(500).send('Error creating user.');
    }
});

router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.redirect('/?error=missing');
    }
    const normEmail = String(email).trim().toLowerCase();

    const usersFilePath = path.join(__dirname, '..', 'data.csv');

    try {
        const data = await fs.readFile(usersFilePath, 'utf8');
        const lines = data.split('\n').filter(Boolean);
        if (lines.length === 0) return res.redirect('/?error=invalid');

        const header = lines[0].toLowerCase();
        const isNewFormat = header.startsWith('email_enc,');
        let found = false;
        let username = '';
        const key = deriveKey(process.env.APP_SECRET || 'hehe-secret-key');

        for (let i = isNewFormat ? 1 : 0; i < lines.length; i++) {
            try {
                const parts = lines[i].split(',');
                if (!parts[0]) continue;

                if (isNewFormat) {
                    if (parts.length < 8) continue;
                    const [emailEnc, usernameEnc, _salt, passwordHash, ivEmail, tagEmail, ivUsername, tagUsername] = parts;
                    let decryptedEmail;
                    try {
                        decryptedEmail = decryptText(emailEnc, ivEmail, tagEmail, key);
                    } catch (_e) {
                        continue;
                    }
                    if (decryptedEmail && decryptedEmail.trim().toLowerCase() === normEmail) {
                        const ok = await bcrypt.compare(password, passwordHash);
                        if (ok) {
                            found = true;
                            username = decryptText(usernameEnc, ivUsername, tagUsername, key) || '';
                        }
                        break;
                    }
                } else {
                    // old: email, password_hash
                    const [plainEmail, passwordHash] = parts;
                    if (plainEmail && plainEmail.trim().toLowerCase() === normEmail) {
                        const ok = await bcrypt.compare(password, passwordHash);
                        if (ok) {
                            found = true;
                            username = email.split('@')[0];
                        }
                        break;
                    }
                }
            } catch (_e) {
                // Skip malformed row
                continue;
            }
        }

        if (found) {
            const encoded = encodeURIComponent(username || 'User');
            return res.redirect(`/dashboard.html?name=${encoded}`);
        }
        return res.redirect('/?error=invalid');
    } catch (e) {
        return res.redirect('/?error=server');
    }
});

router.get('/logout', (req, res) => {
    return res.redirect('/');
});

module.exports = router;