const fs = require('fs').promises;
const bcrypt = require('bcrypt');
const path = require('path');
const { deriveKey, encryptText, decryptText } = require('./cryptoUtils.js');

const { addUserToCache } = require('./userData.js');

const usersFilePath = path.join(__dirname, '..', 'data.csv');

const APP_SECRET = process.env.APP_SECRET || 'hehe-secret-key';

/*
 * Hashes a password and saves the new user to the CSV.
 */
async function createNewUser(username, email, plainTextPassword) {
    try {
        const saltRounds = 10;
        const salt = await bcrypt.genSalt(saltRounds);
        const passwordHash = await bcrypt.hash(plainTextPassword, salt);

        const key = deriveKey(APP_SECRET);

        const encEmail = encryptText(email, key);
        const encUsername = encryptText(username || '', key);

        let prefix = '';
        try {
            const stat = await fs.stat(usersFilePath);
            if (stat.size === 0) {
                prefix = 'email_enc,username_enc,salt,password_hash,iv_email,tag_email,iv_username,tag_username\n';
            }
        } catch (e) {
            // If file doesn't exist, create with header
            if (e.code === 'ENOENT') {
                await fs.writeFile(usersFilePath, 'email_enc,username_enc,salt,password_hash,iv_email,tag_email,iv_username,tag_username\n');
            }
        }

        const line = [
            encEmail.ciphertextB64,
            encUsername.ciphertextB64,
            salt,
            passwordHash,
            encEmail.ivB64,
            encEmail.tagB64,
            encUsername.ivB64,
            encUsername.tagB64
        ].join(',');

        const csvLine = (prefix ? prefix : '') + line + '\n';
        await fs.appendFile(usersFilePath, csvLine);

        addUserToCache(email);

        return true;

    } catch (error) {
        console.error("Error in createNewUser:", error);
        return false;
    }
}

module.exports = {
    createNewUser,
    deriveKey,
    decryptText
};

