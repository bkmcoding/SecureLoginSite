const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const { deriveKey, decryptText } = require('./cryptoUtils.js');

const usersFilePath = path.join(__dirname, '..', 'data.csv');

// This is our in-memory cache.
const userEmailCache = new Set();

/*
 * Reads the CSV file and loads all emails into the in-memory cache.
 */
async function initializeUserCache() {
    try {
        const data = await fs.readFile(usersFilePath, 'utf8');
        const lines = data.split('\n');

        const header = (lines[0] || '').toLowerCase();
        const isNewFormat = header.startsWith('email_enc,');

        const startIdx = 1; // skip header
        for (let i = startIdx; i < lines.length; i++) {
            const line = lines[i];
            if (line) {
                const [col0] = line.split(',');
                if (col0) userEmailCache.add(col0);
            }
        }
        console.log(`[User Cache] Loaded ${userEmailCache.size} users into memory.`);
    } catch (error) {
        // This handles the case where the file doesn't exist yet
        if (error.code === 'ENOENT') {
            console.log('[User Cache] users_secure.csv not found. Starting with an empty cache.');
        } else {
            console.error('[User Cache] Error loading user cache:', error);
        }
    }
}



/*
 * Instantly checks if an email exists in the cache.
 * returns true if email is used
 */
async function doesUserExistAsync(email) {
    try {
        const data = await fs.readFile(usersFilePath, 'utf8');
        const lines = data.split('\n').filter(Boolean);
        if (lines.length === 0) return false;
        const header = (lines[0] || '').toLowerCase();
        const isNewFormat = header.startsWith('email_enc,');
        const key = deriveKey(process.env.APP_SECRET || 'hehe-secret-key');
        for (let i = 1; i < lines.length; i++) {
            try {
                const parts = lines[i].split(',');
                if (!parts[0]) continue;
                if (isNewFormat) {
                    if (parts.length < 8) continue;
                    const [emailEnc, _usernameEnc, _salt, _hash, ivEmail, tagEmail] = parts;
                    const decrypted = decryptText(emailEnc, ivEmail, tagEmail, key);
                    if (decrypted === email) return true;
                } else {
                    // Legacy: email, password_hash
                    const [plainEmail] = parts;
                    if (plainEmail === email) return true;
                }
            } catch (_e) {
                continue;
            }
        }
        return false;
    } catch (e) {
        return false;
    }
}


function addUserToCache(email) {
    userEmailCache.add(email);
    console.log(`[User Cache] Added entry to cache. New size: ${userEmailCache.size}`);
}

module.exports = {
    initializeUserCache,
    doesUserExistAsync,
    addUserToCache
};
