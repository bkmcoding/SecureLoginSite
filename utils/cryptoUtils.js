const crypto = require('crypto');

function deriveKey(secret) {
    return crypto.createHash('sha256').update(secret, 'utf8').digest();
}

function encryptText(plainText, key) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
        ciphertextB64: ciphertext.toString('base64'),
        ivB64: iv.toString('base64'),
        tagB64: tag.toString('base64')
    };
}

function decryptText(ciphertextB64, ivB64, tagB64, key) {
    const iv = Buffer.from(ivB64, 'base64');
    const tag = Buffer.from(tagB64, 'base64');
    const ciphertext = Buffer.from(ciphertextB64, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plain.toString('utf8');
}

module.exports = {
    deriveKey,
    encryptText,
    decryptText
};


