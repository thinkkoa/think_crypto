/**
 * @ author: richen
 * @ copyright: Copyright (c) - <richenlin(at)gmail.com>
 * @ license: MIT
 * @ version: 2020-05-18 16:29:55
 */
const crypto = require('crypto');
const cryptoJS = require('crypto-js');

module.exports = {

    /**
     *
     *
     * @param {*} message
     * @param {*} key
     * @param {string} [iv='']
     * @param {boolean} [base64=true]
     * @param {string} [mod='CBC']  CBC,ECB
     * @param {string} [pad='Pkcs7'] Pkcs7,ZeroPadding,NoPadding
     * @returns
     */
    encrypt: function (message, key, iv = '', base64 = true, mod = 'CBC', pad = 'Pkcs7') {
        let keyHex = cryptoJS.enc.Utf8.parse(key);
        message = cryptoJS.enc.Utf8.parse(message);
        let ivHex = cryptoJS.enc.Utf8.parse(iv);
        let option = {
            mode: cryptoJS.mode[mod],
            padding: cryptoJS.pad[pad],
            iv: ivHex
        };
        let encrypted = cryptoJS.AES.encrypt(message, keyHex, option);
        if (base64) {
            return encrypted.toString();
        } else {
            return encrypted.ciphertext.toString();
        }
    },

    /**
     *
     *
     * @param {*} ciphertext
     * @param {*} key
     * @param {string} [iv='']
     * @param {boolean} [base64=true]
     * @param {string} [mod='CBC']  CBC,ECB
     * @param {string} [pad='Pkcs7'] Pkcs7,ZeroPadding,NoPadding
     * @returns
     */
    decrypt: function (ciphertext, key, iv = '', base64 = true, mod = 'CBC', pad = 'Pkcs7') {
        let keyHex = cryptoJS.enc.Utf8.parse(key);
        // let ivHex = cryptoJS.enc.Hex.parse(cryptoJS.enc.Utf8.parse(iv).toString(cryptoJS.enc.Hex));
        let ivHex = cryptoJS.enc.Utf8.parse(iv);
        let option = {
            mode: cryptoJS.mode[mod],
            padding: cryptoJS.pad[pad],
            iv: ivHex
        };
        if (base64) {
            ciphertext = cryptoJS.enc.Base64.parse(ciphertext);
        } else {
            ciphertext = cryptoJS.enc.Hex.parse(ciphertext);
        }
        let decrypted = cryptoJS.AES.decrypt({ ciphertext: ciphertext }, keyHex, option);
        return decrypted.toString(cryptoJS.enc.Utf8).toString();
    },

    /**
     * 获取真实key
     *
     * @param {*} key
     * @returns
     */
    getRealKey: function (key) {
        let keysha1 = crypto.createHash('sha1').update(key).digest('buffer');
        let realkey = crypto.createHash('sha1').update(keysha1).digest('hex').substring(0, 32);
        return Buffer.from(realkey, 'hex');
    },

    /**
     * 匹配java中SecureRandom SHA1PRNG模式AES加密
     *
     * @param {*} message
     * @param {*} key
     * @param {string} [iv='']
     */
    encryptSS: function (message, key, iv = '') {
        key = this.getRealKey(key);
        let crypted = '', cipher = crypto.createCipheriv('aes-128-ecb', key, '');
        crypted = cipher.update(message, 'utf8', 'binary');
        crypted += cipher.final('binary');
        crypted = Buffer.from(crypted, 'binary').toString('base64');
        return crypted;
    },

    /**
     * 匹配java中SecureRandom SHA1PRNG模式AES解密
     *
     * @param {*} ciphertext
     * @param {*} key
     * @param {string} [iv='']
     */
    decryptSS: function (ciphertext, key, iv = '') {
        key = this.getRealKey(key);
        let decipher = crypto.createDecipheriv('aes-128-ecb', key, '');
        const buf1 = Buffer.from(ciphertext, 'base64').toString('hex');
        let decrypted = decipher.update(buf1, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    },

    /**
     * hmac
     *
     * @param {*} content
     * @returns
     */
    hmac: function (content) {
        let shasum = crypto.createHash('sha1');
        shasum.update(content);
        return shasum.digest('base64');
    },
};