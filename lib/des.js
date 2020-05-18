/**
 * @ author: richen
 * @ copyright: Copyright (c) - <richenlin(at)gmail.com>
 * @ license: MIT
 * @ version: 2020-05-18 16:31:41
 */

const crypto = require('crypto');
const iconv = require('iconv-lite');
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
        let encrypted = cryptoJS.DES.encrypt(message, keyHex, option);
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
        let decrypted = cryptoJS.DES.decrypt({ ciphertext: ciphertext }, keyHex, option);
        return decrypted.toString(cryptoJS.enc.Utf8).toString();
    },

    /**
     * 
     *
     * @param {*} text
     * @param {*} key
     * @param {*} iv
     * @param {string} [charset='utf8']
     * @returns
     */
    encryptPadZero: function (text, key, iv, charset = 'utf8') {
        key = key.length >= 8 ? key.slice(0, 8) : key.concat('0'.repeat(8 - key.length));
        const keyHex = Buffer.from(key);
        iv = iv ? Buffer.from(iv) : keyHex;
        const cipher = crypto.createCipheriv('des-cbc', keyHex, iv);
        text = iconv.encode(text, charset);
        let c = cipher.update(text, charset, 'base64');
        c += cipher.final('base64');
        return c;
    },

    /**
     * 
     *
     * @param {*} text
     * @param {*} key
     * @param {*} iv
     * @param {string} [charset='utf8']
     * @returns
     */
    decryptPadZero: function (text, key, iv, charset = 'utf8') {
        key = key.length >= 8 ? key.slice(0, 8) : key.concat('0'.repeat(8 - key.length));
        const keyHex = Buffer.from(key);
        iv = iv ? Buffer.from(iv) : keyHex;
        const cipher = crypto.createDecipheriv('des-cbc', keyHex, iv);
        let c = cipher.update(text, 'base64');
        c = iconv.decode(Buffer.from(c, 'binary'), charset);
        c += cipher.final('utf8');
        return c;
    },

    /**
     * 3DES加密
     *
     * @param {*} message
     * @param {*} key
     * @param {string} [iv='']
     * @param {boolean} [base64=true]
     * @param {string} [mod='CBC']
     * @param {string} [pad='Pkcs7']
     * @returns
     */
    encrypt3DES: function (message, key, iv = '', base64 = true, mod = 'CBC', pad = 'Pkcs7') {
        let keyHex = cryptoJS.enc.Utf8.parse(key);
        message = cryptoJS.enc.Utf8.parse(message);
        let ivHex = cryptoJS.enc.Utf8.parse(iv);
        let option = {
            mode: cryptoJS.mode[mod],
            padding: cryptoJS.pad[pad],
            iv: ivHex
        };
        let encrypted = cryptoJS.TripleDES.encrypt(message, keyHex, option);
        if (base64) {
            return encrypted.toString();
        } else {
            return encrypted.ciphertext.toString();
        }
    },

    /**
     * 3DES解密
     *
     * @param {*} ciphertext
     * @param {*} key
     * @param {string} [iv='']
     * @param {boolean} [base64=true]
     * @param {string} [mod='CBC']
     * @param {string} [pad='Pkcs7']
     * @returns
     */
    decrypt3DES: function (ciphertext, key, iv = '', base64 = true, mod = 'CBC', pad = 'Pkcs7') {
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
        let decrypted = cryptoJS.TripleDES.decrypt({ ciphertext: ciphertext }, keyHex, option);
        return decrypted.toString(cryptoJS.enc.Utf8).toString();
    }
};
