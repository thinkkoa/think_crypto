/**
 * @ author: richen
 * @ copyright: Copyright (c) - <richenlin(at)gmail.com>
 * @ license: MIT
 * @ version: 2020-05-18 16:38:34
 */
const NodeRSA = require('node-rsa');

/**
 * 格式化rsa的密钥，64位长度为一行
 *
 * @param {*} key
 * @returns
 */
const formatRSAKey = function (key) {
    let len = key.length, privateLen = 64;//private key 64 length one line
    let space = Math.floor(len / privateLen), flag = len % privateLen === 0 ? true : false, str = '';
    for (let i = 0; i < space; i++) {
        str = `${str}${key.substr(i * privateLen, privateLen)}\r\n`;
    }
    if (!flag) {
        str = `${str}${key.substring(space * privateLen)}\r\n`;
    }
    return str;
};

module.exports = {

    formatRSAKey: formatRSAKey,

    /**
     * 返回标准格式的rsa的私钥
     *
     * @param {*} key rsa的私钥
     * @param {boolean} [pkcs8=true] pkcs8模式(java端使用)
     * @returns
     */
    getRSAPrivateKey: function (key, pkcs8 = true) {
        if (pkcs8) {
            return `-----BEGIN PRIVATE KEY-----\r\n${formatRSAKey(key)}-----END PRIVATE KEY-----`;
        } else {
            return `-----BEGIN RSA PRIVATE KEY-----\r\n${formatRSAKey(key)}-----END RSA PRIVATE KEY-----`;
        }
    },

    /**
     * 返回标准格式的rsa的公钥
     * 
     * @param string key rsa的公钥
     * @returns
     */
    getRSAPublicKey: function (key) {
        return `-----BEGIN PUBLIC KEY-----\r\n${formatRSAKey(key)}-----END PUBLIC KEY-----`;
    },

    /**
     * 公钥加密
     *
     * @param {*} clearText 明文
     * @param {*} key 公钥
     * @returns
     */
    encryptPub: function (clearText, key) {
        let publicKey = new NodeRSA(key);
        publicKey.setOptions({ encryptionScheme: 'pkcs1' });
        let encryptData = publicKey.encrypt(clearText, 'base64');
        return encryptData;
    },

    /**
     * 私钥加密
     *
     * @param {*} clearText 明文
     * @param {*} key 私钥
     * @returns
     */
    encryptPri: function (clearText, key) {
        let privatekey = new NodeRSA(key);
        privatekey.setOptions({ encryptionScheme: 'pkcs1' });
        let encryptData = privatekey.encryptPrivate(clearText, 'base64');
        return encryptData;
    },

    /**
     * 私钥解密
     *
     * @param {*} encryptedData 密文
     * @param {*} key 私钥
     * @returns
     */
    decryptPri: function (encryptedData, key) {
        let privatekey = new NodeRSA(key);
        privatekey.setOptions({ encryptionScheme: 'pkcs1' });

        let decryptedData = privatekey.decrypt(encryptedData, 'utf8');
        return decryptedData;
    },

    /**
     * 公钥解密
     *
     * @param {*} encryptedData 密文
     * @param {*} key 公钥
     * @returns
     */
    decryptPub: function (encryptedData, key) {
        let publickey = new NodeRSA(key);
        publickey.setOptions({ encryptionScheme: 'pkcs1' });

        let decryptedData = publickey.decryptPublic(encryptedData, 'utf8');
        return decryptedData;
    }
}; 
