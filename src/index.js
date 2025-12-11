const fetch = require('./fetch.js');
const JSEncrypt = require('./jsencrypt.js');
const { BigInteger } = require('./jsbn.js');
const utils = require('./utils.js');

const SVC_URL = 'rpc.pc-printer-discovery';
const PORT = 9163;
const FETCH_LIMIT = 20;
const TRY_LOCALHOST = true;

const hextob64 = hex =>
    Buffer.from(hex, 'hex').toString('base64')
        .toString("base64").replace(/\+/g, "-")
        .replace(/\//g, "_").replace(/=+$/, "");

class RSAEncryptionService {
    jse = new JSEncrypt();
    constructor(modulus, exponent) {
        if(modulus.modulus&&modulus.exponent&&!exponent)
            exponent = modulus.exponent, modulus = modulus.modulus;
        const key = this.jse.getKey();
        const n = new BigInteger(modulus, 16);
        const e = parseInt(exponent, 16);
        key.parsePropertiesFrom({ n, e });
    }
    encrypt(payload) {
        return this.jse.getKey().encrypt(payload);
    }
    decrypt(text) {
        return this.jse.getKey().decrypt(text);
    }
}

class PrintServer {
    host = '';
    port = PORT;
    constructor(host, port) {
        this.host = host;
        this.port = port || PORT;
    }
    get url() {
        return 'http://' + this.host + ':' + this.port;
    }
    async getPublicKey() {
        const tok = await (
            await fetch(this.url + '/public-key')
        ).json();
        if(typeof tok != 'object') throw new TypeError('Server returned invalid public key');
        if(typeof tok.modulus != 'string') throw new TypeError('Server returned invalid public key');
        if(typeof tok.exponent != 'string') throw new TypeError('Server returned invalid public key');
        return tok;
    }
    async getPublicKeyAsJWT() {
        const key = await this.getPublicKey();
        return {
            kty: 'RSA',
            n: hextob64(key.modulus),
            e: hextob64(key.exponent),
            alg: 'RSA-OAEP-256',
            ext: true
        };
    }
    async createEncryptionService() {
        return new RSAEncryptionService(await this.getPublicKey())
    }
    async getPrinters(showCapabilities) {
        const response = await fetch(this.url + '/printers' + (
            showCapabilities?'':'?ignoreCapabilities=true'
        ));
        const data = await response.json();
        if(!Array.isArray(data)) throw new TypeError("Server did not return an array");
        return data;
    }
    async hasPrinter(name) {
        return (await fetch(this.url + '/printers/' + name)).ok;
    }
    /**
     * 
     * @param {string} printer 
     * @param {Blob} blob 
     * @param {{
     *  name?: string,
     *  copies?: number,
     *  duplex?: boolean|"long-edge"|"short-edge",
     *  color?: boolean,
     *  size?: string,
     *  token?: string,
     *  extras?: string[][]
     * }} options 
     * @returns 
     */
    async print(printer, blob, options={}) {
        const details = await this.getPrinterDetails(printer);
        if(options.duplex === true || options.duplex === 'long-edge') options.duplex = 'LONG_EDGE';
        else if(options.duplex === 'short-edge') options.duplex = 'SHORT_EDGE';
        else options.duplex = 'NO_DUPLEX';
        const size = details.capabilities.mediaSizes.filter(s => s.name === options.size)[0];
        if(!size) throw new ReferenceError(`Size ${options.size} is not available on printer`);
        delete options.size;
        options.width = size.widthMicrons;
        options.height = size.heightMicrons;
        if(details.authMode === 'per-printer') {
            return await this.print_perPrinterAuth(printer, blob, options);
        } else {
            throw new Error(`Auth type ${details.authMode} is not yet supported`);
        }
    }
    /**
     * 
     * @param {string} printer 
     * @param {Blob} blob 
     * @param {{
     * name?: string
     * copies?: number,
     * width?: number,
     * height?: number,
     * duplex?: string,
     * color?: string,
     * username?: string,
     * password?: string,
     * token?: string,
     * extras?: string[][]
     * }} options 
     */
    async print_perPrinterAuth(printer, blob, options={}) {
        const encsvc = await this.createEncryptionService(); 
        if(!options.name) options.name = 'Print Job';
        if(!options.extras) options.extras = [];
        options.name = String(options.name);
        if(options.name.length > 500) options.name = options.name.slice(0, 500);
        if(!options.copies) options.copies = 1;
        if(options.copies < 1) options.copies = 1;
        if(isNaN(options.copies)) options.copies = 1;
        options.copies = Math.floor(options.copies);
        const fd = new FormData();
        fd.append('printerName', this.url + '/printers/' + printer);
        fd.append('copies', options.copies.toString());
        fd.append('duplex', options.duplex);
        fd.append('color', options.color);
        fd.append('mediaWidthMicrons', options.width);
        fd.append('mediaHeightMicrons', options.height);
        options.extras.forEach(e => fd.append(e[0], e[1]));
        const headers = {
            'Content-Type': "multipart/form-data; boundary=----WebKitFormBoundarylA4G3yq20NYmXx9n",
            'Origin': 'chrome-extension://ndakideadaglgpbblmppfonobpdgggin',
            'Client-Type': 'ChromeAppExt-1.4.3',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36'
        };
        if(options.token) headers['authorization'] = `Bearer ${options.token}`;
        const enc = await utils.encryptDocument(blob);
        fd.append('iv', enc.iv);
        fd.append('key', encsvc.encrypt(enc.key));
        fd.append('printDocument', enc.blob);
        fd.append('documentName', encsvc.encrypt(options.name));
        fd.append('authOption', '');
        fd.append('authOption', '');
        fd.append('remember', 'false');
        fd.append('credentials', encsvc.encrypt(options.username + ':' + options.password));
        const fdr = await utils.formDataToBuffer(fd);
        headers['Content-Length'] = fdr.byteLength;
        return await fetch(this.url + '/printers/' + printer + '/jobs', {
            method: 'POST',
            headers,
            body: fdr,
        });
    }
    async getPrinterDetails(name) {
        const r = await fetch(this.url + '/printers/' + name);
        if(r.status === 404) throw new ReferenceError("Specified printer does not exist");
        if(r.status === 401 || r.status === 403) throw new Error("Unauthorized");
        if(Math.floor(r.status/100) === 4) throw new Error("Client error, retry request");
        if(Math.floor(r.status/100) === 5) throw new Error("Unknown server error");
        if(Math.floor(r.status/100) === 3) throw new TypeErrorError("Unexpected redirect");
        if(!r.ok) throw new Error("Unknown error");
        return await r.json();
    }
};

/** @returns {Promise<{ name: string, description: string, authMode: "per-printer" }[]>} */
async function findPrinters_old(debug) {
    const printers = [];
    for(let i = 0; i <= FETCH_LIMIT+(TRY_LOCALHOST?1:0); i++) {
        const host = i>FETCH_LIMIT?'localhost':SVC_URL+(i<1?'':`${i}`) + ':' + PORT;
        try {
            const response = await fetch('http://' + host + '/printers?ignoreCapabilities=true');
            console.log(await response.text());
            printers.push(...await response.json());
            debug && console.log('got a response from ' + host);
        } catch (error) {
            debug && console.warn('couldn\'t get a response from ' + host + ':');
            void(error);
        }
    };
    return printers;
};

module.exports = { findPrinters: findPrinters_old, PrintServer }
