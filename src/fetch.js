const http = require('http');
const { isTypedArray } = require('util/types');

/**
 * Makes a fetch request
 * @param {string|URL} url 
 * @param {{
 *  method?: "GET"|"POST"|"HEAD"|"OPTIONS"|"PUT"|"DELETE",
 *  body?: string|ArrayBuffer|Uint8Array|Buffer|any,
 *  headers?: {
 *      [key: string]: string
 *  }
 * }} options 
 * @returns {Promise<FetchResult>}
 */
module.exports = function fetch(url, options={}) {
    return new Promise((resolve, reject) => {
        if(!options.method) options.method = 'GET';
        if(!options.headers) options.headers = {};
        if(Object.keys(options).includes('body') && !['POST','PUT'].includes(options.method))
            return reject(new TypeError("A body can only be specified with POST or PUT requests"));
        if(!['GET','POST','HEAD','OPTIONS','PUT','DELETE'].includes(options.method))
            return reject(new TypeError("Invalid method"));
        if(url instanceof URL) 
            url = url.href;
        const request = http.request(url, {
            headers: options.headers,
            method: options.method
        }, function (res) {
            if(options.debug) console.log('[fetch] Response received');
            const chunks = [];
            res.on('data', chunk => chunks.push(chunk));
            res.on('end', () => {
                if(options.debug) console.log('[fetch] Response ended');
                resolve(new FetchResult(res.statusCode, res.statusMessage, Buffer.concat(chunks)))
            });
        });
        request.on('error', error => reject(error));
        if(Object.keys(options).includes('body'))
            request.write(
                (options.body instanceof String || options.body instanceof ArrayBuffer ||
                    options.body instanceof Buffer || isTypedArray(options.body)) ? options.body :
                    JSON.stringify(options.body),
                function (error) {
                    if(error)
                        reject(error);
                    request.end();
                }
            );
        else request.end();
    });
}

class FetchResult {
    #statusCode = 0;
    #statusText = 0;
    #buffer;
    /**
     * 
     * @param {number} statusCode 
     * @param {string} statusText 
     * @param {Buffer} buffer 
     */
    constructor(statusCode, statusText, buffer) {
        this.#statusCode = statusCode;
        this.#statusText = statusText;
        this.#buffer = buffer;
    }
    get status() {
        return this.#statusCode;
    }
    get statusText() {
        return this.#statusText;
    }
    get ok() {
        const range = Math.floor(this.#statusCode/100)*100;
        return range === 200 || range === 300 || range === 100;
    }
    async text (enc='utf-8') {
        return this.#buffer.toString(enc);
    }
    async json(enc='utf-8') {
        return JSON.parse(await this.text(enc));
    }
    async buffer() {
        return this.#buffer;
    }
    async arraybuffer() {
        return new ArrayBuffer(this.#buffer);
    }
    async uint8array() {
        return new Uint8Array(this.#buffer);
    }
};
