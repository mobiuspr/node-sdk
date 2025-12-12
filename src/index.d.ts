export declare class PrintServer {
    host: strng;
    port: number;
    /**
     * The base URL of the server, including the hostname, protocol, and port
     * @readonly
     */
    url: string;
    /**
     * A class representing a MobilityPrint server.
     * @param host The hostname or IP address of the server.
     * @param port The port the server is running on.
     */
    constructor(host: string, port?: number);
    /**
     * Gets the public key as raw JSON from the server.
     */
    getPublicKey(): Promise<{ modulus: string, exponent: string }>;
    /**
     * Gets the public key as a JSON web token (JWT)
     */
    getPublicKeyAsJWT(): Promise<JSONWebToken>;
    createEncryptionService(): Promise<RSAEncryptionService>;
    getPrinters():Promise<{ name: string, description: string, authMode: AuthMode }[]>;
    getPrinters():Promise<PrinterProperties[]>;
    getPrinterDetails(printer: string):Promise<PrinterProperties>
    print(printer: string, pdfFile: Blob, options?: PrintOptions): Promise<Response>;
}

interface PrintOptions {
    copies?: number,
    color?: boolean,
    duplex?: boolean|"long-edge"|"short-edge",
    size?: string,
    token?: string,
    username?: string,
    password?: string,
    /**
     * The name of the print job.
     */
    name?: string,
    /**
     * Extra FormData params to add.
     */
    extras?: string[][]
}

interface PrinterProperties {
    name: string,
    description: string,
    authMode: AuthMode,
    capabilities: {
        mediaSizes: MediaSize[],
        resolutions: Resolution[],
        color: ColorMode[],
        duplex: DuplexType[]
    }
}

type AuthMode = 'per-printer'|'per-user';
type ColorMode = 'STANDARD_COLOR'|'STANDARD_MONOCHROME';
type DuplexType = 'NO_DUPLEX'|'LONG_EDGE'|'SHORT_EDGE';

declare class RSAEncryptionService {
    constructor(modulus: string, exponent: string);
    encrypt(payload: string): string;
    decrypt(payload: string): string;
};

interface JSONWebToken {
    kty: "RSA",
    n: string,
    e: string,
    alg: 'RSA-OAEP-256',
    ext: true
};

interface MediaSize {
    name: string,
    customDisplayName: string,
    widthMicrons: number,
    heightMicrons: height,
    isDefault: boolean,
    IsContinuousFeed: boolean
}

interface Resolution {
    horizontalDpi: number,
    verticalDpi: number
}
