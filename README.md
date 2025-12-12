# Mobius-SDK
Mobius-SDK is a work-in-progress Node.JS library that allows you to print documents directly to MobilityPrint print servers. It currently only supports `per-printer`-authenticated printers, but we hope to expand it soon.

## Installation
We will be putting this on NPM once it's out of the alpha stage. You'll be able to install it using the `devel` version.

## Usage
We're working on some docs, as it's technically still in the alpha stage. Please be patient.

Update: TypeScript documentation (in `src/index.d.ts`) has now been added, VSCode should autocomplete unless its being stoopid

## How does this work?
Mobius-SDK was reverse-engineered from the MobilityPrint extension for Chromebooks. Unlike the extension, Mobius-SDK only supports HTTP scanning, not mDNS/DNS-SD. In thoses cases, you can also scan on mDNS yourself, and then pass the hostnames or IP addresses directly to a `PrintServer` object.

Mobius-SDK uses the same third-party libraries that the MobilityPrint extension uses to maintain compatibility. They've been included with Mobius-SDK. The third-party libraries used are [JSEncrypt](https://github.com/travist/jsencrypt), [jsbn](https://github.com/andyperlitch/jsbn), and [AES-JS](https://github.com/ricmoo/aes-js).

Mobius-SDK is designed to be compatible and have feature parity with the MobilityPrint extension for Chromebooks.

## FAQ
### Is it open-source?
Yes. This library is licensed under the GNU GPLv3 License. You're allowed to use this library, even for commercial purposes.

### What platforms does it support?
Mobius-SDK works on Windows, MacOS, Linux, UNIX, BSD (including FreeBSD/OpenBSD), and AIX, and requires Node.JS v20 or newer.

### Is there a web version for Mobius-SDK?
I'm currently planning on making a web version after I finish Mobius-SDK and Mobius.

### Can I use this as a driver?
I've actually been working on a CUPS backend using Mobius-SDK for Linux, UNIX, MacOS. Once I make Mobius-WebSDK, I'll also make drivers for Windows 96 (the website).
