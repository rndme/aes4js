# aes4js
A high-level long-term-supported AES-GCM 256 encrypt/decrypt routine for JavaScript using native WebCrypto API

# purpose
A simple and safe promise-based text+binary encryption library for browsers. It uses plain text keys and plain-text-capable (JSON) ciphertext output for easy integration and storage. Keeping with best practices, the AES Encryption keys are derived from the plain text password using 1,000,000 rounds of PBKDF with SHA256 to prevent brute-forcing guessing.


# usage
There are only 2 methods:

* *encrypt(key, plain)* - encode _plain_ (string or arrayBuffer) to ciphertext data object using _key_
* *decrypt(key, cipher)* - decode _cipher_ object/JSON back into _plain_(string or arrayBuffer) using _key_

# live demo
See it in action on [a dead-simple encode/decode demo](https://pagedemos.com/qskd4gcdndtg/output/).

# example
```
aes4js.encrypt("123", "hello world") // encrypt with password 123
      .then(aes4js.decrypt.bind(this, "123")) // decrypt
      .then(alert) // display decrypted value
```

# requires
aes4js uses no outside code libraries, but does require several native browser APIs and Classes:

* atob()
* Array.from()
* Blob()
* FileReader()
* TextDecoder()
* TextEncoder()
* Uint8Array()
* crypto.getRandomValues()
* crypto.subtle.encrypt()
* crypto.subtle.decrypt()
* crypto.subtle.digest()
* crypto.subtle.exportKey()
* crypto.subtle.importKey()










