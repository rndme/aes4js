// aes4js, by dandavis. MIT applies.

function aesEnc(key, str) {
	var iv = window.crypto.getRandomValues(new Uint8Array(12)),
		encoder = new TextEncoder('utf-8'),
		encodedString = encoder.encode(str),
		bin = false;
	if(typeof str === "object") {
		encodedString = str; // arrayish
		bin = true;
	}

	return derive(key).then(function(key) {
		return window.crypto.subtle.encrypt({
			name: "AES-GCM",
			iv: iv,
			tagLength: 128,
		}, key, encodedString)
		  .then(function(encrypted) {
			return window.crypto.subtle.exportKey("jwk", key)
			  .then(function(c) {
				return new Promise(function(resolve, reject) {
					var fr = new FileReader;
					fr.onload = function() {
						resolve({
							encrypted: fr.result,
							iv: [].slice.call(iv),
							bin: bin
						});
					};
					fr.onerror = reject;
					fr.readAsDataURL(new Blob([encrypted]));
				}); // end fr promise wrapper
			}); // end export
		}); //end encrypt
	}) //end derive
	.
	catch(console.error);
} /* end aesEnc() */

	function aesDec(key, obj) {
	if(typeof obj === "string") obj = JSON.parse(obj);
	return derive(key).then(function(key) {
		return new Promise(function(resolve, reject) {
			var blob = dataUrlToBlob(obj.encrypted),
				fr = new FileReader();
			fr.onload = function() {
				window.crypto.subtle.decrypt({
					name: "AES-GCM",
					iv: new Uint8Array(obj.iv),
					tagLength: 128,
				}, key, fr.result)
				  .then(function(x){
					return obj.bin ? x : new TextDecoder("utf-8").decode(x);
				  })
				  .then(resolve)
				  .catch(function(y) {
					if(String(y) === "OperationError") y = "Opps!\r\n\r\nWrong Password, try again.";
					reject(y);
					//resolve(y);
				}); //end catch
			}; //end fr.onload()
			fr.readAsArrayBuffer(blob);
		}) //end promise wrapper
		.catch(function(e) {throw e;});
	}); //end derive
} /* end aesDec() */

function sha256(str) {
	return crypto.subtle.digest("SHA-256", new TextEncoder("utf-8").encode(str))
	  .then(function(x) {
		return Array.from(new Uint8Array(x)).map(function(b) {
			return('00' + b.toString(16)).slice(-2);
		}).join('');
	});
} /* end sha256() */

function derive(plainText) {
	if(plainText.length < 10) plainText = plainText.repeat(12 - plainText.length);
	return sha256("349d" + plainText + "9d3458694307" + plainText.length)
	  .then(function(salt) {
		var passphraseKey = new TextEncoder().encode(plainText),
			saltBuffer = new TextEncoder().encode(salt);
		return window.crypto.subtle.importKey('raw', passphraseKey, {
			name: 'PBKDF2'
		}, false, ['deriveBits', 'deriveKey'])
		  .then(function(key) {
			return window.crypto.subtle.deriveKey({
				"name": 'PBKDF2',
				"salt": saltBuffer,
				"iterations": 100000 + plainText.length,
				"hash": 'SHA-256'
			}, key, {
				"name": 'AES-GCM',
				"length": 256
			}, true, ["encrypt", "decrypt"]);
		});
	});
} /* end derive() */


function dataUrlToBlob(strUrl) {
	var parts = strUrl.split(/[:;,]/),
		type = parts[1],
		decoder = parts[2] == "base64" ? atob : decodeURIComponent,
		binData = decoder(parts.pop()),
		mx = binData.length,
		i = 0,
		uiArr = new Uint8Array(mx);

	for(i; i < mx; ++i) uiArr[i] = binData.charCodeAt(i);

	return new Blob([uiArr], {type: type});
} /* end dataUrlToBlob() */
