let numLimit = 94


function initOptions() {
    const optionsElement = document.querySelector(".options")
    optionsElement.innerHTML = "";

    const type = document.querySelector("#algorithm").value;
    
    if(type == 2 || type == 3) {
        optionsElement.innerHTML += `
        <p>Įveskite inicijavimo vektorių (turi turėti 16 simbolių):</p>
        <p class="init-vector-warning warning"></p>
        <input oninput="initVectorLengthWarning()" type="text" class="init-vector">
        `;
    }
    if(type == 3) {
        optionsElement.innerHTML += `
        <p>Įveskite segmentų dydį:</p>
        <input type="number" class="segment">
        `;
    }

    document.querySelector(".segment").oninput = function () {
        if (this.value < 1) {
            this.value = 1
        }
        document.querySelector(".segment").innerHTML = this.value;
    }
}
function lengthWarning(inputValue, warningElement, target) {
    const count = inputValue.length;

    if(count < target) {
        warningElement.innerHTML = `Trūksta ${16 - count} simbolių.`;
    }
    else if(count > target) {
        warningElement.innerHTML = `${count - 16} simbolių per daug.`;
    }
    else {
        warningElement.innerHTML = "";
    }
}
function secretKeyLengthWarning() {
    const inputValue = document.querySelector(".secret-key").value;
    const warningElement = document.querySelector(".secret-key-warning");
    lengthWarning(inputValue, warningElement, 16);
}
function initVectorLengthWarning () {
    const inputValue = document.querySelector(".init-vector").value;
    const warningElement = document.querySelector(".init-vector-warning");
    lengthWarning(inputValue, warningElement, 16);
}
// function inputTextLengthWarning () {
//     const inputValue = document.querySelector(".init-vector").value;
//     const warningElement = document.querySelector(".init-vector-warning");



//     lengthWarning(inputValue, warningElement);
// }
function onSubmit() {
    console.log(document.querySelector(".unencrypted-text").value)
    let inputValue = document.querySelector(".unencrypted-text").value
    const secretKey = document.querySelector(".secret-key").value

    if(secretKey.length != 16) return;

    const type = document.querySelector("#algorithm").value

    if(type == 2) {
        inputValue = paddingText(inputValue, 16)
        let initVector = document.querySelector(".init-vector").value;
        if(initVector.length != 16) return;

        document.querySelector(".result").innerHTML = cbc(inputValue, secretKey, initVector)
    }
    if(type == 1) {
        inputValue = paddingText(inputValue, 16)
        document.querySelector(".result").innerHTML = ecb(inputValue, secretKey)
    }
    if(type == 3) {
        let initVector = document.querySelector(".init-vector").value;
        let segment = document.querySelector(".segment").value;
        segment = parseInt(segment)
        inputValue = paddingText(inputValue, segment)
        if(initVector.length != 16) return;

        document.querySelector(".result").innerHTML = cfb(inputValue, secretKey, initVector, segment)
    }

    document.querySelector(".decode").style.display = "block"
}
function resultDecode() {
    let inputValue = document.querySelector(".result").innerHTML;
    onSubmitDecode(inputValue)
}
function inputDecode() {
    let inputValue = document.querySelector(".unencrypted-text").innerHTML;
    onSubmitDecode(inputValue)
}
function onSubmitDecode(input) {
    let inputValue = input
    const secretKey = document.querySelector(".secret-key").value

    if(secretKey.length != 16) return;

    let type = document.querySelector("#algorithm").value

    if(type == 1) document.querySelector(".result").innerHTML = ecbDecode(inputValue, secretKey)
    if(type == 2) {
        let initVector = document.querySelector(".init-vector").value;
        if(initVector.length != 16) return;

        document.querySelector(".result").innerHTML = cbcDecode(document.querySelector(".result").innerHTML, secretKey, initVector)
    }
    if(type == 3) {
        let initVector = document.querySelector(".init-vector").value;
        let segment = document.querySelector(".segment").value;
        segment = parseInt(segment)
        inputValue = paddingText(inputValue, segment)
        if(initVector.length != 16) return;

        document.querySelector(".result").innerHTML = cfbDecode(inputValue, secretKey, initVector, segment)
    }

    document.querySelector(".decode").style.display = "none"
}
function cbc(inputValue, secretKey, initVector) {
    // An example 128-bit key
    let key = aesjs.utils.utf8.toBytes(secretKey);
    console.log(key)
    console.log(secretKey)
    //let key = [ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 ];
    
    // The initialization vector (must be 16 bytes)
    let iv = aesjs.utils.utf8.toBytes(initVector)
    console.log(iv)
    console.log(initVector)
    //let iv = [ 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,35, 36 ];
    
    // Convert text to bytes (text must be a multiple of 16 bytes)
    let textBytes = aesjs.utils.utf8.toBytes(inputValue);
    let aesCbc = new aesjs.ModeOfOperation.cbc(key, iv);
    let encryptedBytes = aesCbc.encrypt(textBytes);
    
    // To print or store the binary data, you may convert it to hex
    let encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
    return encryptedHex
}
function cbcDecode(encryptedHex, secretKey, initVector) {
    let key = aesjs.utils.utf8.toBytes(secretKey);
    let iv = aesjs.utils.utf8.toBytes(initVector)

    var encryptedBytes = aesjs.utils.hex.toBytes(encryptedHex);

    var aCbc = new aesjs.ModeOfOperation.cbc(key, iv);
    var decryptedBytes = aCbc.decrypt(encryptedBytes);
    
    var decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
    return decryptedText
}
function ecb(inputValue, secretKey) {
    // An example 128-bit key
    let key = aesjs.utils.utf8.toBytes(secretKey);
    
    // Convert text to bytes
    var textBytes = aesjs.utils.utf8.toBytes(inputValue);
    
    var aesEcb = new aesjs.ModeOfOperation.ecb(key);
    var encryptedBytes = aesEcb.encrypt(textBytes);
    
    // To print or store the binary data, you may convert it to hex
    var encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
    return encryptedHex
    // "a7d93b35368519fac347498dec18b458"
    
}
function ecbDecode(encryptedHex, secretKey) {
    // When ready to decrypt the hex string, convert it back to bytes
    var encryptedBytes = aesjs.utils.hex.toBytes(encryptedHex);
    let key = aesjs.utils.utf8.toBytes(secretKey);

    // Since electronic codebook does not store state, we can
    // reuse the same instance.
    //var aesEcb = new aesjs.ModeOfOperation.ecb(key);
    var aesEcb = new aesjs.ModeOfOperation.ecb(key);
    var decryptedBytes = aesEcb.decrypt(encryptedBytes);
    
    // Convert our bytes back into text
    var decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
    return decryptedText
}
function cfb(inputValue, secretKey, initVector, segment) {
    console.log(inputValue)
        // An example 128-bit key
    var key = aesjs.utils.utf8.toBytes(secretKey);
    
    // The initialization vector (must be 16 bytes)
    var iv = aesjs.utils.utf8.toBytes(initVector)
    
    // Convert text to bytes (must be a multiple of the segment size you choose below)
    var textBytes = aesjs.utils.utf8.toBytes(inputValue);
    
    // The segment size is optional, and defaults to 1
    var aesCfb = new aesjs.ModeOfOperation.cfb(key, iv, segment);
    var encryptedBytes = aesCfb.encrypt(textBytes);
    
    // To print or store the binary data, you may convert it to hex
    var encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
    return encryptedHex
}
function cfbDecode(encryptedHex, secretKey, initVector, segment) {
    var key = aesjs.utils.utf8.toBytes(secretKey);
    
    // The initialization vector (must be 16 bytes)
    var iv = aesjs.utils.utf8.toBytes(initVector)

    // When ready to decrypt the hex string, convert it back to bytes
    var encryptedBytes = aesjs.utils.hex.toBytes(encryptedHex);

    // The cipher feedback mode of operation maintains internal state,
    // so to decrypt a new instance must be instantiated.
    var aesCfb = new aesjs.ModeOfOperation.cfb(key, iv, segment);
    var decryptedBytes = aesCfb.decrypt(encryptedBytes);
    
    // Convert our bytes back into text
    var decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
    return decryptedText
}
function paddingText(input, multiple) {
    let inputValue = input;
    let counter = multiple;
    while(true) {
        if(inputValue.length == counter) break;
        if(inputValue.length < multiple-1 || (inputValue.length < counter && inputValue.length > counter / 2)) {
            const length = counter - inputValue.length;
            for(let i = 0; i < length; i++) {
                inputValue += String.fromCharCode(0);
            }
            break;
        }
        counter *= 2;
    }
    return inputValue
}
function downloadFile() {
    const link = document.createElement("a");
    const content = document.querySelector(".result").innerHTML;
    const file = new Blob([content], { type: 'text/plain' });
    link.href = URL.createObjectURL(file);
    link.download = "sample.txt";
    link.click();
    URL.revokeObjectURL(link.href);
}
function readFile(input) {
    console.log("hello")
    let file = input.files[0];
  
    let reader = new FileReader();
  
    reader.readAsText(file);
  
    reader.onload = function() {
      console.log(reader.result);
      document.querySelector(".unencrypted-text").value = reader.result
    };
  
    reader.onerror = function() {
      console.log(reader.error);
    };
  
  }