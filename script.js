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
        } else if (this.value > 16)
        this.value = 16
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
    let inputValue = document.querySelector(".unencrypted-text").value;
    onSubmitDecode(inputValue)
}
function onSubmitDecode(input) {
    let inputValue = input
    const secretKey = document.querySelector(".secret-key").value
    console.log("inputValue: " + inputValue)
    console.log("Secret key:" + secretKey)

    if(secretKey.length != 16) return;

    let type = document.querySelector("#algorithm").value

    if(type == 1) document.querySelector(".result").innerHTML = ecbDecode(inputValue, secretKey)
    if(type == 2) {
        let initVector = document.querySelector(".init-vector").value;
        if(initVector.length != 16) return;

        document.querySelector(".result").innerHTML = cbcDecode(inputValue, secretKey, initVector)
    }
    if(type == 3) {
        let initVector = document.querySelector(".init-vector").value;
        let segment = document.querySelector(".segment").value;
        segment = parseInt(segment)
        inputValue = paddingText(inputValue, segment)
        if(initVector.length != 16) return;

        console.log(inputValue, secretKey, initVector, segment)

        document.querySelector(".result").innerHTML = cfbDecode(inputValue, secretKey, initVector, segment)
    }

    document.querySelector(".decode").style.display = "none"
}
function cbc(inputValue, secretKey, initVector) {
    let key = aesjs.utils.utf8.toBytes(secretKey);
    let iv = aesjs.utils.utf8.toBytes(initVector)
    let textBytes = aesjs.utils.utf8.toBytes(inputValue);

    let aesCbc = new aesjs.ModeOfOperation.cbc(key, iv);
    let encryptedBytes = aesCbc.encrypt(textBytes);
    let encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);

    return encryptedHex
}
function cbcDecode(encryptedHex, secretKey, initVector) {
    let key = aesjs.utils.utf8.toBytes(secretKey);
    let iv = aesjs.utils.utf8.toBytes(initVector)
    let encryptedBytes = aesjs.utils.hex.toBytes(encryptedHex);

    let aCbc = new aesjs.ModeOfOperation.cbc(key, iv);
    let decryptedBytes = aCbc.decrypt(encryptedBytes);
    let decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);

    return decryptedText
}
function ecb(inputValue, secretKey) {
    let key = aesjs.utils.utf8.toBytes(secretKey);
    let textBytes = aesjs.utils.utf8.toBytes(inputValue);
    
    let aesEcb = new aesjs.ModeOfOperation.ecb(key);
    let encryptedBytes = aesEcb.encrypt(textBytes);
    
    let encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
    return encryptedHex
}
function ecbDecode(encryptedHex, secretKey) {
    let encryptedBytes = aesjs.utils.hex.toBytes(encryptedHex);
    let key = aesjs.utils.utf8.toBytes(secretKey);

    let aesEcb = new aesjs.ModeOfOperation.ecb(key);
    let decryptedBytes = aesEcb.decrypt(encryptedBytes);
    let decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);

    return decryptedText
}
function cfb(inputValue, secretKey, initVector, segment) {
    let key = aesjs.utils.utf8.toBytes(secretKey);
    let iv = aesjs.utils.utf8.toBytes(initVector)
    let textBytes = aesjs.utils.utf8.toBytes(inputValue);

    let aesCfb = new aesjs.ModeOfOperation.cfb(key, iv, segment);
    let encryptedBytes = aesCfb.encrypt(textBytes);
    let encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);

    return encryptedHex
}
function cfbDecode(encryptedHex, secretKey, initVector, segment) {
    let key = aesjs.utils.utf8.toBytes(secretKey);
    let iv = aesjs.utils.utf8.toBytes(initVector)
    let encryptedBytes = aesjs.utils.hex.toBytes(encryptedHex);

    let aesCfb = new aesjs.ModeOfOperation.cfb(key, iv, segment);
    let decryptedBytes = aesCfb.decrypt(encryptedBytes);
    let decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);

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
    let file = input.files[0];
  
    let reader = new FileReader();
  
    reader.readAsText(file);
  
    reader.onload = function() {
      document.querySelector(".unencrypted-text").value = reader.result
    };
  
    reader.onerror = function() {
      console.log(reader.error);
    };
  
  }