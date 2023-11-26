async function checkCredentials() {
    this.form = document.getElementById("login-form");
    const formData = new FormData(form);
    fetch('/authentication/init', {
        method: 'POST',
        body: formData
    })
    .then(response => initialCheckStatus(response))
    .then(credentialGetJson => ({
        publicKey: {
            ...credentialGetJson.publicKey,
            allowCredentials: credentialGetJson.publicKey.allowCredentials
                && credentialGetJson.publicKey.allowCredentials.map(credential => ({
                    ...credential,
                    id: base64urlToUint8array(credential.id),
                })),
            challenge: base64urlToUint8array(credentialGetJson.publicKey.challenge),
            extensions: credentialGetJson.publicKey.extensions,
        },
    }))
    .then(credentialGetOptions =>
        navigator.credentials.get(credentialGetOptions))
    .then(publicKeyCredential => {
        console.log('navigator.credentials.get response', publicKeyCredential);
        return {
            type: publicKeyCredential.type,
            id: publicKeyCredential.id,
            response: {
                authenticatorData: uint8arrayToBase64url(publicKeyCredential.response.authenticatorData),
                clientDataJSON: uint8arrayToBase64url(publicKeyCredential.response.clientDataJSON),
                signature: uint8arrayToBase64url(publicKeyCredential.response.signature),
                userHandle: publicKeyCredential.response.userHandle && uint8arrayToBase64url(publicKeyCredential.response.userHandle),
            },
            clientExtensionResults: publicKeyCredential.getClientExtensionResults(),
        }
    })
    .then((encodedResult) => {
        document.getElementById("credential").value = JSON.stringify(encodedResult);
        this.form.submit();
    })
    .catch(error => displayError(error))
}
