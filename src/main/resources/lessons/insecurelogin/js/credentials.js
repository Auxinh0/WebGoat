function submit_secret_credentials() {
    // The login request is sent over the existing authenticated session; no username or
    // password is embedded in this script or transmitted in clear text.
    var xhttp = new XMLHttpRequest();
    xhttp.open('POST', 'InsecureLogin/login', true);
    xhttp.send();
}
