// https://github.com/extrabacon/google-oauth-jwt#creating-a-service-account-using-the-google-developers-console

var googleAuth = require('google-oauth-jwt');

googleAuth.authenticate({
  // use the email address of the service account, as seen in the API console
  email: process.env.SW_EMAIL, //'my-service-account@developer.gserviceaccount.com',
  // use the PEM file we generated from the downloaded key
  keyFile: process.env.SW_PEM, //'my-service-account-key.pem',
  // specify the scopes you wish to access
  scopes: ['https://www.googleapis.com/auth/analytics.readonly']
}, function (err, token) {
  console.log(token);
});