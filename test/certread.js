/*
 *  Copyright 2006-2017 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
 
'use strict';

/*================================================================*/
/*                            CertRead                            */
/*================================================================*/

// Unit testing suite for certificates

const Keys      = require('..').Keys;
const Base64Url = require('..').Base64Url;

function certReader (certInBase64URL) {
  var certData = new Keys.Certificate(Base64Url.decode(certInBase64URL));
  console.log('Certificate with SN=' + certData.getSerialNumber().toString() + '\n' +
              certData.getIssuer() + '\n' + certData.getSubject() + '\n' +
              certData.getPublicKey().getJwk());
}

var cert = "MIIDYzCCAkugAwIBAgIGAUOeUH5GMA0GCS\
qGSIb3DQEBCwUAMEMxEzARBgoJkiaJk_IsZAEZFgNvcmcxFjAUBgoJkiaJk_IsZAEZFgZ3ZWJwa2kxFDASBgNVBAMTC0RlbW8gU3ViIENBMB4XD\
TE0MDExNzAzNDgzMVoXDTM5MDExNzAzNDgzMVowQzEjMCEGCSqGSIb3DQEJARYUam9obi5kb2VAZXhhbXBsZS5jb20xHDAaBgNVBAMTE0tleUdl\
bjIgVHJ1c3RBbmNob3IwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCp61eV2UkUj8Fx5XYVA60l7SCXpISCmWdSPB_4Bbcw7Naa_x2\
fkyNsD179_dZPy3FbaQtNzqLIo6EPXaLYLWOGKjnpzp2MZXYKxNfwSccPjxhSyO40zaDY5CLP4QfzUVVvD4SETzQGqxSJXMXzUPzePBiUGG5qO\
k8ZxGv12lmGThfiTQJC2ENzguwjEELejPQrOAQIbG-_CYqUsYBt0alJBAkD89WQ7M9ssJx7kPuqdD32YMBNOPc0jAswrpsFB-1narT33L2wkpN\
UK9DnKsrvIu1nCp0u6PaMDeeHL1TR51vzpZvDUMUvL2kE-e0iqN_Due0sYIpU9Qh0wy952shjAgMBAAGjXTBbMAkGA1UdEwQCMAAwDgYDVR0PA\
QH_BAQDAgOIMB0GA1UdDgQWBBQeM7I_s8St2uxNVg4AUyrAOU4LhDAfBgNVHSMEGDAWgBRZXCF2vVvvaakHecbUVh7jS1yIVTANBgkqhkiG9w\
0BAQsFAAOCAQEAGhQMWLwV1sK1QQvXM_P0_VznWsXK8OGXZ7XSk2Ja9ajrECempZKBkDCQ63GiUSDaKjkXIkA9b9VKX6lMNytvOTHWIzh4cH49\
5cyhKtQ3UT1DNOakqrqkAlkWCjpOUerUNyYJRhgtd5xRssMUo4O1QB-PPniM01PStB6OrXWjc2OvSX6-EZwsZbPTOSSdUQK9jQ8V6MSC4rz5cQ\
2JHizYBx_6h-Kg8_xHKCLZc__mV9rHhByW0hP2HbBocjXg4uUCAOS8GVPnD_OoJ4rYtd_AyHRuedOnG-AwwLnKNGZSKsMDA89BE79FxkLf8cnS\
UnjPrTE9tPGAsi7a2CfSZz8VXg";

var cert_v1 = "MIIC5zCCAlACAQEwDQYJKoZIhvcNAQEFBQAwgbsxJDAiBgNVBAcTG1ZhbGlDZ\
XJ0IFZhbGlkYXRpb24gTmV0d29yazEXMBUGA1UEChMOVmFsaUNlcnQsIEluYy4xNTAzBgNVBAsTLFZhbGlDZXJ0IENsYXNzIDIg\
UG9saWN5IFZhbGlkYXRpb24gQXV0aG9yaXR5MSEwHwYDVQQDExhodHRwOi8vd3d3LnZhbGljZXJ0LmNvbS8xIDAeBgkqhkiG9w0\
BCQEWEWluZm9AdmFsaWNlcnQuY29tMB4XDTk5MDYyNjAwMTk1NFoXDTE5MDYyNjAwMTk1NFowgbsxJDAiBgNVBAcTG1ZhbGlDZX\
J0IFZhbGlkYXRpb24gTmV0d29yazEXMBUGA1UEChMOVmFsaUNlcnQsIEluYy4xNTAzBgNVBAsTLFZhbGlDZXJ0IENsYXNzIDIgU\
G9saWN5IFZhbGlkYXRpb24gQXV0aG9yaXR5MSEwHwYDVQQDExhodHRwOi8vd3d3LnZhbGljZXJ0LmNvbS8xIDAeBgkqhkiG9w0B\
CQEWEWluZm9AdmFsaWNlcnQuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDOOnHK5avIWZJV16vYdA757tn2VUdZZUc\
OBVXc65g2PFxTXdMwzzjsvUGJ7SVCCSRrCl6zfN1SLUzm1NZ9WlmpZdRJEy0kTRxQb7XBhVQ7_nHk01xC-YDgkRoKWzk2Z_M_VX\
wbP7RfZHM047QSv4dk-NoS_zcnwbNDu-97bi5p9wIDAQABMA0GCSqGSIb3DQEBBQUAA4GBADt_UG9vUJSZSWI4OB9L-KXIPqeCgf\
Yrx-jFzug6EILLGACOTb2oWH-heQC1u-mNr0HZDzTuIYEZoDJJKPTEjlbVUjP9UNV-mWwD5MlM_Mtsq2azSiGM5bUMMj4Qssxsod\
yamEwCW_POuZ6lcg5Ktz885hZo-L7tdEy8W9ViH0Pd";

var other_cert = "MIIHwzCCBaugAwIBAgIUfQuXudo6SVbkrJosltTgAtIQ2PowDQYJKoZIhvcNAQEFBQAweTELMAkGA1UEBh\
MCQk0xGTAXBgNVBAoTEFF1b1ZhZGlzIExpbWl0ZWQxJTAjBgNVBAsTHFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxKDAmBg\
NVBAMTH1F1b1ZhZGlzIE5vIFJlbGlhbmNlIFJvb3QgQ0EgRzIwHhcNMTIwNDEyMTI0NDI0WhcNMTUwNDEyMTI0NDI0WjBYMQswCQ\
YDVQQGEwJMSTEpMCcGA1UEChMgTGllY2h0ZW5zdGVpbmlzY2hlIExhbmRlc2JhbmsgQUcxHjAcBgNVBAMTFUxMQiBSb290IENBIH\
B1YmxpYyB2MjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL4Q3hTuqb49g3eNz6l8zW_IjdluqydipXKR7fhfh3j9CO\
OoyQ5MtdpHNGKl4bkojaJ6wrGM2wgyATAKZePToxH5weMlktpwvyc7Y1M5tIe5LPj3rzOB_X3V-0x4wlhuDgPRvG9Trd9TftW0RjX\
aAY8x_yi_tJyG6-cIK-uYT09Md7WxXIPOTN-axj7wsVLzMiwcG11WeyIsgqVPQwoQATS1r_m4oCnXVx7NTsbjn-au573HiXzU97aF\
xrPxg7o2acHYVLUuFcgpupibYGJIvAqJbCGkQB3MAyGkHnnVckyidFWjR1FKY9diLtC3gGTlu3lTnw3GjmVLLSDpNQBXEuAy8xsQe\
g7CvjLEe3Zv7nqmiHtRDUqbwSolPanY4WsdZDyIKDEf8pNC8sFph-e3JVu7yKQhl-OPVgRrXAWED5iNqha7bGrY9zEObkSSGTTaXt\
opRMObEWSVwYTt9wfpEBEWZAlPZnGVRRvqS_lZaRtvSqmtihnSAA51Yv9T7kPE82hhOQ3HvMgG4QMh9DpdkYl9ZEHOm87xcD_Wpa-\
qbeAVa6_zyRWst89pFyO2qM6I5a5lulYvdHrJDMT2_0oAPs1tgfpNlOlruA2A-uKXmaROzj0xg-Uvf5R8GBocj7q10wiD_AYdmdX8\
s2O2Ybbiqu_WGDgxJbQIZp9Q7WSis9CFAgMBAAGjggJiMIICXjASBgNVHRMBAf8ECDAGAQH_AgEBMHQGCCsGAQUFBwEBBGgwZjAqB\
ggrBgEFBQcwAYYeaHR0cDovL29jc3AucXVvdmFkaXNnbG9iYWwuY29tMDgGCCsGAQUFBzAChixodHRwOi8vdHJ1c3QucXVvdmFkaX\
NnbG9iYWwuY29tL3F2bnJjYWcyLmNydDBRBgNVHR4BAf8ERzBFoEMwD4ENQGp1cmF0cnVzdC5saTAJgQdAbGxiLmxpMAmBB0BsbGI\
uY2gwCYEHQGxsYi5hdDAPgQ1AYmFua2xpbnRoLmNoMIHIBgNVHSAEgcAwgb0wgboGDCsGAQQBvlgAA4hMADCBqTCBggYIKwYBBQUH\
AgIwdhp0QW55IHVzZSBvZiB0aGlzIENlcnRpZmljYXRlIGNvbnN0aXR1dGVzIGFjY2VwdGFuY2Ugb2YgdGhlIExMQiBDZXJ0aWZpY\
2F0ZSBQb2xpY3kgLyBDZXJ0aWZpY2F0aW9uIFByYWN0aWNlIFN0YXRlbWVudC4wIgYIKwYBBQUHAgEWFmh0dHBzOi8vd3d3LmxsYi\
5saS9wa2kwDgYDVR0PAQH_BAQDAgEGMCcGA1UdJQQgMB4GCCsGAQUFBwMCBggrBgEFBQcDBAYIKwYBBQUHAwkwHwYDVR0jBBgwFoA\
Ur9DvHfgJ-TQRH9RXVvngO6ZhxDcwOwYDVR0fBDQwMjAwoC6gLIYqaHR0cDovL2NybC5xdW92YWRpc2dsb2JhbC5jb20vcXZucmNh\
ZzIuY3JsMB0GA1UdDgQWBBQO3mVRfY1r_g3d36XUC89aDocfRzANBgkqhkiG9w0BAQUFAAOCAgEACHiNrQpM2Q4oMsfthke5iwlDj\
JMRNGK6u7NhFbFd6aC7cGfgnJfv6RMlmiVpmA9QXieeRtG2zMiDMAWq_7_mo3z006InAQ08cgyX7XYfBWMLDl1kR1LSYWvxDiLa1E\
U-I_Nv9lpEhCpKQgj69WPLVmjZoNRNV-PHOyspmf3yt4PHJt4tBvbwxBpz_B2d--EuwklIbqhq1s1px_D-bHIIEBbp1xDkDIJAUVN\
A0cfDdpYW2niz9QiGHessDsLgK1hW2xW3W2qzHVGSmuO1D8EmGhhK0iJjl088DLocmZr0iZWj6utyGEmZWeDfvLLiUFun1MOAYF9B\
hMQ0dJXKD1A9ubK6CKNEYYAAcqZTbybyFgMGutIQ3flWEW0FTj0MY8U81lK8av05j7u-J9CiFxx7aSXJilB7HqbkQjKMOeL9hdG2U\
AbtOfaWZpDPpizD58i-3J5B6mKACDCgkB0b1DmXhqf7A7fmoo-vwCyRx4AyWXxxJXZd7tuQUWOuUgnKZTbNViW5Cr8UMvmq934FYd\
Ka0MFb-IME_H9vgpejp2cD_3cc20QkfYeLqm5V7nKZeIm4jB7X2mbE-z0wFlbHiBJ7cgqi-XkW4lXqRsUISNtT5PyPfCjI5BlI5jb\
tb7u6f3Vq4nzkZQFETkW8URQYYGZ6A-0BVjMn2gNDmBmc32EAzXI";

var unsupported_ec_curve = "MIIEsTCCBDigAwIBAgIBATAKBggqhkjOPQQDAzBVMQswCQYDVQQGEwJERTENMAsGA1UECgwEY\
nVuZDEMMAoGA1UECwwDYnNpMQ0wCwYDVQQFEwQwMDAzMRowGAYDVQQDDBFURVNUIGNzY2EtZ2VybWFueTAeFw0xMjEwMzExNDI5NT\
VaFw0yNjA0MzAyMzU5NTlaMFUxCzAJBgNVBAYTAkRFMQ0wCwYDVQQKDARidW5kMQwwCgYDVQQLDANic2kxDTALBgNVBAUTBDAwMDM\
xGjAYBgNVBAMMEVRFU1QgY3NjYS1nZXJtYW55MIIBtTCCAU0GByqGSM49AgEwggFAAgEBMDwGByqGSM49AQECMQCMuR6CozhtKA9d\
b35Q5kHfFS9xCe1UVrQSsdoZf7cRI6zTpymQHRpxh0cAEzEH7FMwZAQwe8OCxj2MFQw8cggKzgWvoMK-oo5PsieHE5Fl77qR-Q-Kp\
YFKUDrU6wSox90izigmBDAEqMfdIs4oJos5tVQW8ER8L7d94Qfc0qYuiA6lPuti1Xy0OQKV28mUOreGlvpQTBEEYQQdHGTwaM9F_6\
KmOoG3wT9riEej537xT-Pbf8r-DL0Q6Ogm4DQ21kaq74ey4kfUrx6Kvh11IPnCpFyx646Vz9VSYrcLKf7sWGThnAVP-ZEpKA5GRiF\
3kYERQoIDQSY8UxUCMQCMuR6CozhtKA9db35Q5kHfFS9xCe1UVrMfFm5srAQlp886tq9rf8MQO4gyAukEZWUCAQEDYgAELH1Ru9xX\
CpDV3aA6tygQuxgfa9wl5f06x_C-WQoUJ3oCj4Q5rg7LcWvS68S39FUEZjyp1v_6WsDCIxwCifbOP7o7PIJtWmaBnXADAHRF8HBjQ\
csV6dLw74eGKiYm89QMo4IBmTCCAZUwHQYDVR0OBBYEFKONt8Db7PWpH8prPV6y8yi1pdwXMA4GA1UdDwEB_wQEAwIBBjArBgNVHR\
AEJDAigA8yMDEyMTAzMTE0Mjk1NVqBDzIwMTUxMDMxMjM1OTU5WjAWBgNVHSAEDzANMAsGCQQAfwAHAwEBATBRBgNVHREESjBIgRh\
jc2NhLWdlcm1hbnlAYnNpLmJ1bmQuZGWGHGh0dHBzOi8vd3d3LmJzaS5idW5kLmRlL2NzY2GkDjAMMQowCAYDVQQHDAFEMFEGA1Ud\
EgRKMEiBGGNzY2EtZ2VybWFueUBic2kuYnVuZC5kZYYcaHR0cHM6Ly93d3cuYnNpLmJ1bmQuZGUvY3NjYaQOMAwxCjAIBgNVBAcMA\
UQwEgYDVR0TAQH_BAgwBgEB_wIBADA1BgNVHR8ELjAsMCqgKKAmhiRodHRwOi8vd3d3LmJzaS5idW5kLmRlL3Rlc3RfY3NjYV9jcm\
wwDQYHZ4EIAQEGAQQCBQAwHwYDVR0jBBgwFoAUo423wNvs9akfyms9XrLzKLWl3BcwCgYIKoZIzj0EAwMDZwAwZAIwF4Iq16Y-_qV\
iymJrcsDea3tv41P-jlGPgvQckSCj450E0TRLWo8yzkevak7CcNatAjAKaPPpnPpxPWarhHfqX6Bdmvxmuzt286LIaBI4uhRgcHqR\
S5CH2TV6ZHBFrMQdPC0";

function scanCerts() {
  certReader(cert);
  certReader(cert_v1);
  certReader(other_cert);
  try {
    certReader(unsupported_ec_curve);
  } catch (err) {
    if (err.toString().indexOf('Malformed signature algorithm') < 0) {
      throw new TypeError('Cert error error');
    }
  } 
}

exports.scanCerts = scanCerts;
