# sentinel-scan report — `deakin-coursework`

**Triage summary:** Highest score of any repo scanned, and genuinely the most real findings — multiple `.pem`/`key.pem`/`cert.pem` files committed across several university networking-course assignments (SIT209, Group project). These are near-certainly self-signed lab certificates generated for coursework exercises, not production credentials, and this repo is archived/retired coursework rather than live infrastructure — but they are real private key material sitting in a public repo, which is exactly the category of thing worth knowing about even in a low-stakes context. Not individually decrypted or content-verified beyond the earlier binary/size checks already applied by the scanner itself.

**Risk score:** 954

## Secrets
| Severity | File | Line | Kind |
|---|---|---|---|
| CRITICAL | `deakin-coursework/Group-4-Project/Ver-3.0/cert/key.pem` | 0 | pem_key_file |
| CRITICAL | `deakin-coursework/Group-4-Project/Ver-3.0/cert/key.pem` | 1 | private_key_header |
| CRITICAL | `deakin-coursework/Group-4-Project/Ver-3.0/cert/cert.pem` | 0 | pem_key_file |
| CRITICAL | `deakin-coursework/Group-4-Project/Ver-3.0/cert/csr.pem` | 0 | pem_key_file |
| CRITICAL | `deakin-coursework/SIT209/Topic 9/key.pem` | 0 | pem_key_file |
| CRITICAL | `deakin-coursework/SIT209/Topic 9/cert.pem` | 0 | pem_key_file |
| CRITICAL | `deakin-coursework/SIT209/Individual Project/certificates/key.pem` | 0 | pem_key_file |
| CRITICAL | `deakin-coursework/SIT209/Individual Project/certificates/cert.pem` | 0 | pem_key_file |
| CRITICAL | `deakin-coursework/Topic9/key.pem` | 0 | pem_key_file |
| CRITICAL | `deakin-coursework/Topic9/cert.pem` | 0 | pem_key_file |
| MEDIUM | `deakin-coursework/bootstrap/js/src/collapse.js` | 26 | generic_secret_assignment |
| MEDIUM | `deakin-coursework/bootstrap/js/src/offcanvas.js` | 29 | generic_secret_assignment |
| MEDIUM | `deakin-coursework/bootstrap/js/src/scrollspy.js` | 20 | generic_secret_assignment |
| MEDIUM | `deakin-coursework/bootstrap/js/src/dropdown.js` | 31 | generic_secret_assignment |
| MEDIUM | `deakin-coursework/bootstrap/js/src/button.js` | 19 | generic_secret_assignment |
| MEDIUM | `deakin-coursework/bootstrap/js/src/carousel.js` | 30 | generic_secret_assignment |
| MEDIUM | `deakin-coursework/bootstrap/js/src/modal.js` | 24 | generic_secret_assignment |
| MEDIUM | `deakin-coursework/bootstrap/site/assets/js/search.js` | 29 | generic_secret_assignment |
| MEDIUM | `deakin-coursework/SIT217-Task9.2HD/LedControlOnInternet_Esp8266.ino` | 4 | generic_secret_assignment |
| MEDIUM | `deakin-coursework/SIT209/Topic 8/weather3.js` | 3 | generic_secret_assignment |
| MEDIUM | `deakin-coursework/SIT209/Topic 8/weather2.js` | 3 | generic_secret_assignment |
| MEDIUM | `deakin-coursework/Exercise-Tracker/Fingerprint_Oled_Esp8266.ino` | 26 | generic_secret_assignment |
| MEDIUM | `deakin-coursework/Exercise-Tracker/Temp_Hum.ino` | 5 | generic_secret_assignment |
| MEDIUM | `deakin-coursework/Exercise-Tracker/Temp_Hum.ino` | 8 | generic_secret_assignment |
| MEDIUM | `deakin-coursework/Exercise-Tracker/Temp_Hum.ino` | 64 | generic_secret_assignment |
| MEDIUM | `deakin-coursework/SIT217-Task11.1P/CameraWebServer.ino` | 25 | generic_secret_assignment |
| MEDIUM | `deakin-coursework/Topic8/weather3.js` | 3 | generic_secret_assignment |
| MEDIUM | `deakin-coursework/Topic8/weather2.js` | 3 | generic_secret_assignment |
| LOW | `deakin-coursework/bootstrap/config.yml` | 77 | high_entropy_string |
| LOW | `deakin-coursework/bootstrap/config.yml` | 79 | high_entropy_string |
| LOW | `deakin-coursework/bootstrap/config.yml` | 81 | high_entropy_string |
| LOW | `deakin-coursework/bootstrap/config.yml` | 83 | high_entropy_string |
| LOW | `deakin-coursework/bootstrap/config.yml` | 85 | high_entropy_string |
| LOW | `deakin-coursework/bootstrap/site/content/docs/5.1/examples/dashboard-rtl/index.html` | 9 | high_entropy_string |
| LOW | `deakin-coursework/bootstrap/site/content/docs/5.1/examples/dashboard-rtl/index.html` | 11 | high_entropy_string |
| LOW | `deakin-coursework/bootstrap/site/content/docs/5.1/examples/masonry/index.html` | 6 | high_entropy_string |
| LOW | `deakin-coursework/bootstrap/site/content/docs/5.1/examples/dashboard/index.html` | 8 | high_entropy_string |
| LOW | `deakin-coursework/bootstrap/site/content/docs/5.1/examples/dashboard/index.html` | 10 | high_entropy_string |
| LOW | `deakin-coursework/Group-4-Project/Ver-2.0/contact.html` | 9 | high_entropy_string |
| LOW | `deakin-coursework/Group-4-Project/Ver-2.0/graphs.html` | 13 | high_entropy_string |
| LOW | `deakin-coursework/Group-4-Project/Ver-2.0/graphs.html` | 16 | high_entropy_string |
| LOW | `deakin-coursework/Group-4-Project/Ver-2.0/graphs.html` | 17 | high_entropy_string |
| LOW | `deakin-coursework/Group-4-Project/Ver-2.0/about_us.html` | 13 | high_entropy_string |
| LOW | `deakin-coursework/Group-4-Project/Ver-2.0/about_us.html` | 16 | high_entropy_string |
| LOW | `deakin-coursework/Group-4-Project/Ver-2.0/about_us.html` | 17 | high_entropy_string |
| LOW | `deakin-coursework/Group-4-Project/Ver-2.0/water_effect.html` | 13 | high_entropy_string |
| LOW | `deakin-coursework/Group-4-Project/Ver-2.0/water_effect.html` | 16 | high_entropy_string |
| LOW | `deakin-coursework/Group-4-Project/Ver-2.0/water_effect.html` | 17 | high_entropy_string |
| LOW | `deakin-coursework/Group-4-Project/Ver-1.0/home.html` | 13 | high_entropy_string |
| LOW | `deakin-coursework/Group-4-Project/Ver-1.0/home.html` | 16 | high_entropy_string |
| LOW | `deakin-coursework/Group-4-Project/Ver-1.0/home.html` | 17 | high_entropy_string |
| LOW | `deakin-coursework/Group-4-Project/Ver-1.0/contact.html` | 13 | high_entropy_string |
| LOW | `deakin-coursework/Group-4-Project/Ver-1.0/contact.html` | 16 | high_entropy_string |
| LOW | `deakin-coursework/Group-4-Project/Ver-1.0/contact.html` | 17 | high_entropy_string |
| LOW | `deakin-coursework/Group-4-Project/Ver-1.0/graphs.html` | 13 | high_entropy_string |
| LOW | `deakin-coursework/Group-4-Project/Ver-1.0/graphs.html` | 16 | high_entropy_string |
| LOW | `deakin-coursework/Group-4-Project/Ver-1.0/graphs.html` | 17 | high_entropy_string |
| LOW | `deakin-coursework/Group-4-Project/Ver-1.0/about_us.html` | 13 | high_entropy_string |
| LOW | `deakin-coursework/Group-4-Project/Ver-1.0/about_us.html` | 16 | high_entropy_string |
| LOW | `deakin-coursework/Group-4-Project/Ver-1.0/about_us.html` | 17 | high_entropy_string |
| LOW | `deakin-coursework/Topic3/AboveAndBeyond/web/public/home.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/Topic3/AboveAndBeyond/web/public/home.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/Topic3/AboveAndBeyond/web/public/driver.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/Topic3/AboveAndBeyond/web/public/driver.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/Topic3/AboveAndBeyond/web/public/404.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/Topic3/AboveAndBeyond/web/public/404.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/Topic3/AboveAndBeyond/web/public/login.html` | 21 | high_entropy_string |
| LOW | `deakin-coursework/Topic3/AboveAndBeyond/web/public/comingsoon.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/Topic3/AboveAndBeyond/web/public/comingsoon.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/Topic3/AboveAndBeyond/web/public/passenger.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/Topic3/AboveAndBeyond/web/public/passenger.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/Topic3/AboveAndBeyond/web/public/signup.html` | 17 | high_entropy_string |
| LOW | `deakin-coursework/Topic3/AboveAndBeyond/web/public/signup.html` | 21 | high_entropy_string |
| LOW | `deakin-coursework/Topic3/AboveAndBeyond/web/public/signup.html` | 24 | high_entropy_string |
| LOW | `deakin-coursework/Topic3/web/public/device-list.html` | 13 | high_entropy_string |
| LOW | `deakin-coursework/Topic3/web/public/device-list.html` | 17 | high_entropy_string |
| LOW | `deakin-coursework/Topic3/web/public/iot-applications.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/Topic3/web/public/iot-applications.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/Topic3/web/public/register-device.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/Topic3/web/public/register-device.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/Topic2/AboveAndBeyond/index.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/Topic2/AboveAndBeyond/index.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/Topic2/AboveAndBeyond/studyroom.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/Topic2/AboveAndBeyond/studyroom.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/Topic2/AboveAndBeyond/kitchen.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/Topic2/AboveAndBeyond/kitchen.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/Topic2/AboveAndBeyond/guestroom.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/Topic2/AboveAndBeyond/guestroom.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/Topic2/AboveAndBeyond/bedroom.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/Topic2/AboveAndBeyond/bedroom.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 3/web/public/device-list.html` | 13 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 3/web/public/device-list.html` | 17 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 3/web/public/iot-applications.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 3/web/public/iot-applications.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 3/web/public/register-device.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 3/web/public/register-device.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 3/Above-And-Beyond/web/public/home.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 3/Above-And-Beyond/web/public/home.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 3/Above-And-Beyond/web/public/driver.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 3/Above-And-Beyond/web/public/driver.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 3/Above-And-Beyond/web/public/404.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 3/Above-And-Beyond/web/public/404.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 3/Above-And-Beyond/web/public/login.html` | 21 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 3/Above-And-Beyond/web/public/comingsoon.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 3/Above-And-Beyond/web/public/comingsoon.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 3/Above-And-Beyond/web/public/passenger.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 3/Above-And-Beyond/web/public/passenger.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 3/Above-And-Beyond/web/public/signup.html` | 17 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 3/Above-And-Beyond/web/public/signup.html` | 21 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 3/Above-And-Beyond/web/public/signup.html` | 24 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 4/web/public/device-list.html` | 13 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 4/web/public/device-list.html` | 17 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 4/web/public/iot-applications.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 4/web/public/iot-applications.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 4/web/public/register-device.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 4/web/public/register-device.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 5/web/public/device-list.html` | 13 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 5/web/public/device-list.html` | 17 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 5/web/public/iot-applications.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 5/web/public/iot-applications.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 5/web/public/register-device.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 5/web/public/register-device.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 2/Above-And-Beyond/index.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 2/Above-And-Beyond/index.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 2/Above-And-Beyond/studyroom.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 2/Above-And-Beyond/studyroom.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 2/Above-And-Beyond/kitchen.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 2/Above-And-Beyond/kitchen.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 2/Above-And-Beyond/guestroom.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 2/Above-And-Beyond/guestroom.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 2/Above-And-Beyond/bedroom.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 2/Above-And-Beyond/bedroom.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 7/web/public/device-list.html` | 13 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 7/web/public/device-list.html` | 17 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 7/web/public/send-command.html` | 12 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 7/web/public/iot-applications.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 7/web/public/iot-applications.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 7/web/public/register-device.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 7/web/public/register-device.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 1/iot-applications.html` | 13 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 1/iot-applications.html` | 17 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 1/iot-applications.html` | 20 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 1/Above-And-Beyond/index.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 1/Above-And-Beyond/index.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 6/web/public/device-list.html` | 13 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 6/web/public/device-list.html` | 17 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 6/web/public/iot-applications.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 6/web/public/iot-applications.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 6/web/public/register-device.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Topic 6/web/public/register-device.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Individual Project/public/home.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Individual Project/public/home.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Individual Project/public/driver.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Individual Project/public/driver.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Individual Project/public/404.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Individual Project/public/404.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Individual Project/public/login.html` | 21 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Individual Project/public/comingsoon.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Individual Project/public/comingsoon.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Individual Project/public/passenger.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Individual Project/public/passenger.html` | 18 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Individual Project/public/signup.html` | 17 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Individual Project/public/signup.html` | 21 | high_entropy_string |
| LOW | `deakin-coursework/SIT209/Individual Project/public/signup.html` | 24 | high_entropy_string |
| LOW | `deakin-coursework/Topic1/iot-applications.html` | 6 | high_entropy_string |
| LOW | `deakin-coursework/Topic1/AboveAndBeyond/index.html` | 14 | high_entropy_string |
| LOW | `deakin-coursework/Topic1/AboveAndBeyond/index.html` | 18 | high_entropy_string |

## Vulnerable Dependencies
| Severity | Package | Version | Vuln ID |
|---|---|---|---|
| MEDIUM | @babel/core | 7.17.9 | GHSA-4x5r-pxfx-6jf8 |
| MEDIUM | ip | 1.1.5 | GHSA-2p57-rm9w-gvfp |
| MEDIUM | ip | 1.1.5 | GHSA-78xj-cgh5-2h22 |
| MEDIUM | postcss | 8.4.12 | GHSA-7fh5-64p2-3v2j |
| MEDIUM | postcss | 8.4.12 | GHSA-qx2v-qp2m-jg93 |
| MEDIUM | rollup | 2.70.1 | GHSA-gcx4-mw62-g8wm |
| MEDIUM | rollup | 2.70.1 | GHSA-mw96-cpmx-2vgc |
| MEDIUM | terser | 5.12.1 | GHSA-4wf5-vphf-c2xc |
| MEDIUM | vnu-jar | 21.10.12 | GHSA-fccg-7w3p-w66f |
| MEDIUM | axios | 0.26.1 | GHSA-3g43-6gmg-66jw |
| MEDIUM | axios | 0.26.1 | GHSA-3p68-rc4w-qgx5 |
| MEDIUM | axios | 0.26.1 | GHSA-43fc-jf86-j433 |
| MEDIUM | axios | 0.26.1 | GHSA-5c9x-8gcm-mpgx |
| MEDIUM | axios | 0.26.1 | GHSA-62hf-57xw-28j9 |
| MEDIUM | axios | 0.26.1 | GHSA-6chq-wfr3-2hj9 |
| MEDIUM | axios | 0.26.1 | GHSA-898c-q2cr-xwhg |
| MEDIUM | axios | 0.26.1 | GHSA-fvcv-3m26-pcqx |
| MEDIUM | axios | 0.26.1 | GHSA-hfxv-24rg-xrqf |
| MEDIUM | axios | 0.26.1 | GHSA-j5f8-grm9-p9fc |
| MEDIUM | axios | 0.26.1 | GHSA-jr5f-v2jv-69x6 |
| MEDIUM | axios | 0.26.1 | GHSA-m7pr-hjqh-92cm |
| MEDIUM | axios | 0.26.1 | GHSA-p92q-9vqr-4j8v |
| MEDIUM | axios | 0.26.1 | GHSA-pf86-5x62-jrwf |
| MEDIUM | axios | 0.26.1 | GHSA-pjwm-pj3p-43mv |
| MEDIUM | axios | 0.26.1 | GHSA-pmwg-cvhr-8vh7 |
| MEDIUM | axios | 0.26.1 | GHSA-vf2m-468p-8v99 |
| MEDIUM | axios | 0.26.1 | GHSA-w9j2-pvgh-6h63 |
| MEDIUM | axios | 0.26.1 | GHSA-wf5p-g6vw-rhxx |
| MEDIUM | axios | 0.26.1 | GHSA-xhjh-pmcv-23jw |
| MEDIUM | axios | 0.26.1 | GHSA-xx6v-rp6x-q39c |
| MEDIUM | body-parser | 1.19.2 | GHSA-qwcr-r2fm-qrc7 |
| MEDIUM | express | 4.17.3 | GHSA-qw6h-vgh9-j6wx |
| MEDIUM | express | 4.17.3 | GHSA-rv95-896h-c2vc |
| MEDIUM | jsonwebtoken | 8.5.1 | GHSA-8cf7-32gw-wr33 |
| MEDIUM | jsonwebtoken | 8.5.1 | GHSA-hjrf-2m68-5959 |
| MEDIUM | jsonwebtoken | 8.5.1 | GHSA-qwph-4952-7xr6 |
| MEDIUM | moment | 2.29.1 | GHSA-8hfj-j24r-96c4 |
| MEDIUM | moment | 2.29.1 | GHSA-wc69-rhjr-hc9g |
| MEDIUM | mongoose | 6.2.6 | GHSA-9m93-w8w6-76hh |
| MEDIUM | mongoose | 6.2.6 | GHSA-f825-f98c-gj3g |
| MEDIUM | mongoose | 6.2.6 | GHSA-h8hf-x3f4-xwgp |
| MEDIUM | mongoose | 6.2.6 | GHSA-m7xq-9374-9rvx |
| MEDIUM | mongoose | 6.2.6 | GHSA-vg7j-7cwx-8wgw |
| MEDIUM | mongoose | 6.2.6 | GHSA-wpg9-53fq-2r8h |
| MEDIUM | nodemailer | 6.7.3 | GHSA-268h-hp4c-crq3 |
| MEDIUM | nodemailer | 6.7.3 | GHSA-9h6g-pr28-7cqp |
| MEDIUM | nodemailer | 6.7.3 | GHSA-c7w3-x93f-qmm8 |
| MEDIUM | nodemailer | 6.7.3 | GHSA-mm7p-fcc7-pg87 |
| MEDIUM | nodemailer | 6.7.3 | GHSA-p6gq-j5cr-w38f |
| MEDIUM | nodemailer | 6.7.3 | GHSA-r7g4-qg5f-qqm2 |
| MEDIUM | nodemailer | 6.7.3 | GHSA-rcmh-qjqh-p98v |
| MEDIUM | nodemailer | 6.7.3 | GHSA-vvjj-xcjg-gr5g |
| MEDIUM | nodemailer | 6.7.3 | GHSA-wqvq-jvpq-h66f |
| MEDIUM | express | 4.17.3 | GHSA-qw6h-vgh9-j6wx |
| MEDIUM | express | 4.17.3 | GHSA-rv95-896h-c2vc |
| MEDIUM | express | 4.17.3 | GHSA-qw6h-vgh9-j6wx |
| MEDIUM | express | 4.17.3 | GHSA-rv95-896h-c2vc |
| MEDIUM | express | 4.17.3 | GHSA-qw6h-vgh9-j6wx |
| MEDIUM | express | 4.17.3 | GHSA-rv95-896h-c2vc |
| MEDIUM | express | 4.17.3 | GHSA-qw6h-vgh9-j6wx |
| MEDIUM | express | 4.17.3 | GHSA-rv95-896h-c2vc |
| MEDIUM | express | 4.17.3 | GHSA-qw6h-vgh9-j6wx |
| MEDIUM | express | 4.17.3 | GHSA-rv95-896h-c2vc |
| MEDIUM | body-parser | 1.20.0 | GHSA-qwcr-r2fm-qrc7 |
| MEDIUM | express | 4.17.3 | GHSA-qw6h-vgh9-j6wx |
| MEDIUM | express | 4.17.3 | GHSA-rv95-896h-c2vc |
| MEDIUM | express | 4.17.3 | GHSA-qw6h-vgh9-j6wx |
| MEDIUM | express | 4.17.3 | GHSA-rv95-896h-c2vc |
| MEDIUM | body-parser | 1.20.0 | GHSA-qwcr-r2fm-qrc7 |
| MEDIUM | express | 4.17.3 | GHSA-qw6h-vgh9-j6wx |
| MEDIUM | express | 4.17.3 | GHSA-rv95-896h-c2vc |
| MEDIUM | axios | 0.26.1 | GHSA-3g43-6gmg-66jw |
| MEDIUM | axios | 0.26.1 | GHSA-3p68-rc4w-qgx5 |
| MEDIUM | axios | 0.26.1 | GHSA-43fc-jf86-j433 |
| MEDIUM | axios | 0.26.1 | GHSA-5c9x-8gcm-mpgx |
| MEDIUM | axios | 0.26.1 | GHSA-62hf-57xw-28j9 |
| MEDIUM | axios | 0.26.1 | GHSA-6chq-wfr3-2hj9 |
| MEDIUM | axios | 0.26.1 | GHSA-898c-q2cr-xwhg |
| MEDIUM | axios | 0.26.1 | GHSA-fvcv-3m26-pcqx |
| MEDIUM | axios | 0.26.1 | GHSA-hfxv-24rg-xrqf |
| MEDIUM | axios | 0.26.1 | GHSA-j5f8-grm9-p9fc |
| MEDIUM | axios | 0.26.1 | GHSA-jr5f-v2jv-69x6 |
| MEDIUM | axios | 0.26.1 | GHSA-m7pr-hjqh-92cm |
| MEDIUM | axios | 0.26.1 | GHSA-p92q-9vqr-4j8v |
| MEDIUM | axios | 0.26.1 | GHSA-pf86-5x62-jrwf |
| MEDIUM | axios | 0.26.1 | GHSA-pjwm-pj3p-43mv |
| MEDIUM | axios | 0.26.1 | GHSA-pmwg-cvhr-8vh7 |
| MEDIUM | axios | 0.26.1 | GHSA-vf2m-468p-8v99 |
| MEDIUM | axios | 0.26.1 | GHSA-w9j2-pvgh-6h63 |
| MEDIUM | axios | 0.26.1 | GHSA-wf5p-g6vw-rhxx |
| MEDIUM | axios | 0.26.1 | GHSA-xhjh-pmcv-23jw |
| MEDIUM | axios | 0.26.1 | GHSA-xx6v-rp6x-q39c |
| MEDIUM | express | 4.17.3 | GHSA-qw6h-vgh9-j6wx |
| MEDIUM | express | 4.17.3 | GHSA-rv95-896h-c2vc |
| MEDIUM | body-parser | 1.20.0 | GHSA-qwcr-r2fm-qrc7 |
| MEDIUM | express | 4.17.3 | GHSA-qw6h-vgh9-j6wx |
| MEDIUM | express | 4.17.3 | GHSA-rv95-896h-c2vc |
| MEDIUM | axios | 0.26.1 | GHSA-3g43-6gmg-66jw |
| MEDIUM | axios | 0.26.1 | GHSA-3p68-rc4w-qgx5 |
| MEDIUM | axios | 0.26.1 | GHSA-43fc-jf86-j433 |
| MEDIUM | axios | 0.26.1 | GHSA-5c9x-8gcm-mpgx |
| MEDIUM | axios | 0.26.1 | GHSA-62hf-57xw-28j9 |
| MEDIUM | axios | 0.26.1 | GHSA-6chq-wfr3-2hj9 |
| MEDIUM | axios | 0.26.1 | GHSA-898c-q2cr-xwhg |
| MEDIUM | axios | 0.26.1 | GHSA-fvcv-3m26-pcqx |
| MEDIUM | axios | 0.26.1 | GHSA-hfxv-24rg-xrqf |
| MEDIUM | axios | 0.26.1 | GHSA-j5f8-grm9-p9fc |
| MEDIUM | axios | 0.26.1 | GHSA-jr5f-v2jv-69x6 |
| MEDIUM | axios | 0.26.1 | GHSA-m7pr-hjqh-92cm |
| MEDIUM | axios | 0.26.1 | GHSA-p92q-9vqr-4j8v |
| MEDIUM | axios | 0.26.1 | GHSA-pf86-5x62-jrwf |
| MEDIUM | axios | 0.26.1 | GHSA-pjwm-pj3p-43mv |
| MEDIUM | axios | 0.26.1 | GHSA-pmwg-cvhr-8vh7 |
| MEDIUM | axios | 0.26.1 | GHSA-vf2m-468p-8v99 |
| MEDIUM | axios | 0.26.1 | GHSA-w9j2-pvgh-6h63 |
| MEDIUM | axios | 0.26.1 | GHSA-wf5p-g6vw-rhxx |
| MEDIUM | axios | 0.26.1 | GHSA-xhjh-pmcv-23jw |
| MEDIUM | axios | 0.26.1 | GHSA-xx6v-rp6x-q39c |
| MEDIUM | body-parser | 1.20.0 | GHSA-qwcr-r2fm-qrc7 |
| MEDIUM | express | 4.17.3 | GHSA-qw6h-vgh9-j6wx |
| MEDIUM | express | 4.17.3 | GHSA-rv95-896h-c2vc |
| MEDIUM | express | 4.17.3 | GHSA-qw6h-vgh9-j6wx |
| MEDIUM | express | 4.17.3 | GHSA-rv95-896h-c2vc |
| MEDIUM | express | 4.17.3 | GHSA-qw6h-vgh9-j6wx |
| MEDIUM | express | 4.17.3 | GHSA-rv95-896h-c2vc |
| MEDIUM | request | 2.88.2 | GHSA-p8p7-x288-28g6 |
| MEDIUM | express | 4.17.3 | GHSA-qw6h-vgh9-j6wx |
| MEDIUM | express | 4.17.3 | GHSA-rv95-896h-c2vc |
| MEDIUM | body-parser | 1.20.0 | GHSA-qwcr-r2fm-qrc7 |
| MEDIUM | express | 4.17.3 | GHSA-qw6h-vgh9-j6wx |
| MEDIUM | express | 4.17.3 | GHSA-rv95-896h-c2vc |
| MEDIUM | axios | 0.26.1 | GHSA-3g43-6gmg-66jw |
| MEDIUM | axios | 0.26.1 | GHSA-3p68-rc4w-qgx5 |
| MEDIUM | axios | 0.26.1 | GHSA-43fc-jf86-j433 |
| MEDIUM | axios | 0.26.1 | GHSA-5c9x-8gcm-mpgx |
| MEDIUM | axios | 0.26.1 | GHSA-62hf-57xw-28j9 |
| MEDIUM | axios | 0.26.1 | GHSA-6chq-wfr3-2hj9 |
| MEDIUM | axios | 0.26.1 | GHSA-898c-q2cr-xwhg |
| MEDIUM | axios | 0.26.1 | GHSA-fvcv-3m26-pcqx |
| MEDIUM | axios | 0.26.1 | GHSA-hfxv-24rg-xrqf |
| MEDIUM | axios | 0.26.1 | GHSA-j5f8-grm9-p9fc |
| MEDIUM | axios | 0.26.1 | GHSA-jr5f-v2jv-69x6 |
| MEDIUM | axios | 0.26.1 | GHSA-m7pr-hjqh-92cm |
| MEDIUM | axios | 0.26.1 | GHSA-p92q-9vqr-4j8v |
| MEDIUM | axios | 0.26.1 | GHSA-pf86-5x62-jrwf |
| MEDIUM | axios | 0.26.1 | GHSA-pjwm-pj3p-43mv |
| MEDIUM | axios | 0.26.1 | GHSA-pmwg-cvhr-8vh7 |
| MEDIUM | axios | 0.26.1 | GHSA-vf2m-468p-8v99 |
| MEDIUM | axios | 0.26.1 | GHSA-w9j2-pvgh-6h63 |
| MEDIUM | axios | 0.26.1 | GHSA-wf5p-g6vw-rhxx |
| MEDIUM | axios | 0.26.1 | GHSA-xhjh-pmcv-23jw |
| MEDIUM | axios | 0.26.1 | GHSA-xx6v-rp6x-q39c |
| MEDIUM | express | 4.17.3 | GHSA-qw6h-vgh9-j6wx |
| MEDIUM | express | 4.17.3 | GHSA-rv95-896h-c2vc |
| MEDIUM | body-parser | 1.20.0 | GHSA-qwcr-r2fm-qrc7 |
| MEDIUM | express | 4.17.3 | GHSA-qw6h-vgh9-j6wx |
| MEDIUM | express | 4.17.3 | GHSA-rv95-896h-c2vc |
| MEDIUM | axios | 0.26.1 | GHSA-3g43-6gmg-66jw |
| MEDIUM | axios | 0.26.1 | GHSA-3p68-rc4w-qgx5 |
| MEDIUM | axios | 0.26.1 | GHSA-43fc-jf86-j433 |
| MEDIUM | axios | 0.26.1 | GHSA-5c9x-8gcm-mpgx |
| MEDIUM | axios | 0.26.1 | GHSA-62hf-57xw-28j9 |
| MEDIUM | axios | 0.26.1 | GHSA-6chq-wfr3-2hj9 |
| MEDIUM | axios | 0.26.1 | GHSA-898c-q2cr-xwhg |
| MEDIUM | axios | 0.26.1 | GHSA-fvcv-3m26-pcqx |
| MEDIUM | axios | 0.26.1 | GHSA-hfxv-24rg-xrqf |
| MEDIUM | axios | 0.26.1 | GHSA-j5f8-grm9-p9fc |
| MEDIUM | axios | 0.26.1 | GHSA-jr5f-v2jv-69x6 |
| MEDIUM | axios | 0.26.1 | GHSA-m7pr-hjqh-92cm |
| MEDIUM | axios | 0.26.1 | GHSA-p92q-9vqr-4j8v |
| MEDIUM | axios | 0.26.1 | GHSA-pf86-5x62-jrwf |
| MEDIUM | axios | 0.26.1 | GHSA-pjwm-pj3p-43mv |
| MEDIUM | axios | 0.26.1 | GHSA-pmwg-cvhr-8vh7 |
| MEDIUM | axios | 0.26.1 | GHSA-vf2m-468p-8v99 |
| MEDIUM | axios | 0.26.1 | GHSA-w9j2-pvgh-6h63 |
| MEDIUM | axios | 0.26.1 | GHSA-wf5p-g6vw-rhxx |
| MEDIUM | axios | 0.26.1 | GHSA-xhjh-pmcv-23jw |
| MEDIUM | axios | 0.26.1 | GHSA-xx6v-rp6x-q39c |
| MEDIUM | node-sass | 5.0.0 | GHSA-r8f7-9pfq-mjmv |
| MEDIUM | postcss | 8.2.10 | GHSA-566m-qj78-rww5 |
| MEDIUM | postcss | 8.2.10 | GHSA-7fh5-64p2-3v2j |
| MEDIUM | postcss | 8.2.10 | GHSA-qx2v-qp2m-jg93 |
| MEDIUM | express | 4.17.3 | GHSA-qw6h-vgh9-j6wx |
| MEDIUM | express | 4.17.3 | GHSA-rv95-896h-c2vc |
| MEDIUM | express | 4.17.3 | GHSA-qw6h-vgh9-j6wx |
| MEDIUM | express | 4.17.3 | GHSA-rv95-896h-c2vc |
| MEDIUM | request | 2.88.2 | GHSA-p8p7-x288-28g6 |

## Secrets in Git History
| Severity | Commit | File | Kind |
|---|---|---|---|
| CRITICAL | `eca4518fa2be` | `Group-4-Project/Ver-3.0/cert/key.pem` | private_key_header |
| MEDIUM | `eca4518fa2be` | `Exercise-Tracker/Fingerprint_Oled_Esp8266.ino` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `Exercise-Tracker/Temp_Hum.ino` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `Exercise-Tracker/Temp_Hum.ino` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `Exercise-Tracker/Temp_Hum.ino` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `SIT209/Topic 8/weather2.js	` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `SIT209/Topic 8/weather3.js	` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `SIT217-Task11.1P/CameraWebServer.ino` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `SIT217-Task9.2HD/LedControlOnInternet_Esp8266.ino` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `Topic8/weather2.js` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `Topic8/weather3.js` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `bootstrap/dist/js/bootstrap.bundle.js` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `bootstrap/dist/js/bootstrap.esm.js` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `bootstrap/dist/js/bootstrap.esm.min.js` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `bootstrap/dist/js/bootstrap.js` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `bootstrap/js/dist/button.js` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `bootstrap/js/dist/carousel.js` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `bootstrap/js/dist/collapse.js` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `bootstrap/js/dist/dropdown.js` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `bootstrap/js/dist/modal.js` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `bootstrap/js/dist/offcanvas.js` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `bootstrap/js/dist/scrollspy.js` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `bootstrap/js/dist/tab.js` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `bootstrap/js/src/button.js` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `bootstrap/js/src/carousel.js` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `bootstrap/js/src/collapse.js` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `bootstrap/js/src/dropdown.js` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `bootstrap/js/src/modal.js` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `bootstrap/js/src/offcanvas.js` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `bootstrap/js/src/scrollspy.js` | generic_secret_assignment |
| MEDIUM | `eca4518fa2be` | `bootstrap/site/assets/js/search.js` | generic_secret_assignment |
