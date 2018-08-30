# Trusted Timestamps

Packaging of https://d-mueller.de/blog/dealing-with-trusted-timestamps-in-php-rfc-3161/

## Install

Install with composer

```bash
composer require ludeus/trusted-timestamp ~1.0
```

## Usage

### Timestamp a file (certified)  
NOTE: $tsa_url = url of your Timestamp Authority
you can find free TSA ex: https://gist.github.com/Manouchehri/fd754e402d98430243455713efada710

```php
$requestFile = TrustedTimestamps::createRequestfile($sha1);
$signature = TrustedTimestamps::signRequestfile($requestFile, $tsa_url);
file_put_contents($signature_filename, base64_decode($signature));
```

### Get timestamp (datetime) from a signature file

```php
$content64 = base64_encode(file_get_contents($signature_filename));
$timestamp = TrustedTimestamps::getTimestampFromAnswer($content64);
```