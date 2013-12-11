### php-sodium

+ PHP extension using [libsodium](https://github.com/jedisct1/libsodium.git). libsodium uses the [NACL: Networking and Cryptography library](http://nacl.cr.yp.to/).
+ PHP 5.3 +

#### Build on Linux

1. Install php5, git
2. Install php5-dev
3. Install [libsodium](https://github.com/jedisct1/libsodium.git)
4. Install php-sodium
```bash
git clone https://github.com/alethia7/php-sodium.git
phpize && ./configure && make && sudo make install ; make test
```

5. Enable sodium extenion in PHP. Add "extension = sodium.so" to php.ini. On Debian systems execute:
```bash
# As root
echo "extension = sodium.so" > /etc/php5/mods-available/sodium.ini
php5enmod sodium 
```

#### Build on Windows

Confirmed.

#### Documentation

See: [php-sodium API](docs/README.md)

#### Example

1. Alice sends an encrypted message to Bob. 
2. Alice and Bob create and exchange public keys.
3. Bob decrypts Alice's message.

```php
<?php
/*
 * php-sodium uses namespace sodium.
 * crypto() and nonce() objects contain the methods.
 * Methods will throw a crypto_exception on error.
 */
try {
    
    $c = new \sodium\crypto();
    // Create a secret key
    $alice_secret = $c->keypair();
    // Create public key to give to Bob
    $alice_public = new \sodium\public_key();
    // Load binary key from alice_secret (pbin)
    // false: expect a binary key; i.e. not a hex key 
    $alice_public->load($alice_secret->pbin, false);
    // Alice's friend Bob 
    $bob_secret = $c->keypair();
    // Create public key from bob_secret (pbin)
    $bob_public = new \sodium\public_key();
    $bob_public->load($bob_secret->pbin, false);
    // Alice's message to Bob
    $message  = "Now Jesus did many other signs in the presence of the disciples,";
    $message .= "which are not written in this book; but these are written so that";
    $message .= "you may believe that Jesus is the Christ, the Son of God, and that";
    $message .= "by believing you may have life in his name. (ESV, John 20:30:31)";
    // Create a nonce
    $nonce = new \sodium\nonce();
    // Every call to $nonce->next() generates a new nonce! Important for crypto_box
    // Use Bob's public key to send to Bob 
    $encrypted_text = $c->box($message, $nonce->next(), $bob_public, $alice_secret);
    // Bob receives Alice's public key, the $encrypted_text, and a 24 byte nonce 
    // string ($nonce->nbin) from Alice 
    $nonce_from_alice = $nonce->nbin;
    // Bob creates a nonce object.
    $bob_nonce = new \sodium\nonce();
    // nonce::set_nonce() will throw a crypto_exception if the new nonce < the last nonce.
    $message_decrypted = $c->box_open(
    
          $encrypted_text
        , $bob_nonce->set_nonce($nonce_from_alice, true)
        , $alice_public
        , $bob_secret
    );
    
    echo "Message successfully encrypted/decrypted\n";
}
catch(\sodium\crypto_exception $e) {
    
    syslog(LOG_ERR, sprintf("Error: (%s) %s\n%s\n"
    
        , $e->getCode()
        , $e->getMessage()
        , $e->getTraceAsString()
    ));
}
?>
```
