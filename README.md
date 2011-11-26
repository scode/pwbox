DO NOT USE THIS. I AM SERIOUS.

Until the above notice is removed and replaced by actual
documentation, the only reason this code is public is to allow people
to review the crypto stuff.

## What is it?

An easy-to-use high-level abstraction (for the JVM) to accomplish a
single thing: password protected cryptographically sound storage of
small amounts of data (suitable for keychains and similar
use-cases). Code required to encrypt:

    PWBox box = new PWBox();
    byte[] data = box.encrypt("passphrase", "super secret data".getBytes("UTF-8"))

I am currently looking for feedback on whether or not the format and
implementation is cryptographically sound.

## TODO

* Fix error propagation; don't result in PWBoxError when PWBoxException is appropriate (structural changes only).
* Consider that humans prefer to know whether they entered the wrong passphrase or the data was corrupt. I could
  have a dedicated field which is stipulated to be a pre-defined phrase encrypted, and use that to test for a
  bad passphrase. A tamperer would be able to trick the user into believing she has the wrong passphrase, but
  the main purpose is to allow the common case to be friendlier: not to report tampering whenever the user
  enters an incorrect passphrase.

## Requested feedback points

* Is it cryptographically safe to encrypt known plain text for wrong passphrase detection?

## Feedback so far

* Maybe use other than CBC (CTR?) to decrease reliance on IV entropy
* And/or maybe use key stretching for the IV
* Consider HMAC:ing plaintext instead of iv+salt+crypted.


