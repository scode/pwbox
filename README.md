DO NOT USE THIS. I AM SERIOUS.

Until the above notice is removed and replaced by actual
documentation, the only reason this code is public is to allow people
to review the crypto stuff.

Reviewers: See PWBox.java; it has a description of the format and the
tiny implementation.

## What is it?

An easy-to-use high-level abstraction (for the JVM) to accomplish a
single thing: password protected cryptographically sound storage of
small amounts of data (suitable for keychains and similar
use-cases). Code required to encrypt:

    PWBox box = new PWBox();
    byte[] data = box.encrypt("passphrase", "super secret data".getBytes("UTF-8"))

I am currently looking for feedback on whether or not the format and
implementation is cryptographically sound (see PWBox.java - the only
relelvant part).

## TODO

* Fix error propagation; don't result in PWBoxError when PWBoxException is appropriate (structural changes only).

## Requested feedback points

See PWBox.java.

* Is it cryptographically safe to encrypt known plain text for wrong passphrase detection?

## Feedback so far

* (rejected; updated feedback is that CBC degrades better) Maybe use other than CBC (CTR?) to decrease reliance on IV entropy
* And/or maybe use key stretching for the IV
* Consider HMAC:ing plaintext instead of iv+salt+crypted.


