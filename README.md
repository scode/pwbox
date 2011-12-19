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

    byte[] encrypted = box.encrypt(PWBox.Format.DEFAULT, "passphrase", "super secret data".getBytes("UTF-8"))

Core required to decrypt:

    byte[] plain = box.decrypt("passphrase", encrypted);

I am currently looking for feedback on whether or not the format and
implementation is cryptographically sound (see PWBox.java - the only
relelvant part).

## Requested feedback points

See PWBox.java.

* Is it cryptographically safe to encrypt known plain text for wrong passphrase detection?

## Feedback so far

* (rejected; updated feedback is that CBC degrades better) Maybe use other than CBC (CTR?) to decrease reliance on IV entropy
* And/or maybe use key stretching for the IV
** Out of princple, not being a cryptographer, I do not want to implement key stretching myself even if it "seems" simple. Key stretching an arbitrary byte[] doesn't seem exposed by the Java API.
** The reason to consider this is to be more resilient against poor IV entropy.
* Consider HMAC:ing plaintext instead of iv+salt+crypted.
** Here is a good reason why not to do that: http://blog.thoughtcrime.org/the-cryptographic-doom-principle
** That seems to apply to the "bad passphrase detection" algorithm too. However, since we are using a different IV for that, and the plaintext is by definition already known, it would seem harmless.



