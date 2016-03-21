DO NOT USE THIS. I AM SERIOUS.

Until the above notice is removed and replaced by actual
documentation, the only reason this code is public is to allow people
to review the crypto stuff.

Reviewers: See PWBox.java; it has a description of the format and the
tiny implementation.

[![Travis Build Status](https://travis-ci.org/scode/pwbox.svg?branch=master)](https://travis-ci.org/scode/pwbox)

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

### Early feedback (from back in 2011)

* (rejected; updated feedback is that CBC degrades better) Maybe use other than CBC (CTR?) to decrease reliance on IV entropy
* And/or maybe use key stretching for the IV
 * Out of princple, not being a cryptographer, I do not want to implement key stretching myself even if it "seems" simple. Key stretching an arbitrary byte[] doesn't seem exposed by the Java API.
 * The reason to consider this is to be more resilient against poor IV entropy.
* Consider HMAC:ing plaintext instead of iv+salt+crypted.
 * Here is a good reason why not to do that: http://blog.thoughtcrime.org/the-cryptographic-doom-principle
 * That seems to apply to the "bad passphrase detection" algorithm too. However, since we are using a different IV for that, and the plaintext is by definition already known, it would seem harmless.

### Fedback from B.F. Dimmick (late 2015)

Feedback kindly provided my B.F. Dimmick (me@billdimmick.com)
follows. This feedback was based on
`05e2c8e173d479f30c4669dd357fa7e5b7209815`.

With a summary of "I took a look at it this weekend. It's
good. Solid. With a couple of tweaks, I'd use it.", these specific
suggestions were provided:

* Weakness: Where you can, prefer SHA256 to SHA1. Things have changed
  in the past 4 years and SHA1 is going to way of the dodo.
* Weakness: I prefer AES256 to AES128 but it's debatable if it's more
  secure unless you're trying to protect against nation-state
  attackers.
* Weakness: the password marker. While it's nice to have a way to fail
  fast if someone puts in the wrong password, but you may be handing
  over too much for that convenience - you give an attacker the IV,
  the ciphertext of the marker, and, since they know it's a PWBox
  because of the header information, they have the plaintext and the
  algorithms used to both encrypt the marker ciphertext and generate
  the key.
  * I'd note this weakness as fairly minor, though, since you're not
    re-using keys for both marker and actual ciphertext. There's a
    potential improvement that you could make, but it would involve
    re-thinking your format.
  * One thing you could do is instead of the password marker being a
    fixed string, you could skirt the edge of the Doom Principle and:
    * On encryption:
      * Generate a single random byte array which is the algorithm blocksize.
      * Calculate the SHA256 of this random byte data.
      * Generate a key from the password and a 32 byte salt.
      * Encrypt the random byte data with this key, using NoPadding.
      * Send the key salt, the iv, the ciphertext of the encrypted random byte data, and the plaintext hash.
    * On decryption:
      * Generate a key from the salt and the password.
      * Decrypt the ciphertext of the random byte data and the IV.
      * Generate the SHA256 of this plaintext, compare with the provided hash.
  * This should work around the problems Moxie outlines in his Doom
    writeup - no padding based attacks and you're dealing with a fixed
    amount of data, which means the operations always take the same
    amount of time.
  * The other thing you could do is switch to AES/GCM/NoPadding, which
    is probably what I would do: GCM provides authenticity as part of
    its evaluation, so you can jettison the whole extra set of data to
    verify the password. Instead, you'd just verify the password by
    trying to decrypt the ciphertext and failing on the first block.
* Nitpick: While you explicitly call out memory safety as not an
  issue, you could call, say, clearPassword() on the PBEKeySpec so it
  clears out the password from memory when you're done with it so it
  doesn't sit around in your vm waiting to be gc'd.
* Nitpick: the constants could be derived from places already in the
  core Java crypto primitives.
