DO NOT USE THIS. I AM SERIOUS.

Until the above notice is removed and replaced by actual
documentation, the only reason this code is public is to allow people
to review the crypto stuff.

= TODO =

* Fix error propagation; don't result in PWBoxError when PWBoxException is appropriate (structural changes only).
* Consider that humans prefer to know whether they entered the wrong passphrase or the data was corrupt. Probably adjust format
  slightly to allow for this, but I'm worried about what the implications are if I do it by simply stiuplating that
  a part of the file is a certain pre-defined string encrypted.

