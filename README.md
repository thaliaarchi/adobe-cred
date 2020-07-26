# Adobe credential dump analysis

This is parser and attempted cracker for the 2013 Adobe credential leak.

Adobe encrypted the passwords with DES or Triple DES in block mode, so
any identical 8-character plaintext sequences are also the same when
encrypted. Additionally, password hints are included in plaintext,
making common passwords easy to guess. These weaknesses were highlighted
by [XKCD 1286: Encryptic](https://xkcd.com/1286/)
([Explain](https://www.explainxkcd.com/wiki/index.php?title=1286:_Encryptic))
in which the passwords were turned into a crossword puzzle.

This project assumes the passwords were encrypted with DES (56-bit key)
which is much weaker than Triple DES (168-bit key). It includes a hard
fork of `crypto/des` that unrolls the key generation permutations for
improved performance and uses `uint64` rather than `[]byte` in its API.

This project shall only be used for research purposes.
