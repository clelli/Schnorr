# Schnorr

In 1991, Claus Peter Schnorr published on the Journal of Cryptology a paper titled "Efficient Signature Generation by Smart Cards", where he presented his idea for a new efficient signature scheme.
It had many interesting features and benefits, but it has not been standardised yet due to a patent preventing widespread usage; researchers have recently proposed some possible approach, notably Pieter Wuille, Bitcoin Core developer.
We followed his proposal and present our implementation of Schnorr Signature using Elliptic Curve Cryptography, based on the assumption of the Discrete Logarithm Problem.

We start with an overview of the mathematic foundations of Elliptic Curve Cryptography and the assumptions on which it is based. Then we focus on Schnorr signature, starting from the analysis of the idea behind the algorithm, and presenting our python implementation, explained step by step. 

A key point in our dissertation is the analysis of the benefits of Schnorr signature algorithm, among which one of the most important is additivity. This one is not present in other signature schemes and leads to a relevant feature: multisignature, a protocol through which a group of signers sign a common message, is reduced to be indistinguishable from a single signature. We implement this multisignature scheme showing the several benefits of it.

Finally, we introduce Elliptic Curve Digital Signature Algorithm, currently used in Bitcoin, to appreciate how big an improvement Schnorr Signature Algorithm is compared to that.
