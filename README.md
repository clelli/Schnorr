# Schnorr

In 1991 on the Journal of Cryptology, Claus Peter Schnorr published a paper titled "Efficient Signature Generation by Smart Cards", where he presented his idea for a new efficient signature scheme.
Even if it has so many interesting features and benefits, it has not been standardised yet; however, it is possible to find some ideas proposed by some researchers, but not a script on which the schemes are implemented. We chose to follow the guide line designed by Pieter Wuille, a very important Bitcoin Core developer.
We present our implementation of Schnorr Signature applied to Elliptic Curve Cryptography, which is based on the assumption of the Discrete Logarithm Problem. 

We start with an important overview of the mathematics necessary in order to deeply understand Elliptic Curve Cryptography and the assumptions on which it is based. Then we focus on Schnorr Signature, starting from the analysis of the idea behind the algorithm, and going on presenting our implementation and explaining it step by step. 

A key point in our dissertation is the analysis of the benefits of SSA, among which the most important is: additivity. This one is not present in any other signature, and leads to a very important and innovative feature: multisignature, a protocol through which a group of signers can generate a single joint signature on a common message.
We illustrate also our implementation of this scheme and the several benefits brought by this feature.

Finally, we introduce Elliptic Curve Digital Signature Algorithm, currently used in Bitcoin, showing how much improvements Schnorr Signature Algorithm carries with itself.
