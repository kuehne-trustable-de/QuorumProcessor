# QuorumProcessor
Verify given quorum to retrieve a predefined key 

The intention of this module is to protect a given key not just by one but a quorum (N out of M) of passwords. A typival use case is an organizations signing key: No single person should be able to sign documents (four-eyes-principle) but due to holidays, travel, maternty leave it is not feasable to depend on just two persons. So e.g. four persons are designated to be able to take part in the signing process but just two of them are required to be present (2 out of 4 quorum).

This module does the required calculations to derive personal keys from the user's password using PBKDF (https://en.wikipedia.org/wiki/PBKDF2), takes valid combinations of users, merges their derived password output and applies a key derivation again with the length of the initial key ('combined passwords key'). From this value and the inital key a 'key processing pattern' is calculated ( XOR of the key and password derivation steps) and stored per user combination.

The intial key isn't stored anywhere!

With any valid combination of use passwords the mentioned steps can be performed again to build the 'combined passwords key'. XORing this value with the 'key processing pattern' retrieves the initial key!
