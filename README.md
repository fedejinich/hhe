# HHE (Hybrid Homomorphic Encryption) SDK

This SDK provides a set of building blocks to implement hybrid homomorphic encryption schemes using PASTA as symmetric cipher and BFV for homomorphic encryption, to achieve both security and efficiency.

## Introduction

The primary objective of this project is to provide a solution for hybrid homomorphic encryption for various use cases.

## Supported Use Cases

Currently, the SDK supports only a single-user scenario. In the future, it will support additional use cases.

### Single-User

In this case we will consider two participants, Abe (sender) and Bart (operator):

1. Abe generates public and secret keys for homomorphic encryption.
2. Abe encrypts some data using a symmetric cipher and encrypts the symmetric secret key using homomorphic encryption,
3. Abe sends the encrypted data to Bart along with the encrypted symmetric secret key.
4. Later, Bart homomorphically evaluates the decryption of the symmetric ciphertext to convert it to an homomorphically operable ciphertext
5. Bart then uses the homomorphically operable ciphertext to perform the required computation on the encrypted data.
6. Finally, Bart sends the encrypted result of the computation back to Abe,
7. Abe decrypts it to obtain the final output

## Dependencies

To use this SDK, you will need to have the following dependencies installed:

- [pasta-go](https://github.com/fedejinich/pasta-go)
- [latigo](https://github.com/tuneinsight/lattigo)
