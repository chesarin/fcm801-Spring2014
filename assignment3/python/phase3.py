#!/usr/bin/env python
from M2Crypto import EVP
def encrypt(alg, key, data):
    cipher = EVP.Cipher(alg, key, '12345678', 1, padding=1)
    v = cipher.update(data)
    v = v + cipher.final()
    del cipher
    return v
def decrypt(alg, key,  data):
    cipher = EVP.Cipher(alg, key, '12345678', 0, padding=1)
    v = cipher.update(data)
    v = v + cipher.final()
    del cipher
    return v
def encrypt_file(alg, key, infilename, outfilename):
    with open(infilename, 'rb') as infile:
        with open(outfilename, 'wb') as outfile:
            while True:
                buff = infile.read()
                if not buff: break
                updatedbuff = encrypt(alg, key, buff)
                outfile.write(updatedbuff)
def decrypt_file(alg, key, infilename, outfilename):
    with open(infilename, 'rb') as infile:
        with open(outfilename, 'wb') as outfile:
            while True:
                buff = infile.read()
                if not buff: break
                updatedbuff = decrypt(alg, key, buff)
                outfile.write(updatedbuff)
                
key = 'c0a497761b175379ed63397cc980546559faa84ca9cbeede773117c31508b6ac'
cipher = 'aes_256_ecb'
input_file = raw_input('Enter your inputfile:>')
encrypted_file = input_file + '-' + cipher
encrypt_file(cipher, key ,input_file, encrypted_file)
print 'Now we are going to decrypt the file {}'.format(encrypted_file)
decrypted_file = encrypted_file + '-decrypted-' + cipher
decrypt_file(cipher, key, encrypted_file, decrypted_file)
print 'We are done with encryption and decryption of file {}'.format(input_file)




