#!/usr/bin/env python
from M2Crypto import EVP
import time
from functools import wraps
def timethis(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.clock()
        r = func(*args, **kwargs)
        end = time.clock()
        execution_time = end - start
        return r, execution_time
    return wrapper
@timethis
def encrypt(alg, key, iv, data):
    cipher = EVP.Cipher(alg, key, iv, 1, padding=1)
    v = cipher.update(data)
    v = v + cipher.final()
    del cipher
    return v
@timethis
def decrypt(alg, key, iv,  data):
    cipher = EVP.Cipher(alg, key, iv, 0, padding=1)
    v = cipher.update(data)
    v = v + cipher.final()
    del cipher
    return v
def encrypt_file(alg, key, iv, infilename, outfilename):
    with open(infilename, 'rb') as infile:
        with open(outfilename, 'wb') as outfile:
            totaltime = 0
            while True:
                buff = infile.read()
                if not buff: break
                updatedbuff, partialtime = encrypt(alg, key, iv, buff)
                totaltime += partialtime
                outfile.write(updatedbuff)
            print 'total encryption time {}'.format(totaltime)
def decrypt_file(alg, key, iv, infilename, outfilename):
    with open(infilename, 'rb') as infile:
        with open(outfilename, 'wb') as outfile:
            totaltime = 0
            while True:
                buff = infile.read()
                if not buff: break
                updatedbuff, partialtime = decrypt(alg, key, iv, buff)
                totaltime += partialtime
                outfile.write(updatedbuff)
            print 'total decryption time {}'.format(totaltime)

key = '6c3ea0477630ce21a2ce334aa746c2cd'
largekey = key * 2
iv =  'c782dc4c098c66cbd9cd27d825682c81'
input_file = raw_input('Enter your inputfile:>')

ciphers = ['aes_128_cbc', 'bf_cbc', 'des_ede3_cbc', 'rc4']
ciphers_large_keys = ['aes_256_cbc']
for cipher in ciphers:
    encrypted_file = input_file + '-' + cipher
    print 'length of the key is:{} and length of iv is:{}'.format(len(key)*4,len(iv)*4)
    print 'encrypting filename {} its result will be placed in {}'.format(input_file, encrypted_file)
    decrypted_file_name = encrypted_file + '-decrypted'
    encrypt_file(cipher, key , iv, input_file, encrypted_file)
    decrypt_file(cipher, key, iv, encrypted_file, decrypted_file_name )
    
for cipher in ciphers_large_keys:
    encrypted_file = input_file + '-' + cipher
    print 'length of the key is:{} and length of iv is:{}'.format(len(largekey)*4,len(iv)*4)
    print 'encrypting filename {} its result will be placed in {}'.format(input_file, encrypted_file)
    encrypt_file(cipher, key , iv, input_file, encrypted_file)
    decrypted_file_name = encrypted_file + '-decrypted'
    decrypt_file(cipher, key, iv, encrypted_file, decrypted_file_name )


        