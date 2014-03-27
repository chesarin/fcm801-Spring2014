#!/usr/bin/env python
from os import path
input_file = raw_input('Enter your inputfile:>')
with open(input_file, 'rb') as infile:
    total_bytes = 0
    while True:
        buff = infile.read(1)
        if not buff: break
        total_bytes += 1
    print 'total bytes in input file {}'.format(total_bytes)

size = path.getsize(input_file)
print 'total number of bytes according to os.path is {}'.format(size)
with open(input_file, 'rb') as infile:
    data = infile.read()
    print 'size of data is {}'.format(len(data))
    print 'buffer has the following data {}'.format(data.encode('hex'))
print 'total number of bytes '
input_file2 = raw_input('Enter your second input file:>')
with open(input_file2, 'rb') as infile2:
    data2 = infile2.read()
    print 'size of data is {}'.format(len(data2))
    print 'buffer has the following data {}'.format(data2.encode('hex'))
data3 = data[:len(data)-len(data2)] + data2
print 'length of data3 {}'.format(len(data3))
print 'data3 has the following {}'.format(data3.encode('hex'))
with open('data3-file.data','wb') as outfile:
    outfile.write(data3)
