#!/usr/bin/env python
import gmpy as _g
import time
from datetime import datetime
import random
def calculate_seconds():
    initial_date_str = "04-10-2014 9:00"
    initial_date_time = datetime.strptime(initial_date_str, '%m-%d-%Y %H:%M')
    initial_time = time.mktime(initial_date_time.timetuple())
    final_date_str = "04-10-2014 9:30"
    final_date_time = datetime.strptime(final_date_str, '%m-%d-%Y %H:%M')
    final_time = time.mktime(final_date_time.timetuple())
    return initial_time,final_time

def calculate_process_id():
    initial_process_id = 1800
    final_process_id = 2000
def create_random_value(seed):
    random.seed(seed)
    r = _g.mpz(random.getrandbits(1024))
    return r
    # r = _g.rand
    # r('init',1024)
    # r('seed',seed)
    # r('next')
    # result = r('save',1024)
    # print 'size of random number is {} in base 2'.format(_g.numdigits(result,2))
    # return result
def calculate_seed(n):
    initial_time,final_time = calculate_seconds()
    gmp_initial_time = _g.mpz(initial_time)
    gmp_final_time = _g.mpz(final_time)
    gmp_initial_pid = _g.mpz(0)
    gmp_final_pid = _g.mpz(32768)
    gmp_initial_ppid = _g.mpz(0)
    gmp_final_ppid = _g.mpz(32768)
    
    while gmp_initial_time <= gmp_final_time:
        while gmp_initial_pid <= gmp_final_pid:
            # print gmp_initial_pid
            while gmp_initial_ppid <= gmp_final_ppid:
                seed = gmp_initial_time * gmp_initial_pid * gmp_initial_ppid
                # print seed
                rvalue = create_random_value(seed)
                # while _g.numdigits(rvalue,2) != 1024:
                #     rvalue = create_random_value(seed)
                calculate_division(rvalue, n)
                # print rvalue
                gmp_initial_ppid += 1
            gmp_initial_pid += 1
        # print gmp_initial_time
        gmp_initial_time += 1
        
def calculate_division(test, n):
    # print n
    # print 'number of digits in test is {} in base 2'.format(_g.numdigits(test,2))
    # print 'number of digits in n is {} in base 2'.format(_g.numdigits(n,2))
    prime = _g.next_prime(test)
    # print prime
    if _g.is_prime(prime):
        # print 'I got a prime {}'.format(prime)
        if n % prime == 0:
            print n
            print 'success'
            # print prime
    
# print 'hello'

a = _g.mpz(3)
b = _g.mpz(4)
a * b
n = _g.mpz(24273618023607084486640780738570808771621986433484759110890007663285083070301411494342166417501975875434396254572210883097197606002792961188765714012586572973883316624919480269976588918378510060114863169458998238884707186422078503198409711517331925718724992482313607561083572145615542689766892477475245783591560768105522701218201319805109927490758320089753382216289985913622881684008449778824296369632718648732093073866955919245262132806601747308245712568619870175403589653143883582535983611659536338442969098602432733731978529775504102960957720743400991276136582059048290901573859913873714239909117158697715526500669)

digits = _g.numdigits(n,2)
print 'number of digits in n is {}'.format(digits)
# print n
# calculate_seconds()
calculate_seed(n)