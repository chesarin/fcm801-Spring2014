#!/usr/bin/env python
import re
import password
import time
import logging
import os
from multiprocessing import Process,Lock,Queue
logging.basicConfig(level=logging.DEBUG,
                    format='[%(levelname)s] (%(processName)-10s) %(message)s')

class FileProcessor(object):
    def __init__(self,fname):
        self.fname = fname
        self.data = []
    def extract_data(self):
        with open(self.fname,'r') as f:
            for line in f:
                self.data.append(line.rstrip())
    def get_data(self):
        return self.data
    def print_data(self):
        for i in self.data:
            print i,
            
class ShadowFileProcessor(object):
    def __init__(self,filename):
        self.filename = filename
        self.filedata = []
        self.shadowentries = []
    def process_file(self):
        fp = FileProcessor(self.filename)
        fp.extract_data()
        # fp.print_data()
        self.filedata = fp.get_data()
    def create_shadow_entry(self):
        for entry in self.filedata:
            temp = re.split(':',entry)
            entry = ShadowEntry(temp[0],temp[1])
            entry.get_salt()
            # print entry
            self.shadowentries.append(entry)
    def get_shadow_entries(self):
        return self.shadowentries
        
class ShadowEntry(object):
    def __init__(self,username,encpassword):
        self.username = username
        self.encpassword = encpassword
        self.salt = ''
    def get_username(self):
        return self.username
    def get_password(self):
        return self.encpassword
    def get_salt(self):
        temp = re.split(r"\$",self.encpassword)
        self.salt = '${}${}$'.format(temp[1],temp[2])
        return self.salt
    def __str__(self):
        return 'username:{} hashed password:{} salt:{}'.format(self.username,self.encpassword,self.get_salt())
        
class PasswordCracker(object):
    def __init__(self,shadowQueue,passdb):
        self.passdb = passdb
        self.shadowQueue = shadowQueue
    def run(self):
        while not self.shadowQueue.empty():
            shadowEntry = self.shadowQueue.get()
            shadowTuple = self._getPersonalData(shadowEntry)
            if self._stage1(shadowTuple):
                continue
            if self._stage2(shadowTuple):
                continue
        logging.debug('Dying')
    def _stage1(self,shadowTuple):
        status = False
        username,salt,shadowpass = shadowTuple
        logging.debug('In Stage 1 username %s',username)
        for p in self.passdb:
            ptemp = password.encryptp(p,salt)
            if ptemp == shadowpass:
                logging.debug ('SUCCESS Stage1:Found password for %s and that is %s',username,p)
                status = True
                break
        return status
    def _stage2(self,shadowTuple):
        status = False
        username,salt,shadowpass = shadowTuple
        logging.debug('In Stage 2 username %s',username)
        ptemp = password.encryptp(username,salt)
        if ptemp == shadowpass:
            logging.debug ('SUCCESS Stage2:Found password for %s and that is %s',username,username)
            status = True
        return status
        
    def print_results(self):
        print 'passwords cracked via dictionary attack'
        for key,value in self.success.iteritems():
            print 'key:{} password:{} hashed-password:{}'.format(key,value[0],value[1])
    def _getPersonalData(self,shadowEntry):
        name = shadowEntry.get_username()
        salt = shadowEntry.get_salt()
        shadowpass = shadowEntry.get_password()
        return name,salt,shadowpass
            
class PasswordEncrypt(object):
    def __init__(self,passwd,salt):
        self.encryptpass = password.encrypt(passwd,salt)
    def get_password(self):
        return self.encryptpass
        
class PasswordFileProcessor(object):
    def __init__(self,filename):
        self.filename = filename
        self.passwords = []
    def process_file(self):
        fp = FileProcessor(self.filename)
        fp.extract_data()
        data = fp.get_data()
        for entry in data:
            if not re.match(r'^#',entry):
                self.passwords.append(entry)
    def print_data(self):
        for i in self.passwords:
            print i
    def get_data(self):
        return self.passwords
        
if __name__ == '__main__':
    starttime = time.clock()
    logging.debug('starting main')
    shadowfile = 'shadow.txt'
    passwordfile = 'passwords.txt'
    passfp = PasswordFileProcessor(passwordfile)
    passfp.process_file()
    processes = []
    cpus = os.sysconf("SC_NPROCESSORS_ONLN")
    passwdentries = passfp.get_data()
    shadowfp = ShadowFileProcessor(shadowfile)
    shadowfp.process_file()
    shadowfp.create_shadow_entry()
    _sentinel = object()
    shadowEntries = shadowfp.get_shadow_entries()
    shadowQueue = Queue(20)
    logging.debug('filling shadowQueue number of cpus %s',str(cpus))
    logging.debug('size of shadowEntries %s',len(shadowEntries))
    for entry in shadowEntries:
        shadowQueue.put(entry)
    logging.debug('before getting into loop to create threads')
    for pname in range(cpus):
        logging.debug('creating process %s',str(pname))
        c = PasswordCracker(shadowQueue,passwdentries)
        process = Process(target=c.run,args=())
        process.start()
        processes.append(process)
    
    stoptime = time.clock()
    for p in processes:
        p.join()
    logging.debug('Dying')
