from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from Crypto.Hash import HMAC, SHA256




class PasswordManager:

    def __init__(self) -> None:
        self.password_file = "password_file.txt"
        

    def generate_salt(self):
        salt = get_random_bytes(32)
        file = open("salt.txt", "w")
        file.write(str(salt))
    
    def generate_master_pass(self, MasterPass):
        h = HMAC.new(MasterPass.encode('utf-8'), None, digestmod=SHA256).hexdigest()
        f = open('MasterPass.txt', 'w')
        f.write(h)
        f.close()

    def check_master_pass(self, new_pass) ->bool:
        return open('MasterPass.txt', 'r').readline() == HMAC.new(new_pass.encode('utf-8'), digestmod=SHA256).hexdigest()
        
    
    def initi(self, MasterPass):
        f = open("password_file.txt", "w")
        f.close()
        self.generate_salt()
        self.generate_master_pass(MasterPass)

    def generate_key(self, passw):
        salt = bytes(open("salt.txt", "r").readline(), 'utf-8')
        return PBKDF2(passw, salt, dkLen=32)

    def write(self, data, page, passw):

        data = data.strip()
        page = page.strip()

        iv_page, ct_page = self.encrypt(page, passw)
        iv_data, ct_data = self.encrypt(data, passw)

        flag = False
        cnt = 0

        f = open(self.password_file, "r+")

        while True:
            line = f.readline()

            if not line:
                break

            list = line.split(' ')

            if self.decrypt(list[0], list[1], passw) == page:
                flag = True
                supst = list[0] + ' ' + list[1] + ' ' + iv_data + ' ' + ct_data + '\n'
                break

            cnt += 1

        f.close()

        if not flag:
            f = open(self.password_file, "a")
            f.write(iv_page + ' ' + ct_page + ' ' + iv_data + ' ' + ct_data + '\n')
            f.close()

        else:
            lines = open(self.password_file, 'r').readlines()
            lines[cnt] = supst
            out = open(self.password_file, 'w')
            out.writelines(lines)
            out.close()

        
        
    def encrypt(self, data, passw):
        data = data.encode('utf-8')

        cipher_data = AES.new(self.generate_key(passw), AES.MODE_CBC)
        ct_bytes_data = cipher_data.encrypt(pad(data, AES.block_size))
        iv_data = b64encode(cipher_data.iv).decode('utf-8')
        ct_data = b64encode(ct_bytes_data).decode('utf-8')

        return iv_data, ct_data


    def read(self,page, passw):

        page = page.strip()

        f = open(self.password_file, "r")
        while True:
            line = f.readline()
            if not line:
                break

            list = line.split(' ')
 
            if self.decrypt(list[0], list[1], passw) == page:
                iv = list[2]
                ct = list[3]
                break
            
        f.close()
        
        return self.decrypt(iv,ct,passw)
    
    def decrypt(self, iv, ct, passw):
        iv = b64decode(iv)
        ct = b64decode(ct)
        cipher = AES.new(self.generate_key(passw), AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)

        return pt.decode()

        
import sys
 

pw = PasswordManager()

if(sys.argv[1] == 'init'):
    pw.initi(sys.argv[2])
    print('Password Manager Initialized')
elif(sys.argv[1] == 'put' and pw.check_master_pass(sys.argv[2])):
    pw.write(sys.argv[4],sys.argv[3],sys.argv[2])
    print('Stored Password For ' + sys.argv[3])
elif(sys.argv[1] == 'get' and pw.check_master_pass(sys.argv[2])):
    print('Password For ' + sys.argv[3] + ' is: ' + pw.read(sys.argv[3],sys.argv[2]))
else:
    sys.exit('Master password incorrect or integrity check failed.')

    