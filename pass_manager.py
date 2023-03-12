from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode




class PasswordManager:

    def __init__(self) -> None:
        self.passw = 'MasterPass'
        self.password_file = "password_file.txt"
        
    def generate_salt(self):
        salt = get_random_bytes(32)
        file = open("salt.txt", "w")
        file.write(str(salt))
    
    def initi(self):
        f = open("password_file.txt", "w")
        f.close()
        self.generate_salt()

    def generate_key(self):
        salt = bytes(open("salt.txt", "r").readline(), 'utf-8')
        return PBKDF2(self.passw, salt, dkLen=32)


    def write(self, data, page):

        data = data.strip()
        page = page.strip()

        iv_page, ct_page = self.encrypt(page)
        iv_data, ct_data = self.encrypt(data)

        flag = False
        cnt = 0

        f = open(self.password_file, "r+")

        while True:
            line = f.readline()

            if not line:
                break

            list = line.split(' ')

            if self.decrypt(list[0], list[1]) == page:
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

        
        
    def encrypt(self, data):
        data = data.encode('utf-8')

        cipher_data = AES.new(self.generate_key(), AES.MODE_CBC)
        ct_bytes_data = cipher_data.encrypt(pad(data, AES.block_size))
        iv_data = b64encode(cipher_data.iv).decode('utf-8')
        ct_data = b64encode(ct_bytes_data).decode('utf-8')

        return iv_data, ct_data


    def read(self,page):

        page = page.strip()

        f = open(self.password_file, "r")
        while True:
            line = f.readline()
            if not line:
                break

            list = line.split(' ')
 
            if self.decrypt(list[0], list[1]) == page:
                iv = list[2]
                ct = list[3]
                break
            
        f.close()
        
        return self.decrypt(iv,ct)
    
    def decrypt(self, iv, ct):
        iv = b64decode(iv)
        ct = b64decode(ct)
        cipher = AES.new(self.generate_key(), AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)

        return pt.decode()

        
import sys
 
if(sys.argv[2] != 'MasterPass'):
    sys.exit('Wrong Master Password')

pw = PasswordManager()

if(sys.argv[1] == 'init'):
    pw.initi()
    print('Password Manager Initialized')
elif(sys.argv[1] == 'put'):
    pw.write(sys.argv[4],sys.argv[3])
    print('Stored Password For ' + sys.argv[3])
elif(sys.argv[1] == 'get'):
    print('Password For ' + sys.argv[3] + ' is: ' + pw.read(sys.argv[3]))





# pw = PasswordManager()

# pw.initi()

# pw.write('sifra142', 'micro')

# print(pw.read('micro'))

    
