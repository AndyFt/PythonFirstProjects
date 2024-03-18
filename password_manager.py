import os
import base64
import cryptography
from cryptography.hazmat.primitives import hashes
from  cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

master_pwd = input(f"Enter your master password: ")

salt = os.urandom(16)

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
)

derived_key = kdf.derive(master_pwd.encode())

verification_kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
)

verification_kdf.verify(master_pwd.encode(), derived_key)

key = base64.urlsafe_b64encode(derived_key)
f = Fernet(key)


fernettoken = f.encrypt(master_pwd.encode())

master_key = fernettoken.decode()

class Encrypter:
    def __init__(self, keyfile, data):
      self.keyfile = keyfile
      self.data = data
      self.key = None
      
      def generate_key(self):
        if not self.key:
          self.key = Fernet.generate_key().decode()
          return self.key
        
def save_key(key):
  if len(key) != 32:
    raise ValueError("Invalid key length")
  with open("key.key", "wb") as keyfile:
    keyfile.write(base64.urlsafe_b64encode(key))
      

def load_key():
  try:
    with open("key.key", "rb") as keyfile:
      key_data = keyfile.read()
      decoded_key = base64.urlsafe_b64decode(key_data)
      # Ensure the decoded key has the expected length
      if len(decoded_key) != 32:
        raise ValueError("Invalid key length")
      return decoded_key
  except (IOError, ValueError) as e:
    print("Error loading key: ", e)
    return None
  
  
loaded_key = load_key()

if loaded_key:
  # Create the Fernet object using the loaded key
  f = Fernet(loaded_key)
  print("Key loaded successfully!")
else:
  print("Key not loaded correctly.")

print(fernettoken)
print("\n\n")
print(loaded_key)

try:
  verification_kdf.verify(loaded_key.encode(), fernettoken.encode())
except Exception as e:
  print("Key not loaded correctly.")
else:
  print("Key loaded successfully!")
  
  # master_key = file.read()
  # file.close()
  # return master_key


master_key = load_key()


'''
# GENERATE KEY - Here we create the key using a hash of our master password, this is not secure but it's simple and works for demonstration purposes. This script will encrypt and decrypt a file using the Fernet symmetric encryption algorithm, which is  based on AES (Advanced Encryption Standard).

def write_key():
  key = Fernet.generate_key()
  with open("key.key", "wb") as key_file:
    key_file.write(key)'''
    
'''
# Here we call the function to create a new encryption key.
write_key()'''

def add(f):
  name = input("Account name: ")
  pwd = input("Password: ")
  
  # Encrypt the password using the Fernet object
  encrypted_pwd = f.encrypt(pwd.encode())
  
  # Properly base64-encode the encrypted password
  base64_encoded_pwd = base64.b64encode(encrypted_pwd).decode()

  with open('passwords.txt', 'a') as f:
    f.write(name + "|" + base64_encoded_pwd + "\n")

def view(f):
  with open('passwords.txt', 'r') as file:
    for line in file:
      data = line.rstrip()
      user, passw = data.split("|")
      try:
        decrypted_pwd = f.decrypt(base64.b64decode(passw)).decode()
        print(f'User: {user}, |  Password: {decrypted_pwd}')
      except cryptography.fernet.InvalidToken:
        print("Invalid token encountered while decrypting. Skipping this entry.")




while True:
    mode = input("Would you like to add a new password or view existing one? (A/V) or Q to quit: ").upper()
    if mode == "Q":
      break
    if mode == "V":
      view(f)
    elif mode == "A":
      add(f)
    else:
      print('Invalid mode.')
      continue