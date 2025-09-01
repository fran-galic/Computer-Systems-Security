# BoxLock - Password manager za 1. laboratorijsku vježbu iz kolegija Sigurnost Računalnih Sustava
# Potencijalne mane sustava koje bi volio prokomentirati s Asistentima:
# - master_password se prenosi preko cli argumenata što može ostaviti trag u sustavu
# - pošto (koliko sam ja upoznat) ne spremamo vrijednost ključeva u neko osigurano mjesto u memoriju, netko tko ima pristup RAM-u tijekom
#   izvođenja programa bi mogao doći do samih ključeva bez potrebe za master_password

import argparse
import json
import os

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

DB_FILE = "boxlock.db"

# Funkcija za inicijalizaciju baze podataka
def init_db(master_password):
    master_password_bin = master_password.encode()

    salt = get_random_bytes(32)
    iv = get_random_bytes(16)
    
    # Derivacija ključeva sa PBKDF2
    keys = PBKDF2(master_password_bin, salt, dkLen=64, count=1000000)
    AES_encryption_key = keys[:32]  # Ključ za AES-256 šifriranje
    hmac_key = keys[32:]            # Ključ za HMAC-SHA256

    cipher = AES.new(AES_encryption_key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(b'{}', AES.block_size))
    
    # Računanje HMAC-a 
    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(iv + ct)
    hmac_value = h.digest()
    
    # Pohrana u bazu
    with open(DB_FILE, "wb") as db:
        db.write(salt)
        db.write(iv)
        db.write(ct)
        db.write(hmac_value)
    print("Password manager initialized.")

# Funkcija za pohranu lozinke za određeni korisnički račun
def put_password(master_password, address, password):

    if not os.path.exists(DB_FILE):
        print("Error: Database not initialized!")
        return
    
    master_password_bin = master_password.encode()

    # Otvaranje baze i čitanje podataka
    with open(DB_FILE, "rb") as db:
        salt = db.read(32)  
        iv = db.read(16)   
        ct_and_hmac = db.read() 

        ct = ct_and_hmac[:-32]
        stored_hmac = ct_and_hmac[-32:]

    # Derivacija ključeva za dešifriranje i provjeru integriteta
    keys = PBKDF2(master_password_bin, salt, dkLen=64, count=1000000)
    AES_encryption_key = keys[:32]
    hmac_key = keys[32:]

    # Provjera integriteta 
    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(iv + ct)
    try:
        h.verify(stored_hmac)
    except ValueError:
        print("Master password incorrect or integrity check failed!")
        return

    # Dešifriranje podataka
    cipher = AES.new(AES_encryption_key, AES.MODE_CBC, iv)
    try:
        json_data = unpad(cipher.decrypt(ct), AES.block_size)
        data = json.loads(json_data.decode())
    except:
        print("Decryption error!")
        return

    # Ažuriranje podataka s novom lozinkom
    data[address] = password
    
    # Novo šifriranje
    new_iv = get_random_bytes(16)
    new_cipher = AES.new(AES_encryption_key, AES.MODE_CBC, new_iv)
    new_ct = new_cipher.encrypt(pad(json.dumps(data).encode(), AES.block_size))
    
    # stvaranje novog HMAC-a
    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(new_iv + new_ct)
    new_hmac_value = h.digest()
    
    # Pohrana novih podataka u bazu
    with open(DB_FILE, "wb") as db:
        db.write(salt)
        db.write(new_iv)
        db.write(new_ct)
        db.write(new_hmac_value)
    print("Stored password for {}".format(address))

# Funkcija za dohvat lozinke za određeni korisnički račun
def get_password(master_password, address):

    if not os.path.exists(DB_FILE):
        print("Error: Database not initialized!")
        return

    master_password_bin = master_password.encode()

    with open(DB_FILE, "rb") as db:
        salt = db.read(32)
        iv = db.read(16)
        ct_and_hmac = db.read() 

        ct = ct_and_hmac[:-32]
        stored_hmac = ct_and_hmac[-32:]

    # Derivacija ključeva za dešifriranje i provjeru integriteta
    keys = PBKDF2(master_password_bin, salt, dkLen=64, count=1000000)
    AES_encryption_key = keys[:32]
    hmac_key = keys[32:]

    # Provjera integriteta podataka
    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(iv + ct)
    try:
        h.verify(stored_hmac)
    except ValueError:
        print("Master password incorrect or integrity check failed.")
        return

    # Dešifriranje podataka
    cipher = AES.new(AES_encryption_key, AES.MODE_CBC, iv)
    try:
        json_data = unpad(cipher.decrypt(ct), AES.block_size)
        data = json.loads(json_data.decode())
    except:
        print("Decryption error!")
        return

    password = data.get(address)
    if password:
        print(f"Password for {address}: {password}")
    else:
        print(f"No password found for {address}")   

def main():
    parser = argparse.ArgumentParser(description="BoxLock - Password Manager")
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Definiranje komandi
    init_parser = subparsers.add_parser('init')
    init_parser.add_argument('master_password')

    put_parser = subparsers.add_parser('put')
    put_parser.add_argument('master_password')
    put_parser.add_argument('address')
    put_parser.add_argument('password')

    get_parser = subparsers.add_parser('get')
    get_parser.add_argument('master_password')
    get_parser.add_argument('address')

    # učitavanje argumenata s komandne linije
    args = parser.parse_args()

    # Pozivanje odgovarajućih funkcija
    if args.command == 'init':
        init_db(args.master_password)
    elif args.command == 'put':
        put_password(args.master_password, args.address, args.password)
    elif args.command == 'get':
        get_password(args.master_password, args.address)

if __name__ == "__main__":
    main()
