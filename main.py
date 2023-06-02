import json
import os
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
import hashlib
import requests
import base64
from datetime import datetime
from jwt import (
    JWT,
    jwk_from_dict,
    jwk_from_pem,
)
import time
from threading import Thread,Lock, Condition
import random

fingerprint = "85bbd17fbeaaad45aecba62fb974b1ac40eda237d3679b8f213309b32facc376"

block_transaction_count = None
hash_zeros = None

stop_mining = False
mutex = Lock()
cv = Condition(mutex)

bots = [
    "5dcdedc9a04ea6950153c9279d0f8c1ac9528ee8cdf5cd912bebcf7764b3f9db",
    "4319647f2ad81e83bf602692b32a082a6120c070b6fd4a1dbc589f16d37cbe1d",
    "f44f83688b33213c639bc16f9c167543568d4173d5f4fc7eb1256f6c7bb23b26",
    "a4d9a38a04d0aa7de7c29fef061a1a539e6a192ef75ea9730aff49f9bb029f99",
    "9d453e55cd1367ecf122fee880991e29458651f3824cd9ea47b89e06158936e3",
    "e5ed590ed68523b68a869b74564d824f56728d8b29af8dd4dcf1049dfa93c2e2"
]
bot_index = 0

with open("gradecoin.pub","r") as f:
    gradecoin_public_key = f.read()

with open("public.pem","r") as f:
    public_key = f.read()

with open("private.pem","rb") as f:
    private_key = f.read()

passwd = "K2NOJj1XcOHz3fshr3cT7BYHv+o+54PF"


def auth(student_id,passwd,public_key):

    PAR = json.dumps({"student_id":student_id,"passwd":passwd,"public_key":public_key})

    #create temp 128 bit key
    k_temp = get_random_bytes(16)

    #create 128 bit iv
    iv = get_random_bytes(16)

    cipher = AES.new(k_temp,AES.MODE_CBC,iv=iv)

    #pkcs7 padding
    pad = 16 - len(PAR) % 16
    PAR = PAR + pad * chr(pad)

    #encrypt PAR
    CAR = cipher.encrypt(PAR.encode())

    #encrypt k_temp using RSA using SHA-256 with gradecoin_public_key
    recipient_key = RSA.import_key(gradecoin_public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key,hashAlgo=SHA256)
    key_ciphertext = cipher_rsa.encrypt(k_temp)

    #encode k_temp,iv and PAR in base64
    key_ciphertext = base64.b64encode(key_ciphertext).decode()
    iv = base64.b64encode(iv).decode()
    CAR = base64.b64encode(CAR).decode()

    auth_request = json.dumps({"c":CAR,"iv":iv,"key":key_ciphertext})


    response = requests.post("https://gradecoin.xyz/register",data=auth_request)
    print(response.text)

def get_transactions():
    response = requests.get("https://gradecoin.xyz/transaction")

    transactions = json.loads(response.text)

    ids = []
    first_id = None
    for transaction in transactions.items():
        if transaction[1]["source"] == fingerprint:
            first_id = transaction[0]
            continue
        ids.append(transaction[0])

    if first_id is not None:
        ids.insert(0,first_id)
        return ids
    else:
        return []

def get_config():
    response = requests.get("https://gradecoin.xyz/config")

    response = json.loads(response.text)

    global block_transaction_count
    global hash_zeros

    block_transaction_count = response["block_transaction_count"]
    hash_zeros = response["hash_zeros"]

    print("block_transaction_count: ",block_transaction_count)
    print("hash_zeros: ",hash_zeros)

def sign(payload):
    instance = JWT()
    signing_key = jwk_from_pem(private_key,b'1111')
    return instance.encode(payload,signing_key,"RS256")

def send_transaction(target):
    tx = {
        "source":fingerprint,
        "target":target,
        "amount":1,
        "timestamp":datetime.now().isoformat()
    }

    tx = json.dumps(tx).replace(" ","")

    #md5 hash
    tx_hash = hashlib.md5(tx.encode()).hexdigest()

    payload = {
        "tha":tx_hash,
        "iat":int(datetime.now().timestamp()),
        "exp":int(datetime.now().timestamp())+3600
    }

    jwt_token = sign(payload)

    response = requests.post("https://gradecoin.xyz/transaction",data=tx,headers={"Authorization":"Bearer "+jwt_token})

    response = json.loads(response.text)

    print(response["message"])

def send_block():
    transaction_list = get_transactions()
    global bots
    global bot_index
    while len(transaction_list) < block_transaction_count:
        print("Not enough transactions to create a block: ",len(transaction_list))
        if len(transaction_list) == 0:
            print("No transaction available, sending one to bots")
            send_transaction(bots[bot_index])
            bot_index = (bot_index + 1) % len(bots)
        transaction_list = get_transactions()
        time.sleep(3)

    if len(transaction_list) > block_transaction_count:
        transaction_list = transaction_list[:block_transaction_count]
    
    print("Starting to mine block")

    nonce = 0
    ts = datetime.now().isoformat()

    # generate miner threads with random nonces
    threads = []
    n = 20
    for i in range(n):
        threads.append(Thread(target=miner,args=(nonce,transaction_list,ts)))
        nonce += 2**32 // n

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

def miner(nonce,transaction_list,ts):

    temp = {
        "transaction_list":transaction_list,
        "nonce":nonce,
        "timestamp":ts
    }

    payload = {
        "tha":"",
        "iat":int(datetime.now().timestamp()),
        "exp":int(datetime.now().timestamp())+3600
    }

    temp_s = json.dumps(temp).replace(" ","")

    #blake2s hash
    hash_val = hashlib.blake2s(temp_s.encode()).hexdigest()
    target_zeros = "0"*hash_zeros
    print("started thread with nonce: ",nonce)
    while hash_val[:hash_zeros] != target_zeros:
        nonce += 1
        temp["nonce"] = nonce
        temp_s = json.dumps(temp).replace(" ","")
        #blake2s hash
        hash_val = hashlib.blake2s(temp_s.encode()).hexdigest()
    
    jwt_token = sign(payload)

    temp["hash"] = hash_val
    payload["tha"] = hash_val

    response = requests.post("https://gradecoin.xyz/block",data=json.dumps(temp),headers={"Authorization":"Bearer "+jwt_token})

    print(response.text)

    response = json.loads(response.text)

    if response["res"] == "Error":
        print("Error occurred")
    else:
        print("Block mined")




if __name__ == "__main__":
    get_config()
    send_block()







