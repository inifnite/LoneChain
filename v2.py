import hashlib
import datetime

from hashlib import sha512

import json
from textwrap import dedent

from uuid import uuid4
from flask import Flask, jsonify, request

import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from Crypto import Random
from base64 import b64encode, b64decode
import rsa

def newkeys(keysize = 2048):
    random_generator = Random.new().read
    key = RSA.generate(keysize, random_generator)
    private, public = key, key.publickey()
    return public, private

def sign(message, priv_key):
    hash = int.from_bytes(sha512(message.encode('utf-8')).digest(), byteorder='big')
    return pow(hash, priv_key.d, priv_key.n)

def verify(message, signature, pub_key):
    hash = int.from_bytes(sha512(message.encode('utf-8')).digest(), byteorder='big')
    return pow(signature, pub_key.e, pub_key.n) == hash


recent_transactions = []


class Block():
    def __init__(self, blockchain, index=None,  difficulty=None, nonce=None, transactions=[], previous_hash=None):
        self.index = index
        self.timestamp = datetime.datetime.utcnow()
        self.nonce = nonce
        self.difficulty = difficulty
        self.blockchain = blockchain
        self.previous_hash = previous_hash
        self.transactions = self.addTransactions(transactions)
        if previous_hash == '' :
            self.hash = ''
        self.merkleRoot = self.get_merkleRoot(self.transactions)
        self.hash = self.hashing()

    def hashing(self):
        key = hashlib.sha256()
        key.update(str(self.previous_hash).encode('utf-8'))
        key.update(str(self.timestamp).encode('utf-8'))
        key.update(str(self.merkleRoot).encode('utf-8'))
        return key.hexdigest()
    
    def addTransactions(self, transactions):
        trans = []
        for t in transactions:
            if t == None:
                continue
            if(self.previous_hash != ''):
                if t.processTransaction(self.blockchain) == False:
                    print("Transaction ", t.transactionId, "failed to process!!!")
                    continue
            trans.append(t)
        return trans
    
    def get_merkleRoot(self, trans):
        num = len(trans)
        p_trans=[]
        for t in trans:
            t = hashlib.md5(str(t).encode('utf-8'))
            p_trans.append(t.hexdigest())
        trans=[]
        trans=p_trans
        p_trans=[]
        n2 = len(trans)
        if (n2%2) == 1:
            trans.append(trans[n2-1])
            n2 = n2+1
        while len(trans) > 1:
            n1 = len(trans)
            if (n1%2) == 1:
                trans.append(trans[-1])
                n1 = n1+1
            i=0
            while i < n1:
                p_trans.append(hashlib.md5(((str(trans[i])+str(trans[i+1])).encode('utf-8'))).hexdigest())
                i+=2
            trans=[]
            trans=p_trans
            p_trans=[]


class BlockChain():
    def __init__(self):
        self.difficulty = 4
        #self.blocks = [self.GenesisBlock()]
        self.blocks = []
        self.UTXOs = {}

    def GenesisBlock(self):
        genesisBlock = Block(0, self.difficulty, hex(0),'Genesis', '')
        self.blocks.append(genesisBlock)
        return genesisBlock
    
    def isChainValid(self):
        prev_block = Block(self, [])
        for block_num in range(len(self.blocks)):
            curr_block = self.blocks[block_num]
            if block_num == 0:
                prev_block = self.blocks[block_num]
                continue
            if ((curr_block.hashing() != curr_block.hash) or 
            (prev_block.hash != curr_block.previous_hash) or
            str(hashlib.sha256( (str(curr_block.nonce) + str(prev_block.hash)).encode('utf-8') ).hexdigest())[:curr_block.difficulty] != 
            ('').zfill(curr_block.difficulty)):
                #print( curr_block.hash[:curr_block.difficulty])
                #print("curr_block hashing --> ", curr_block.hashing())
                #print("curr_block hash --> ", curr_block.hash)
                #print("curr_block.previous_hash --> ", curr_block.previous_hash)
                #print("prev_block hash --> ", prev_block.hash)
                return False
            prev_block = curr_block 
        return True
    
    def MineBlock(self):
        prev_hash = ''
        if len(self.blocks) != 0: 
            prev_hash = self.blocks[len(self.blocks)-1].hash
        target = ''
        target = target.zfill(self.difficulty)
        nonce = 0
        #print("target --> ", target)
        #print("previous_hash --> ", prev_hash)
        while str(hashlib.sha256( (str(hex(nonce)) + str(prev_hash)).encode('utf-8') ).hexdigest())[:self.difficulty] != target:
            #print("hashed string is ---> ",str(hashlib.sha256( (str(hex(nonce)) + str(prev_hash)).encode('utf-8') ).hexdigest())[:self.difficulty])
            nonce = nonce + 1
        #print("hashed string with correct nonce is ---> ",str(hashlib.sha256( (str(hex(nonce)) + str(prev_hash)).encode('utf-8') ).hexdigest())[:self.difficulty])
        #print("nonce is ---> " , nonce)
        return nonce


    def CheckNonce(self, nonce):
        prev_hash = ''
        if len(self.blocks) != 0: 
            prev_hash = self.blocks[len(self.blocks)-1].hash
        target = ''
        target = target.zfill(self.difficulty)
        if str(hashlib.sha256((str(hex(nonce))+str(prev_hash)).encode('utf-8')).hexdigest())[:self.difficulty] == target:
            return True
        return False
    
    def add_block(self, nonce, pending_transactions):
        if self.CheckNonce(nonce) :
            prev_hash = ''
            if len(self.blocks) != 0:
                prev_hash = self.blocks[len(self.blocks)-1].hash
            pending_transactions_len = len(pending_transactions)
            slice_len = 2
            if pending_transactions_len < 2:
                slice_len = pending_transactions_len
            #print("in function -->   ", len(pending_transactions[:slice_len]))
            newBlock = Block(self, len(self.blocks), self.difficulty, hex(self.MineBlock()), pending_transactions[:slice_len], prev_hash)
            #print("---> ",len(pending_transactions[:slice_len]))
            recent_transactions.extend(pending_transactions[:slice_len])
            recent_transactions[:] = recent_transactions
            pending_transactions[:] = pending_transactions[slice_len:]
            #print("---> ",len(pending_transactions))
            self.blocks.append(newBlock)
            return newBlock


class TransactionOutput():
    def __init__(self, recipient, value, parentTransactionId):
        self.recipient = recipient
        self.value = value
        self.parentTransactionId = parentTransactionId
        self.id = self.hashing()
    
    def hashing(self):
        return hashlib.sha256( (str(self.recipient.exportKey())+str(self.value)).encode('utf-8') ).hexdigest()
    
    def isMine(self, public_key):
        return self.recipient == public_key


class TransactionInput():
    def __init__(self, transactionOutputId):
        self.transactionOutputId = transactionOutputId
        self.UTXO = TransactionOutput(None, None, None)
    



class Wallet():
    def __init__(self, blockchain):
        self.public_key, self.private_key = newkeys()
        self.UTXOs = {}
        self.blockchain = blockchain
    
    def getBalance(self):
        total = 0
        for key, pair in self.blockchain.UTXOs.items():
            if pair.isMine(self.public_key):
                self.blockchain.UTXOs[pair.id] = pair
                total = total + pair.value
        return total
    
    def sendFunds(self,recipient,value):
        if self.getBalance() < value:
            print("#Not Enough funds to send Transaction")
            return None
        
        inputs = []
        total = 0
        for key, pair in self.UTXOs.items():
            total = total + pair.value
            inputs.append(TransactionInput(pair.id))
            if total > value:
                break
        
        newTransaction = Transaction(self.public_key, recipient, value, inputs)
        newTransaction.getSignature(self.private_key)

        for i in inputs:
            self.UTXOs.pop[i.transactionOutputId]
        
        return newTransaction



class Transaction():
    def __init__(self, sender, recipient, value, inputs):
        self.sender = sender
        self.recipient = recipient
        self.value = value
        self.inputs = inputs
        self.outputs = []
        self.signature = ''
        self.transactionId = ''

    def hashing(self):
        return hashlib.sha256( (str(self.sender.exportKey()) + str(self.recipient.exportKey()) 
        + str(self.value) + str(datetime.datetime.utcnow())).encode('utf-8') ).hexdigest()
    
    def getSignature(self, private_key):
        message = str(self.sender.exportKey()) + str(self.recipient.exportKey()) + str(self.value)
        self.signature = sign(message, private_key)
        return self.signature

    def verifySignature(self):
        message = str(self.sender.exportKey()) + str(self.recipient.exportKey()) + str(self.value)
        return verify(message, self.signature, self.sender)
    
    def getInputsValue(self):
        total = 0
        for i in self.inputs:
            if i.UTXO == None:
                continue
            total = total + i.UTXO.value
        return total

    def getOutputsValue(self):
        total = 0
        for o in self.outputs:
            total = total + o.value
        return total

    def processTransaction(self, LoneChain):
        if self.verifySignature() == False:
            print("#Transaction Signature Not Valid!!!")
            return False
        
        for i in self.inputs:
            i.UTXO = LoneChain.UTXOs[i.transactionOutputId]
        
        leftOver = self.getInputsValue() - self.value
        self.transactionId = self.hashing()
        self.outputs.append(TransactionOutput(self.recipient, self.value, self.transactionId))
        self.outputs.append(TransactionOutput(self.sender, leftOver, self.transactionId))

        for o in self.outputs:
            LoneChain.UTXOs[o.id] = o
        
        for i in self.inputs:
            if i.UTXO == None:
                continue
            LoneChain.UTXOs.pop(i.UTXO.id)
        
        return True


def printBlock(block):
    print("Block Index: ", block.index)
    print("Block TimeStamp: ", block.timestamp)
    print("Block Nonce: ", block.nonce )
    print("Block Hash: ", block.hash)
    print("Block Previous Hash: ", block.previous_hash)
    for t in block.transactions:
        print("transaction Id: ", t.transactionId)
        print("\tsender: ", t.sender,"\n\trecipient: ", t.recipient, "\n\tvalue: ",t.value)
    print("\n")

def printTransaction(t):
    print("transaction Id: ", t.transactionId)
    print("\tsender: ", t.sender,"\n\trecipient: ", t.recipient, "\n\tvalue: ",t.value)
    print("\n")



LoneChain = BlockChain()

chain = LoneChain.blocks

#LoneChain.add_block(LoneChain.MineBlock(), 'I am a Block');
#LoneChain.add_block(LoneChain.MineBlock(), 'I am a Block');
#LoneChain.add_block(7, 'I am a Block');

#for i in chain:
#    print(i.hash, "     ###     ", str(hashlib.sha256( (str(i.nonce) + str(i.previous_hash)).encode('utf-8') ).hexdigest())[:i.difficulty])

#print(LoneChain.isChainValid())


wallets = {}
pending_transactions = []

wallet_generic = Wallet(LoneChain)
coinbase = Wallet(LoneChain)

wallets[str(wallet_generic.public_key.export_key())] = wallet_generic
wallets[str(coinbase.public_key.export_key())] = coinbase

gt = Transaction(coinbase.public_key, wallet_generic.public_key, 100, None)
gt.getSignature(coinbase.private_key)
gt.transactionId = 0
gt.outputs.append(TransactionOutput(gt.recipient, gt.value, gt.transactionId))
LoneChain.UTXOs[gt.outputs[0].id] = gt.outputs[0]


wallet_2 = Wallet(LoneChain)
wallets[str(wallet_2.public_key.export_key())] = wallet_2

#block1 = LoneChain.add_block(LoneChain.MineBlock(), 
##[wallet_generic.sendFunds(wallet_2.public_key, 30),
#wallet_generic.sendFunds(wallet_2.public_key, 10)])

#genesisBlock = LoneChain.add_block(LoneChain.MineBlock(), [gt])

#pending_transactions.append(wallet_generic.sendFunds(wallet_2.public_key, 3))
#pending_transactions.append(wallet_generic.sendFunds(wallet_2.public_key, 10))
#pending_transactions.append(wallet_generic.sendFunds(wallet_2.public_key, 5))
#pending_transactions.append(wallet_generic.sendFunds(wallet_2.public_key, 15))

#print(len(pending_transactions))
#block_1 = LoneChain.add_block(LoneChain.MineBlock(), pending_transactions)
#print(len(pending_transactions))

app = Flask(__name__)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')


@app.route('/mineGenesisBlock', methods=['GET'])
def mineGenesisBlock():
    genesisBlock = LoneChain.add_block(LoneChain.MineBlock(), [gt])

    response = {
        "Block Index" : genesisBlock.index,
        "Block TimeStamp" : genesisBlock.timestamp,
        "Block Nonce" : genesisBlock.nonce,
        "Block Hash" : genesisBlock.hash,
        "Block Previous Hash" : genesisBlock.previous_hash,
        "Block Transactions" : {
            "transaction Id": gt.transactionId,
            "sender" : str(gt.sender.export_key()),
            "recipient" : str(gt.recipient.export_key()),
            "value" : gt.value
            }
    }
    return jsonify(response), 201


chain
@app.route('/mine', methods=['GET'])
def mine():
    if len(pending_transactions) == 0:
        return jsonify({"message" : "No Pending Transactions"}), 201
    block = LoneChain.add_block(LoneChain.MineBlock(), pending_transactions)

    transactions = []
    for t in block.transactions:
        transactions.append({
            "transaction Id": t.transactionId,
            "sender" : str(t.sender.export_key()),
            "recipient" : str(t.recipient.export_key()),
            "value" : t.value
            })

    response = {
        "Block Index" : block.index,
        "Block TimeStamp" : block.timestamp,
        "Block Nonce" : block.nonce,
        "Block Hash" : block.hash,
        "Block Previous Hash" : block.previous_hash,
        "Block Transactions" : transactions
    }
    for w in wallets.values():
        print(w.getBalance())
    return jsonify(response), 201



@app.route('/createWallet', methods=['GET'])
def createWallet():
    wallet = Wallet(LoneChain)
    wallets[str(wallet.public_key.export_key())] = wallet
    response = {
        "message" : "New Wallet Formed",
        "privateKey" : str(wallet.private_key.export_key()),
        "publicKey" : str(wallet.public_key.export_key()) 
    }
    for w in wallets.values():
        print(w.public_key)
    return jsonify(response), 200


@app.route('/balanceWallet/<sender>', methods=['GET'])
def balanceWallet(sender):
    sender_wallet = wallets[sender]

    response = {
        "message" : "Successfully Got Balance",
        "balance" : sender_wallet.getBalance()
    }
    return jsonify(response), 200


@app.route('/transactionsWallet', methods=['GET'])
def transactionWallet():
    wallet = Wallet(LoneChain)
    wallets[str(wallet.public_key.export_key())] = wallet
    response = {
        "message" : "New Wallet Formed",
        "privateKey" : str(wallet.private_key.export_key()),
        "publicKey" : str(wallet.public_key.export_key()) 
    }
    for w in wallets.values():
        print(w.public_key)
    return jsonify(response), 200



@app.route('/newTransactions', methods=['POST'])
def new_transaction():
    values = request.get_json()
    required = ['sender', 'recipient', 'value']

    if not all(k in values for k in required):
        return 'Missing values', 400
    
    sender_wallet = wallets[values['sender']]
    recipient = wallets[values['recipient']].public_key
    value = int(values['value'])

    t = sender_wallet.sendFunds(recipient, value)
    t.getSignature(sender_wallet.private_key)
    pending_transactions.append(t)

    response = {
        "transaction Id": t.transactionId,
        "sender" : str(t.sender),
        "recipient" : str(t.recipient),
        "value" : t.value
    }
    
    return jsonify(response), 201


@app.route('/showTransactions', methods=['GET'])
def show_transaction():
    transactions = []
    for t in recent_transactions:
        transactions.append({
            "transaction Id": t.transactionId,
            "sender" : str(t.sender),
            "recipient" : str(t.recipient),
            "value" : t.value
        })
    response = {
        "Recent Transactions" : transactions 
    }
    return jsonify(response), 201




@app.route('/chain', methods=['GET'])
def full_chain():
    blocks = []
    for block in LoneChain.blocks:
        transactions = []
        for t in block.transactions:
            transactions.append({
                "transaction Id": t.transactionId,
                "sender" : str(t.sender),
                "recipient" : str(t.recipient),
                "value" : t.value
                })
        block_info = {
            "Block Index" : block.index,
            "Block TimeStamp" : block.timestamp,
            "Block Nonce" : block.nonce,
            "Block Hash" : block.hash,
            "Block Previous Hash" : block.previous_hash,
            "Block Transactions" : transactions
        }
        blocks.append(block_info)
    response = {
        "length" : len(LoneChain.blocks),
        "blocks" : blocks   
    }
    return jsonify(response), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)