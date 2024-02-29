import base58check
from cssdk import TClient as Client

# checking wallet balance
def checkWalletBalance():

    balance = client.amountToFloat(client.getBalance(Key))
    print('Key balance = ', balance)

def getTransactionData():
    transactionsData = client.getTransactions(Key, 0, 10)
    cnt = 0
    if transactionsData != None and transactionsData.status.code == 0:
        for a in transactionsData.transactions:
            cnt += 1
            print(cnt, '. ', a)

    else:
        print(transactionsData.status.message)

    defaultTransactionId = transactionsData.transactions[0].id
    print('Default transaction id = (', defaultTransactionId.poolSeq, ', ' , defaultTransactionId.index, ')')

    defaultTransaction = client.getTransaction(defaultTransactionId.poolSeq, defaultTransactionId.index)
    if defaultTransaction != None and transactionsData.status.code == 0:
        print('Default pool value: ', defaultTransaction.transaction)

def getPoolData():
    defaultPool = client.getPool(defaultTransactionId.poolSeq)
    if defaultPool != None and defaultPool.status.code == 0:
        print('Default pool value: ', defaultPool)

def getContractData():
    pKeyContracts = client.getUserContracts(Key, 0, 100)
    if pKeyContracts != None and pKeyContracts.status.code == 0:
        cnt = 0
        print(Key,' contracts:')
        for a in pKeyContracts.smartContractsList:
            cnt += 1
            print(cnt, '. ', base58check.b58encode(a.address).decode('UTF-8'), ', deployer: ' , base58check.b58encode(a.deployer).decode('UTF-8'))

    defaultContract = pKeyContracts.smartContractsList[0]
    print('Default contract source code: \n', defaultContract.smartContractDeploy.sourceCode)

    defaultContractSourceCode = client.getContractCode(base58check.b58encode(defaultContract.address).decode('UTF-8'))
    print('Default contract source code by address: \n', defaultContractSourceCode)


def sendTransaction():
    amount = client.getAPI().general.Amount()
    # or
    amount = client.floatToamount(1.001)

    fee =client.double_to_fee(0.1)

    # this version of SDK doesn't work with transactions user fields, this will be awailable in next version
    # UserFields: id(32 bit integer, value(integer, text, amount)) 
    # userFields = {}

    # sending coins to new created account
    client.sendAmount(Key, secureKey, newKey, amount, fee)
    balance = client.amountToFloat(client.getBalance(newKey))
    print(newKey, ': balance = ', balance)

    # sending coins from new created account
    amount = client.floatToamount(0.02)

    client.sendAmount(newKey, newSKey, Key, amount, fee)
    balance = client.amountToFloat(client.getBalance(newKey))
    print(newKey, ': balance = ', balance)

#  deploing new contract
def deployContract():
    with open("smart.txt", "r") as contract_file:
        newContractCode = contract_file.read()

    print(newContractCode)

    contract = client.prepareContract(newContractCode)

    fee = client.double_to_fee(0.1)
    uf_text = ''
    client.deployContract(Key, secureKey, fee, contract, uf_text)

# executing contract
def executeContract():
    pKeyContracts = client.getUserContracts(Key, 0, 100)
    contractAddress =''
    if pKeyContracts == None or pKeyContracts.status.code != 0:
        return 
    num = len(pKeyContracts.smartContractsList)-1
    curContractDepoyData = pKeyContracts.smartContractsList[num]
    contractAddress = base58check.b58encode(curContractDepoyData.address).decode('UTF-8')  

    curContractMethods = client.getContractMethods(contractAddress)
    if curContractMethods == None or len(curContractMethods.methods) == 0:
        print('Contract ', contractAddress, ' has no methods')
        return 
    contractMethod = curContractMethods.methods[0].name

    methodParameters = curContractMethods.methods[0].arguments

    fee = fee = client.double_to_fee(0.1)
    ufText = ''
    used = []
    save_to_bch = True
    client.executeContract(Key,secureKey, contractAddress, contractMethod, methodParameters, fee, ufText, used, save_to_bch)


# deploing new token
def deployToken():
    with open("token.txt", "r") as contract_file:
        newContractCode = contract_file.read()
    newContractCode = newContractCode.replace('_Token_Symbol_', 'NNN')
    newContractCode = newContractCode.replace('_Token_Name_', 'New Token')
    newContractCode = newContractCode.replace('_Token_decimal_', '3')
    newContractCode = newContractCode.replace('_Token_supply_', '1000')
    print(newContractCode)

    contract = client.prepareContract(newContractCode)
    if contract ==None:
        return
    fee = client.double_to_fee(0.5)
    uf_text = ''
    client.deployContract(Key, secureKey, fee, contract, uf_text)
# transfering token
def transferToken():
    contractAddress = '_TokenKey_'

    curContractMethods = client.getContractMethods(contractAddress)
    if curContractMethods == None or len(curContractMethods.methods) == 0:
        print('Contract ', contractAddress, ' has no methods')
        return 
    contractMethod = 'transfer'

    methodParameters = {'to':{'String':'_ReceiverKey_'}, 'amount':{'String':'_token_transfer_value_'}}

    fee = fee = client.double_to_fee(0.1)
    ufText = ''
    used = []
    save_to_bch = True
    client.executeContract(Key,secureKey, contractAddress, contractMethod, methodParameters, fee, ufText, used, save_to_bch)

# initializing api client
client = Client(port = 9013)

# initializing wallet Keys
Key = 'PublicKey'
secureKey = 'Privatekey'

defaultTransactionId = client.getAPI().TransactionId()
# creating new wallet Keys
newKeyPair = client.createKeyPair()
print(newKeyPair)
newKey = newKeyPair[1]
newSKey = newKeyPair[0]

checkWalletBalance()
getTransactionData()
getPoolData()
getContractData()
# sendTransaction()
# deployContract()
# executeContract()
# deployToken()
# transferToken()
