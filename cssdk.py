# This file contains primary functions to get Credits node API main methods v.0.0

import time
import random
import json
import math
import hashlib

import base58check
import ed25519

from struct import *

import thriftpy2
from thriftpy2.rpc import make_client
from thriftpy2.protocol import TBinaryProtocol
from thriftpy2.transport import TMemoryBuffer

class TClient:
    def __init__(self, ip = "127.0.0.1", port = 9090, path = 'thrift-interface-definitions/api.thrift'):
        self.ip = ip
        self.port = port
        self.maxFractionRange = 1000000000000000000.0
        self.thrift_api_path = '' if path == '' else path
        self.api_thrift = thriftpy2.load(self.thrift_api_path, module_name="api_thrift")  

    def getAPI(self):
        return self.api_thrift

    def m_client(self):
        try:
            client = make_client(self.api_thrift.API, self.ip, self.port,  timeout=None)
        except:
            client = None
        return client
    
    def amountToFloat(self, aInteger, aFraction):
        return float(aInteger) + float(aFraction)/self.maxFractionRange

    def amountToFloat(self, amount):
        return float(amount.integral) + float(amount.fraction)/self.maxFractionRange
    
    def floatToamount(self, value):
        res = self.getAPI().general.Amount()
        res.integral = int(value)
        res.fraction = int((value - float(res.integral))*self.maxFractionRange)
        return res

    def setThriftInterfacePath(self, path):
        self.thrift_interface_path = path
    
    def getBalance(self, pKey):
        pKeyBytes = base58check.b58decode(pKey)
        client = self.m_client()
        if client == None:
            print('Can\'t initialize client')
            return None
        res = client.WalletBalanceGet(pKeyBytes) 
        return res.balance 
    
    def createKeyPair(self):
        kPair = ed25519.create_keypair()
        return [base58check.b58encode(kPair[0].sk_s).decode('UTF-8'), base58check.b58encode(kPair[1].vk_s).decode('UTF-8')]

    def double_to_fee(self, value):
        fee_comission = 0
        a = True
        if value < 0.:
            fee_comission += 32768
        else:
            fee_comission += (32768 if value < 0. else 0)
            value = math.fabs(value)
            expf = (0. if value == 0. else math.log10(value))
            expi = int(expf + 0.5 if expf >= 0. else expf - 0.5)
            value /= math.pow(10, expi)
            if value >= 1.:
                value *= 0.1
                expi += 1
            fee_comission += int(1024*(expi + 18))
            fee_comission += int(value * 1024)
        return fee_comission
    
    def normalizeCode(self, javaText):
        javaText = javaText.replace('\r', ' ').replace('\t', ' ').replace('{', ' {')
        while '  ' in javaText:
            javaText = javaText.replace('  ', ' ')
        return javaText

    def javaContractCompile(self, contract_body):
        client = self.m_client()
        if client == None:
            return None
        res = client.SmartContractCompile(contract_body)
        client.close()
        return res

    def parseUserFields(self, ufText, delegate_check, delegate, withdraw, date):
        ufBytes = bytearray(b'\x00')            
        ufBytes.extend(b'\x01')    # number of user fields
        sfBytes = bytearray(b'\x01')  # number of user fields
        tmpBytes = bytearray()
        sLen = 0
        mTrx = False
        if len(ufText) > 0: #adding string uf(1)
            ufBytes.extend(b'\x01\x00\x00\x00') # text user field
            ufBytes.extend(b'\x02')             # ufType = string 
            tm = bytearray(ufText.encode('utf-8'))
            tmpBytes.extend(tm)

        if len(tmpBytes):
            ufBytes.extend(len(tmpBytes).to_bytes(4, byteorder="little"))
            sfBytes.extend(len(tmpBytes).to_bytes(4, byteorder="little"))
            ufBytes.extend(tmpBytes)
            sfBytes.extend(tmpBytes)

        if delegate_check and not mTrx:
            ufBytes.extend(b'\x05\x00\x00\x00') # ufID delegate transaction
            ufBytes.extend(b'\x01')             # ufType = unsigned integer 64 bits
            if delegate:
                if date == 0:
                    val = 1
                    tmpBytes.extend(val.to_bytes(8, byteorder="little"))
                else:
                    if date < 3:
                        date += 2 #free first three values as keys (0, 1, 2)
                    tmpBytes.extend(date.to_bytes(8, byteorder="little"))
            elif withdraw:
                    val = 2
                    tmpBytes.extend(val.to_bytes(8, byteorder="little"))
            ufBytes.extend(tmpBytes)
            sfBytes.extend(tmpBytes)

        return [ufBytes, sfBytes]
    
    def getContractMethods(self, contractKey):
        client = self.m_client()
        pKeyBytes = base58check.b58decode(contractKey)   
        if client == None:
            return None     
        res = client.SmartContractDataGet(pKeyBytes)
        client.close()
        return res

    def getContractCode(self, contractKey):
        client = self.m_client()
        pKeyBytes = base58check.b58decode(contractKey)
        if client == None:
            return None
        res = client.SmartContractGet(pKeyBytes)
        client.close()
        return res.smartContract.smartContractDeploy.sourceCode

    def sendAmount(self, src, src_priv, dst, amount, m_fee):
        client = self.m_client()
        if client == None:
            return
        tr = self.getAPI().Transaction()

        tr.source = base58check.b58decode(src)
        w = client.WalletTransactionsCountGet(tr.source)
        lastInnerId = bytearray((w.lastTransactionInnerId + 1).to_bytes(6,'little'))
        tr.id = int.from_bytes(lastInnerId,byteorder='little', signed=False)
        tr.target = base58check.b58decode(dst)
        tr.amount = amount
        tr.balance = self.getAPI().general.Amount()
        tr.balance.integral = 0
        tr.balance.fraction = 0
        tr.currency = 1
        tr.fee = self.getAPI().AmountCommission()
        tr.fee.commission = m_fee
        userField_bytes = bytearray()
        sUserFields = bytearray()
        tr.userFields = bytes(userField_bytes)
        ms = int(0)
        ufNum1 = bytearray(b'\x00')

        if len(userField_bytes) == 0:
            sUserFields.append(0)
        sMap = '=6s32s32slqhb' + str(len(sUserFields)) + 's' #len(userField_bytes)
        serial_transaction_for_sign = pack(sMap,  #'=' - without alignment
                        lastInnerId,     #6s - 6 byte InnerID (char[] C Type)
                        tr.source,       #32s - 32 byte source public key (char[] C Type)
                        tr.target,       #32s - 32 byte target pyblic key (char[] C Type)
                        tr.amount.integral, #i - 4 byte integer(int C Type)
                        tr.amount.fraction, #q - 8 byte integer(long long C Type)
                        tr.fee.commission,  #h - 2 byte integer (short C Type)
                        tr.currency,        #b - 1 byte integer (signed char C Type)
                        sUserFields)            #b - 1 byte userfield_num

        #print('Serialized transaction: ', serial_transaction.hex())
        senderPKey =  base58check.b58decode(src_priv)
        signing_key = ed25519.SigningKey(senderPKey) # Create object for calulate signing
        tr.signature = signing_key.sign(serial_transaction_for_sign)
        try:
            res = client.TransactionFlow(tr)
        except: 
            print('API Message: ',
            'TimeOut during connection.') # 'The button clicked was "{}"'.format(event), 'The values are', values
            client.close()
            return 
        client.close()
        print('API Message: ', res.status.message if not('Success' in  res.status.message) else ('Success: id: '+ str(res.id.poolSeq) + '.' + str(res.id.index) + ', fee: ' + ''.join(str(res.fee.integral) + "." + str(res.fee.fraction).zfill(18))))
        return res

    def get_tokens(self, sKey):
        client = self.m_client()
        if client == None:
            return None
        res = client.TokenBalancesGet(sKey)
        client.close()
        return res
    
    def getUserContracts(self, pKey, offset, size):
        if offset > 100:
            offset = 100
        pKeyBytes = base58check.b58decode(pKey)
        client = self.m_client()
        if client == None:
            return None
        try:
            res = client.SmartContractsListGet(pKeyBytes, offset, size)
        except:
            print("Contract list get exception")
            res = None
        client.close()
        return res
    
    def getPool(self, seq):
        client = self.m_client()
        if client == None:
            return None
        res = client.PoolInfoGet(seq)
        client.close()
        return res

    def getTransaction(self, seq, idx):
        tId = self.api_thrift.TransactionId()
        tId.poolSeq = seq
        tId.index = idx
        client = self.m_client()
        if client != None:
            res = client.TransactionGet(tId)
            client.close()
        else:
            res = None
        return res

    def getWalletData(self, addr):
        client = self.m_client()
        if client != None:
            res = client.WalletDataGet(addr)
            client.close()
        else:
            res = None
        return res

    def getTransactions(self, pKey, offset, size):
        pKeyBytes = base58check.b58decode(pKey)
        if size > 100:
            size = 100
        client = self.m_client()
        if client == None:
            return None
        res = client.TransactionsGet(pKeyBytes, offset ,size)
        client.close()
        return res

    def getContractData(self, sample):
        client = self.m_client()
        if client == None:
            return None
        addr = base58check.b58decode(sample)
        try:
            res = client.SmartContractDataGet(addr)
        except:
            print("Could not get contract data")
            res = None
        client.close()
        return res

    def serializeMethods(self, methods):
        res = bytearray()
        if methods != None and len(methods) > 0: 
            res.extend(bytes(len(methods).to_bytes(2, byteorder="little")))
            for a in methods:
                res.extend(bytes(a.returnType))
                res.extend(bytes(a.name))
                res.extend(bytes(len(a.arguments).to_bytes(2, byteorder="little")))
                res.extend(bytes(len(a.signature).to_bytes(8, byteorder="little")))
                # res.extend(bytes(a.name.encode('utf-8')))
        return res

    def createContractAddress(self, source, tId, contract):
        tmpBytes = bytearray()
        tmpBytes.extend(source)
        tmpBytes.extend(tId)
        for a in contract.smartContractDeploy.byteCodeObjects:
            tmpBytes.extend(a.byteCode)
        res = hashlib.blake2s()
        res.update(tmpBytes)
        return res.digest()

    def prepareContract(self, source_code):
        contract = self.getAPI().SmartContractInvocation()
        contract.smartContractDeploy = self.getAPI().SmartContractDeploy()
        normalizedCode = self.normalizeCode(source_code)
        compiledCode = self.javaContractCompile(normalizedCode)
        if(compiledCode != None):
            if "Success" not in compiledCode.status.message:
                print('Compile info: ',compiledCode.status.message)
                return None
            if len(compiledCode.byteCodeObjects) == 0:
                print('Compile info: ','Contract can\'t be build correctly. Check it more careflly')
                return None
            else:
                contract.smartContractDeploy.byteCodeObjects = compiledCode.byteCodeObjects
                contract.smartContractDeploy.sourceCode = normalizedCode
                contract.smartContractDeploy.lang = 0
                contract.smartContractDeploy.methods = compiledCode.methods
                print('Compile info: ','Contract is built Sucessfully. Ready for deploy') 
        return contract

    def deployContract(self, src, src_priv, m_fee, contract, uf_text):
        sUserFields = bytearray()
        client = self.m_client()
        if client == None:
            return
        tr = self.getAPI().Transaction()

        tr.smartContract = contract

        tr.source = base58check.b58decode(src)
        w = client.WalletTransactionsCountGet(tr.source)
        lastInnerId = bytearray((w.lastTransactionInnerId + 1).to_bytes(6,'little'))
        tr.id = int.from_bytes(lastInnerId,byteorder='little', signed=False)
        tr.target = self.createContractAddress(tr.source, lastInnerId, contract)
        tr.amount = self.getAPI().general.Amount()
        tr.amount.integral = 0
        tr.amount.fraction = 0
        tr.balance = self.getAPI().general.Amount()
        tr.balance.integral = 0
        tr.balance.fraction = 0
        tr.currency = 1
        tr.fee = self.getAPI().AmountCommission()
        tr.fee.commission = m_fee
        tr.userFields = uf_text
        userField_bytes = bytearray()
        ms = int(0)
        ufNum1 = bytearray(b'\x01') # if contract.smartContractDeploy.methods == None else bytearray(b'\x03')
        if len(userField_bytes) == 0:
            sUserFields.append(0)
        codeLength = len(contract.smartContractDeploy.byteCodeObjects[0].byteCode)
        codeNameLength = len(contract.smartContractDeploy.byteCodeObjects[0].name)
        scriptLength = len(contract.smartContractDeploy.sourceCode)
        ufLength = codeLength + codeNameLength + scriptLength
        # metBytes = self.serializeMethods(contract.smartContractDeploy.methods)
    
        contract._tspec['method'] = (True, 11)
        contract._tspec['params'] = (True, 15)
        contract._tspec['forgetNewState'] = (True, 2)
        contract._tspec['smartContractDeploy'] = (True, 12)
        contract._tspec['usedContracts'] = (True, (15,11))
        contract._tspec['version'] = (True, 6)
        contract.smartContractDeploy._tspec['byteObjects'] = (True, 15)
        contract.smartContractDeploy._tspec['hashState'] = (True, 11)
        contract.smartContractDeploy._tspec['sourceCode'] = (True, 11)
        contract.smartContractDeploy._tspec['tokenStandard'] = (True, 8)
        contract.smartContractDeploy._tspec['lang'] = (True, 8)
        contract.smartContractDeploy._tspec['methods'] = (True, 8)
        contract.smartContractDeploy.hashState = ""
        contract.smartContractDeploy.tokenStandard = 0
        contract.method = ""
        contract.params = []
        contract.usedContracts = []
        contract.forgetNewState = False

        transportOut = TMemoryBuffer()
        protocolOut = TBinaryProtocol(transportOut)
        contract.write(protocolOut)
        scBytes = transportOut.getvalue()
        langVal = int(contract.smartContractDeploy.lang)
        sMap = '=6s32s32slqhb1s4s' + str(len(scBytes)) +'s'#4s' + str(len(metBytes)) + 's8s' 4s' + str(scriptLength) + 's4s' + str(codeNameLength) + 's4s' + str(codeLength) + 's' #len(userField_bytes)
        serial_transaction_for_sign = pack(sMap,  #'=' - without alignment
                            lastInnerId,     #6s - 6 byte InnerID (char[] C Type)
                            tr.source,       #32s - 32 byte source public key (char[] C Type)
                            tr.target,       #32s - 32 byte target pyblic key (char[] C Type)
                            tr.amount.integral, #i - 4 byte integer(int C Type)
                            tr.amount.fraction, #q - 8 byte integer(long long C Type)
                            tr.fee.commission,  #h - 2 byte integer (short C Type)
                            tr.currency,        #b - 1 byte integer (signed char C Type)
                            ufNum1,
                            bytes(len(scBytes).to_bytes(4, byteorder="little")),
                            scBytes

                            # bytes(len(metBytes).to_bytes(4, byteorder="little")),
                            # metBytes,
                            # bytes(langVal.to_bytes(8, byteorder="little"))

                            # bytes(scriptLength.to_bytes(4, byteorder="big")),
                            # bytes(contract.smartContractDeploy.sourceCode.encode('utf-8')),
                            # bytes(codeNameLength.to_bytes(4, byteorder="big")), #code name length
                            # bytes(contract.smartContractDeploy.byteCodeObjects[0].name.encode('utf-8')), #code name
                            # bytes(codeLength.to_bytes(4, byteorder="big")), #code length
                            # bytes(contract.smartContractDeploy.byteCodeObjects[0].byteCode) #b - 1 byte userfield_num

                            )            
                        
        st = serial_transaction_for_sign.hex().upper()
        print('Serialized transaction: ', st)
        senderPKey =  base58check.b58decode(src_priv)
        signing_key = ed25519.SigningKey(senderPKey) # Create object for calulate signing
        tr.signature = signing_key.sign(serial_transaction_for_sign)
        try:
            res = client.TransactionFlow(tr)
        except: 
            print('API Message: ',
            'TimeOut during connection.') # 'The button clicked was "{}"'.format(event), 'The values are', values
            client.close()
            return 
        client.close()
        msg = ''
        try: 
            ls = res.status.message.split(' ')
            msg += ls[0] + ' ' + str(base58check.b58encode(tr.target)).split('\'')[1]
            if(ls[0] == 'Success:'):
                msg += ' deployed'
            else:
                msg += ' not deployed'
        except:
            print('Error: ','Some errors')
        
    
        print('API Message: ', msg)


        return [res, str(base58check.b58encode(tr.target)).split('\'')[1]]
    
    def executeContract(self, src, src_priv, trg, contractMethod, methodParameters, m_fee, uf_text, used_contracts, save_to_bc):
        sUserFields = bytearray()
        client = self.m_client()
        if client == None:
            return
        tr = self.getAPI().Transaction()
        tr.source = base58check.b58decode(src)
        w = client.WalletTransactionsCountGet(tr.source)
        lastInnerId = bytearray((w.lastTransactionInnerId + 1).to_bytes(6,'little'))
        tr.id = int.from_bytes(lastInnerId,byteorder='little', signed=False)
        tr.target = base58check.b58decode(trg)
        tr.amount = self.getAPI().general.Amount()
        tr.amount.integral = 0
        tr.amount.fraction = 0
        tr.balance = self.getAPI().general.Amount()
        tr.balance.integral = 0
        tr.balance.fraction = 0
        tr.currency = 1
        tr.fee = self.getAPI().AmountCommission()
        tr.fee.commission = m_fee
        tr.userFields = uf_text
        tr.smartContract = self.getAPI().SmartContractInvocation()
        tr.smartContract.method = contractMethod
        tr.smartContract.forgetNewState = not(save_to_bc)
        tr.smartContract.params = []
        tr.smartContract.usedContracts = []
        tr.smartContract.version = 1
        tr.smartContract._tspec['method'] = (True, 11)
        tr.smartContract._tspec['params'] = (True, 15)
        tr.smartContract._tspec['forgetNewState'] = (True, 2)
        tr.smartContract._tspec['usedContracts'] = (True, (15,11))
        tr.smartContract._tspec['version'] = (True, 6)
        ufNum1 = bytearray(b'\x01')
        paramsLen = len(methodParameters)

        for a in methodParameters:
            for b in methodParameters[a]:
                r = self.getAPI().general.Variant()
                if b == 'String':
                    r.v_string = methodParameters[a][b]
                if b == 'int':
                    r.v_int = methodParameters[a][b]
                if b == 'double':
                    r.v_double = methodParameters[a][b]
                tr.smartContract.params.append(r)
            paramsLen -= 1
            if paramsLen == 0:
                break

        if uf_text == '':
            ufNum1.extend(bytearray(b'\x01'))
        else:
            ufNum1.extend(bytearray(b'\x02'))
        csBytes = bytearray()
        csBytes.extend(b'\x0b\x00\x01')
        if contractMethod == '':
            csBytes.extend(b'\x00\x00\x00\x00')
        else:
            csBytes.extend(len(contractMethod).to_bytes(4, byteorder="big")) #VVV
            csBytes.extend(bytearray(contractMethod.encode('utf-8')))

        # contract parameters    
        if len(tr.smartContract.params) == 0:
            csBytes.extend(b'\x0f\x00\x02\x0c\x00\x00\x00\x00')
        else:
            csBytes.extend(b'\x0f\x00\x02\x0c')
            csBytes.extend(len(tr.smartContract.params).to_bytes(4, byteorder="big"))
            for a in methodParameters:
                if a != 'status_':
                    for aa in methodParameters[a]:
                        if(aa == 'String'):
                            csBytes.extend(b'\x0b\x00\x11')
                            csBytes.extend(len(methodParameters[a][aa]).to_bytes(4, byteorder="big"))
                            csBytes.extend(bytearray(methodParameters[a][aa].encode('utf-8')))
                            csBytes.extend(b'\x00')
                        elif(aa == 'double'):
                            csBytes.extend(b'\x04\x00\x0f')
                            csBytes.extend(bytearray(pack("d",(methodParameters[a][aa]))))
                            csBytes.extend(b'\x00')
                        elif(aa== 'int'):
                            csBytes.extend(b'\x08\x00\x09')
                            csBytes.extend(bytearray((methodParameters[a][aa]).to_bytes(4, byteorder="big")))
                            csBytes.extend(b'\x00')
                        elif(aa == 'boolean'):
                            if(methodParameters[a][aa]):
                                csBytes.extend(b'\x02\x00\x03\x01\x00')
                            else:
                                csBytes.extend(b'\x02\x00\x03\x00\x00')
        # used contracts
        if len(used_contracts) == 0:
            csBytes.extend(b'\x0f\x00\x03\x0b\x00\x00\x00\x00')
        else:
            csBytes.extend(b'\x0f\x00\x03\x0c')
            csBytes.extend(len(used_contracts).to_bytes(4, byteorder="little"))

        # forget new state
        if save_to_bc:
            csBytes.extend(b'\x02\x00\x04\x00')
        else:
            csBytes.extend(b'\x02\x00\x04\x01')

        csBytes.extend(b'\x06\x00\x06')
        csBytes.extend(bytearray(tr.smartContract.version.to_bytes(2, byteorder="big"))) #VVV
        csBytes.extend(b'\x00')

        sMap = '=6s32s32slqhb1s4s' + str(len(csBytes)) +'s' #4s' + str(scriptLength) + 's4s' + str(codeNameLength) + 's4s' + str(codeLength) + 's' #len(userField_bytes)
        serial_transaction_for_sign = pack(sMap,  #'=' - without alignment
                            lastInnerId,     #6s - 6 byte InnerID (char[] C Type)
                            tr.source,       #32s - 32 byte source public key (char[] C Type)
                            tr.target,       #32s - 32 byte target pyblic key (char[] C Type)
                            tr.amount.integral, #i - 4 byte integer(int C Type)
                            tr.amount.fraction, #q - 8 byte integer(long long C Type)
                            tr.fee.commission,  #h - 2 byte integer (short C Type)
                            tr.currency,        #b - 1 byte integer (signed char C Type)
                            ufNum1,
                            bytes(len(csBytes).to_bytes(4, byteorder="little")),
                            csBytes
        )
        # print('Serialized trx: ', serial_transaction_for_sign.hex().upper())
        senderPKey = base58check.b58decode(src_priv)
        signingKey = ed25519.SigningKey(senderPKey) # Create object for calulate signing
        tr.signature = signingKey.sign(serial_transaction_for_sign)
        try:
            res = client.TransactionFlow(tr)
        except: 
            print('API Message: ',
            'TimeOut during connection.') # 'The button clicked was "{}"'.format(event), 'The values are', values
            client.close()
            return 
        client.close()
        msg = ''
        try: 
            ls = res.status.message.strip()
            msg += (ls if len(ls) > 0 else str(base58check.b58encode(tr.target)).split('\'')[1] + ' executed')
            if res.smart_contract_result != None:
                msg += ' Result: ' + str(self.getVariant(res.smart_contract_result))
        except:
            print('Error: ','Some errors')
        
        print('API Message: ', msg)
        print(msg)
        return res

    def getVariant(self, variant):
        if variant.v_int != None:
            return variant.v_int
        if variant.v_string != None:
            return variant.v_string


class WClient:
    def __init__(self, url):
        print('Client not implemented')
        # self.url = url
