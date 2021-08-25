# -*- coding: utf-8 -*-
"""
Created on Wed May 26 17:18:12 2021

@author: asafd
"""

#Used python 3 to demonstrate cipher feedback mode
def StrtoInt(string):   #Converts String to integer
    result = list(string)
    for i in range(len(result)):
        result[i] = int(result[i])
    return result

def InttoStr(listA):    #Converts Integer to String
    result = ""
    for i in listA:
        result = result+str(i)
    return result

def XOR(listA,listB):   #XOR bytes
    result = []
    for i in range (len(listA)):
        x = (listA[i]+listB[i])%2
        result.append(x)
    return result

def XNOR(listA,listB):  #XNOR bytes
    result = []
    for i in range (len(listA)):
        x = (1+(listA[i]+listB[i]))%2
        result.append(x)
    return result

#default values
plaintext = "10101010"
IV = "11111111"
key = "11001122"

'''
FOR USER INPUT
plaintext = input("Enter Plaintext >>")
IV = input("Enter Initialization Value >>")
key = input("Enter Key >>")
'''

print(f'Plaintext :{plaintext}')
print(f'InitialVal:{IV}')
print(f'Key       :{key}')

#Converts String to Integer considering cases like  00011000 where the initial zeroes are also considered
plaintext = StrtoInt(plaintext)
IV = StrtoInt(IV)
key = StrtoInt(key)


'''
ENCRYPTION
CODE = PLAINTEXT XOR (IV XNOR KEY)
'''
code = XNOR(IV, key)
code = XOR(plaintext, code)
#code is cipher feedback

cipher = XNOR(code, key)
cipher = XOR(plaintext, cipher)
cipher = InttoStr(cipher)

print(f'Cipher:{cipher}')


'''
DECRYPTION
PLAINTEXT = CODE XOR (CIPHER XNOR KEY)
'''

cipher = StrtoInt(cipher)
plntxt = XNOR(cipher, key)
plntxt = XOR(code, plntxt)
plntxt = InttoStr(plntxt)
print(f'Decoded Message :{plntxt}')