# -*- coding: utf-8 -*-
"""
Created on Tue Jun  1 13:04:48 2021

@author: Swati
"""

import os
import json
from datetime import datetime

def Create_Rule(fileloc):
    rule = {"name":None,"description":None,"group":[],"packets":{},"asserts":None,"threshold":None,"report":None}#the dictionary
    with open(fileloc,'r') as f:
        lines=f.readlines()
    count=0
    for line in lines:
        count+=1
    rule['name']=lines[0][6:-1]
    #print(rule['name'])
    rule['description']=lines[1][13:-1]
    #print(rule['description'])
    for i in range(count):
        if('packets' in lines[i]):
            p=i
            break
    #the group field continues till p-1
    k=0
    for i in range(3,p):
        rule['group'].append(lines[i][0:-1])
        k+=1
    #print(rule['group'])
    for i in range(count):
        if('asserts' in lines[i]):
            m=i
            break
    #the packets field continues till m-1
    for i in range(p+1,m):
        set = lines[i]
        x = set.split(':',1)
        rule['packets'][x[0]]=x[1][0:-1]
    #print(rule['packets'])
    rule['asserts']=lines[m+1][0:-1]
    #print(rule['asserts'])
    rule['threshold']=int(lines[m+2][11:-1])
    #print(rule['threshold'])
    rule['report']=lines[m+3][8:-1]
    #print(rule['report'])
    return(rule)
   
    
    
def readJson(filename):
    with open(filename) as json_file:
        data = json.load(json_file)
    return data



def arpPoison(Rules,packets):
    cond = list(Rules['packets'].values())
    ca = 0
    cda = 0
    for i in packets:
        p = i['_source']['layers']
        if cond[0] in p:
            ca+=1
            if(list(p.keys())[-1]!=cond[0]):
                cda+=1

    if(cda>(ca*0.5)):
        return True
    else:
        return False
 
    
    
def arpStorm(Rules, Packets):
    cond = list(Rules['packets'].values())
    ca = 0
    cab = 0
    condab = []
    condab.append(cond[1][8:15])
    condab.append(cond[1][17:])
    for i in Packets:
        p = i['_source']['layers']
        if cond[0] in p:
            k = p['eth']
            if(k[condab[0]]==condab[1]):
                cab+=1
            else:
                ca+=1
    
    
    if(cab>0.5*ca):
        return True
    else:
        return False




def synFlood(Rules,packets):
    ns=0
    nsa=0
    cond = list(Rules['packets'].values())
    rule1f=cond[0][0:13]
    rule1v=int(cond[0][15:])
    rule2f=cond[1][0:13]
    rule2v=int(cond[1][15:])
    for i in packets:
        temp = i['_source']['layers']
        if "tcp" in temp:
            temp=temp['tcp']['tcp.flags_tree']
            if int(temp[rule1f])==rule1v:
                ns+=1
            if int(temp[rule2f])==rule2v:
                nsa+=1

    if (ns>0) and (nsa>0) and nsa>(ns):
        return True
    else:
        return False
    



def generateReport(file,rule):
    file.write('Type of Attack:')
    file.write(rule['name'])
    file.write('\n')
    file.write('Description:')
    file.write(rule['description'])
    file.write('\n')
    file.write('Conditions:\n')
    #print(list(rule['packets'].keys()))
    for key,value in rule['packets'].items():
        file.write(key+':'+value)
        file.write(' ')
    file.write('\n')
    file.write('#'*30)
    file.write('\n\n')
    return


#Automating Network Security Analysis at Packet level by using Rule-based Engine

if __name__ == "__main__":
    Rules=[]
    path1 = 'rules'
    path2 = 'testfiles'
    
    for file in os.listdir(path1):
        filename = os.path.join(path1,file)
        rule = Create_Rule(filename)
        Rules.append(rule)
    
    print('**********Welcome to the Network Attack Detection System**********')
    print('We have curated rules to detect important network attacks')
    print('You can detect for other attacks by adding the rules.txt file in rules folder, and formulating a function in ism_project.py file')
    
    currentime = datetime.now()
    reportname = currentime.strftime("%d-%m-%Y_%H-%M-%S")
    
    reportfile = open('report/'+reportname+'.txt','a')
    
    while True:
        print('\nThe following attack detections are possible:')
        i=0
        for file in os.listdir(path1):
            attackname = file.partition('.')
            i+=1
            print(str(i)+'.'+attackname[0])
        
        print("Enter the number for the type of attack you want to detect(or -1 for exit):")
        t = int(input())
        if(t==-1):
            print("Exiting the console")
            print("Your report for the current session is stored in report folder")
            break
        
        
        print("Enter the JSON file name")
        checkfile = input()
        checkfilepath = os.path.join(path2,checkfile+'.json')
        JsonPackets = []
        JsonPackets = readJson(checkfilepath)
        
        if(t==1):
            val = arpPoison(Rules[t-1],JsonPackets)
            if(val == True):
                print('\nARP Poisoning attack detected!!!!!!!')
                generateReport(reportfile, Rules[t-1])
            else:
                print('\nARP poisoning attack is not detected')
        elif(t==2):
            val = arpStorm(Rules[t-1],JsonPackets)
            if(val == True):
                print('\nARP Storm attack detected!!!!!!!')
                generateReport(reportfile, Rules[t-1])
            else:
                print('\nARP Storm attack is not detected')
        elif(t==3):
            val = synFlood(Rules[t-1],JsonPackets)
            if(val == True):
                print('\nSYN Flood attack detected!!!!!!!')
                generateReport(reportfile, Rules[t-1])
            else:
                print('\nSyn Flood attack is not detected')
        else:
            print("\nPlease Enter a Valid Attack")
    
    reportfile.close()