# coding: utf-8
import hmac
import hashlib
import base64
import datetime
import requests
def url_create(host="http://oos-bj2.ctyunapi.cn",bucket="",objectname=""):
    myurl=host+"/"+bucket+"/"+objectname
    return myurl
# x-amz-头标准化构建
def CanonilizedAMZHeaders_Create(headers):
    HeaderStringList=[]
    HeaderString=""
    for k in headers.keys():
        HeaderKey=k.rstrip().lower()
        if(HeaderKey.startswith("x-amz-")):
            HeaderValue=headers[k].lstrip().lower()
            count=0
            i=0
            while i<len(HeaderStringList):
                if(HeaderStringList[i].startswith(HeaderKey+":")):
                    HeaderStringList[i]+=","+HeaderValue
                    print HeaderStringList
                    count+=1
                i+=1
            if(count==0):
                HeaderStringList.append(HeaderKey+":"+HeaderValue)
    HeaderStringList.sort()
    for s in HeaderStringList:
        HeaderString+=s+"\n"
    print HeaderString
    
    return HeaderString
            
def authorize(headers={},httpverb="GET",date="",bucketname="",objectname="",subResource=""):
    ak="58cc1dd2a52d5309a4f4"
    sk="5ac5b36ef3a394a46a816b8d6e833badd30db7a8"
    #StringToSign=httpverb+"\n\n\n"+date+"\n/"+bucketname+"/"+objectname
    Content_Type=""
    if(headers.get("Content-Type")):
        Content_Type=headers.get("Content-Type")
    Content_MD5=""
    if(headers.get("Content-MD5")):
        Content_Type=headers.get("Content-MD5")
    CanonilizedAMZHeaders=CanonilizedAMZHeaders_Create(headers)
    StringToSign=httpverb+"\n"+Content_MD5+"\n"+Content_Type+"\n"+date+"\n"+CanonilizedAMZHeaders+"/"+bucketname+"/"+objectname+subResource
    signature=hmac.new(sk,StringToSign,hashlib.sha1).digest()
    signature= base64.b64encode(signature)
    #signature=hmac.new(sk.encode('utf-8'),StringToSign.encode('utf-8'),hashlib.sha1).digest().encode('base64').rstrip()
    authorization="AWS "+ak+":"+signature
    return authorization


def httpput(files,headers,payload,host="http://oos-bj2.ctyunapi.cn",bucketname="",objectname="",subResource=""):
    date=datetime.datetime.utcnow().strftime('%a, %d %b %Y %X +0000')
    myurl=host+"/"+bucketname+"/"+objectname+subResource
    authorization=authorize(headers,"PUT",date,bucketname,objectname,subResource)
    headers["Date"]=date
    headers["Authorization"]=authorization
    r=requests.put(myurl,headers=headers,files=files,params=payload)
    return r


def httpget(files,headers,payload,host="http://oos-bj2.ctyunapi.cn",bucketname="",objectname="",subResource=""):
    date=datetime.datetime.utcnow().strftime('%a, %d %b %Y %X +0000')
    #use requests params add to url or directly add subResource to url
    #myurl=host+"/"+bucketname+"/"+objectname+subResource
    myurl=host+"/"+bucketname+"/"+objectname
    authorization=authorize(headers,"GET",date,bucketname,objectname,subResource)
    headers["Date"]=date
    headers["Authorization"]=authorization
    r=requests.get(myurl,headers=headers,files=files,params=payload)
    return r

    
#date=datetime.datetime.utcnow().strftime('%a, %d %b %Y %X +0000')
#使用字典需要考虑输入重复key值的情况,headers键值不能以空格开始
#headers={'Content-Type': 'bat','x-amz-acl': 'public-read-write'}
#headers["x-Amz-Meta-ReviewedBy"]="aane" 
#headers["X-Amz-Meta-ReviewedBy"]="jane"
#headers["X-Amz-Meta-FileChecksum"]="0x02661779"
#headers["X-Amz-Meta-ChecksumAlgorithm"]="crc32"
headers={'Content-Type': 'bat'}
payload={'response-content-encoding':'utf-8'}
bucketname="picture2"
#objectname="c.bat"
objectname="%E7%9B%AE%E6%A0%871.txt"
#subResource="?acl=public"
subResource="?response-content-encoding=utf-8"
#payload={"acl":"public"}
path="C:/Users/admin/Desktop/a.bat"
#files={'file':open(path,'rb')}
files={}
#r=httpput(files,headers,payload,bucketname=bucketname,objectname=objectname,subResource=subResource)
r=httpget(files,headers,payload,bucketname=bucketname,objectname=objectname,subResource=subResource)
print r,r.headers,r.text,r.url
with open(u'D:/Program Files/git/test-test/目标.txt','wb') as code:
    code.write(r.content)





    
