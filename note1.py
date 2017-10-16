# coding: utf-8
import hmac
import hashlib
import base64
import datetime
import time
import requests
def url_create(host="http://oos-bj2.ctyunapi.cn",bucket="",objectname="",subResource=""):
    myurl=host+"/"+bucketname+"/"+objectname+subResource
    return myurl
def urlshareobj(host="http://oos-bj2.ctyunapi.cn",headers={},httpverb="GET",date="",bucketname="",objectname="",subResource="",ValidTime=0):
    ak="58cc1dd2a52d5309a4f4"
    UnixTime=str(int(time.time())+ValidTime)
    authorization=authorize(headers,httpverb,UnixTime,bucketname,objectname,subResource) #Expires replace date
    print authorization
    begin=authorization.find(":")
    signature=authorization[begin+1:]
    ShareParams={"Expires":UnixTime,"AWSAccessKeyId":ak,"Signature":signature}
    myurl=host+"/"+bucketname+"/"+objectname
    #req=requests.PreparedRequest.prepare(method=httpverb,url=myurl,headers=headers,params=ShareParams)
    req=requests.PreparedRequest()
    req.prepare_url(myurl,ShareParams)
    return req.url
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
    if(bucketname!=""):
        StringToSign=httpverb+"\n"+Content_MD5+"\n"+Content_Type+"\n"+date+"\n"+CanonilizedAMZHeaders+"/"+bucketname+"/"+objectname+subResource
    else:
        StringToSign=httpverb+"\n"+Content_MD5+"\n"+Content_Type+"\n"+date+"\n"+CanonilizedAMZHeaders+"/"+subResource
    signature=hmac.new(sk,StringToSign,hashlib.sha1).digest()
    signature= base64.b64encode(signature)
    #signature=hmac.new(sk.encode('utf-8'),StringToSign.encode('utf-8'),hashlib.sha1).digest().encode('base64').rstrip()
    authorization="AWS "+ak+":"+signature
    return authorization


def httpput(files,headers,payload,host="http://oos-bj2.ctyunapi.cn",bucketname="",objectname="",subResource=""):
    date=datetime.datetime.utcnow().strftime('%a, %d %b %Y %X +0000')
    #use requests params add to url or directly add subResource to url
    #myurl=host+"/"+bucketname+"/"+objectname+subResource
    if(bucketname!=""):
        myurl=host+"/"+bucketname+"/"+objectname
    else:
        myurl=host+"/"
    authorization=authorize(headers,"PUT",date,bucketname,objectname,subResource)
    headers["Date"]=date
    headers["Authorization"]=authorization
    r=requests.put(myurl,headers=headers,files=files,params=payload)
    return r


def httpget(files,headers,payload,host="http://oos-bj2.ctyunapi.cn",bucketname="",objectname="",subResource=""):
    date=datetime.datetime.utcnow().strftime('%a, %d %b %Y %X +0000')
    #use requests params add to url or directly add subResource to url
    #myurl=host+"/"+bucketname+"/"+objectname+subResource
    if(bucketname!=""):
        myurl=host+"/"+bucketname+"/"+objectname
    else:
        myurl=host+"/"
    authorization=authorize(headers,"GET",date,bucketname,objectname,subResource)
    headers["Date"]=date
    headers["Authorization"]=authorization
    r=requests.get(myurl,headers=headers,files=files,params=payload)
    return r

def httpdelete(files,headers,payload,host="http://oos-bj2.ctyunapi.cn",bucketname="",objectname="",subResource=""):
    date=datetime.datetime.utcnow().strftime('%a, %d %b %Y %X +0000')
    #use requests params add to url or directly add subResource to url
    #myurl=host+"/"+bucketname+"/"+objectname+subResource
    if(bucketname!=""):
        myurl=host+"/"+bucketname+"/"+objectname
    else:
        myurl=host+"/"
    authorization=authorize(headers,"DELETE",date,bucketname,objectname,subResource)
    headers["Date"]=date
    headers["Authorization"]=authorization
    r=requests.delete(myurl,headers=headers,files=files,params=payload)
    return r

def httppost(files,headers,data,payload,host="http://oos-bj2-iam.ctyunapi.cn",bucketname="",objectname="",subResource=""):
    date=datetime.datetime.utcnow().strftime('%a, %d %b %Y %X +0000')
    #use requests params add to url or directly add subResource to url
    #myurl=host+"/"+bucketname+"/"+objectname+subResource
    if(bucketname!=""):
        myurl=host+"/"+bucketname+"/"+objectname
    else:
        myurl=host+"/"
    authorization=authorize(headers,"POST",date,bucketname,objectname,subResource)
    headers["Date"]=date
    headers["Authorization"]=authorization
    r=requests.post(myurl,data=data,headers=headers,files=files,params=payload)
    return r

    
#date=datetime.datetime.utcnow().strftime('%a, %d %b %Y %X +0000')
#使用字典需要考虑输入重复key值的情况,headers键值不能以空格开始
#headers={'Content-Type': 'bat','x-amz-acl': 'public-read-write'}
#headers["x-Amz-Meta-ReviewedBy"]="aane" 
#headers["X-Amz-Meta-ReviewedBy"]="jane"
#headers["X-Amz-Meta-FileChecksum"]="0x02661779"
#headers["X-Amz-Meta-ChecksumAlgorithm"]="crc32"
#headers={'Content-Type': 'bat'}
#payload={'response-content-encoding':'utf-8'}
bucketname="picture2"
#objectname="c.bat"
objectname="%E7%9B%AE%E6%A0%871.txt"
#subResource="?acl=public"
#subResource="?response-content-encoding=utf-8"
#payload={"acl":"public"}
path="C:/Users/admin/Desktop/a.bat"
#files={'file':open(path,'rb')}
files={}
#r=httpput(files,headers,payload,bucketname=bucketname,objectname=objectname,subResource=subResource)
#*******no.4:download
#r=httpget(files,headers,payload,bucketname=bucketname,objectname=objectname,subResource=subResource)
#print r,r.headers,r.text,r.url
#with open(u'D:/Program Files/git/test-test/目标.txt','wb') as code:
   # code.write(r.content)
#*******

#*******no.5:shareurl
"""
#headers={'Content-Type': 'bat'}
headers={}
subResource=""
payload=""
date=datetime.datetime.utcnow().strftime('%a, %d %b %Y %X +0000')

UrlShare=urlshareobj("http://oos-bj2.ctyunapi.cn",headers,"GET",date,bucketname,objectname,"",7*24*60*60)
r=requests.get(UrlShare,headers=headers,files=files,params=payload)
print r,r.headers,r.text,r.url
print UrlShare
"""
#*******
"""
#*******no.6 delete object
headers={}
subResource=""
payload={}
backetname="picture2"
objectname="a.bat"
r=httpdelete(files,headers,payload,bucketname=bucketname,objectname=objectname,subResource=subResource)
print r,r.headers,r.text,r.url

#*******
"""
"""
#*******no.7 create AK/SK(default)
headers={}
subResource=""
payload={"Action":"CreateAccessKey"}
data="Action=CreateAccessKey"
bucketname=""
objectname=""
r=httppost(files,headers,data,payload,bucketname=bucketname,objectname=objectname,subResource=subResource)
with open(u'D:/Program Files/git/test-test/aksk.txt','wb') as code:
    code.write(r.content)

print r,r.headers,r.text,r.url
#*******
"""
"""
#*******no.8 update AK/SK(Primary)
headers={"Content-Type":"string"}
subResource=""
payload={"Action":"UpdateAccessKey","AccessKeyId":"e8d1f88e8f37da5152b5","Status":"active","IsPrimary":"true"}
data=payload  #when data is dict type,headers must be user defined
bucketname=""
objectname=""
r=httppost(files,headers,data,payload,bucketname=bucketname,objectname=objectname,subResource=subResource)
print r,r.headers,r.text,r.url
#*******
"""
"""
#*******no.9 delete AK/SK
headers={}
subResource=""
payload={"Action":"DeleteAccessKey","AccessKeyId":"e58a86f6fd0bf1112e53"}
data="Action=DeleteAccessKey&AccessKeyId=e58a86f6fd0bf1112e53"
bucketname=""
objectname=""
r=httppost(files,headers,data,payload,bucketname=bucketname,objectname=objectname,subResource=subResource)
print r,r.headers,r.text,r.url
#*******
"""
"""
#*******no.10 delete bucket
headers={}
subResource=""
payload={}
bucketname="picture1"
objectname=""
r=httpdelete(files,headers,payload,bucketname=bucketname,objectname=objectname,subResource=subResource)
print r,r.headers,r.text,r.url
#*******
"""
#intermediate

#********no.1 multipart upload
    #initial
headers={}
subResource="?uploads"
payload={}
bucketname="picture2"
objectname="example1.txt"
r=httppost(files,headers,payload,bucketname=bucketname,objectname=objectname,subResource=subResource)
with open(u'D:/Program Files/git/test-test/multipart_upload.txt','wb') as code:
    code.write(r.content)
print r,r.headers,r.text,r.url
    #upload part
headers={"Content-Length":"","Content-MD5"}
subResource=""
payload={"partNumber":"1","uploadId":""}
files={'file':open(path,'rb')} #还需要分片
r=httpput(files,headers,payload,bucketname=bucketname,objectname=objectname,subResource=subResource)
print r,r.headers,r.text,r.url
    #complete upload
headers={"Content-Length":""}
payload={"uploadId":""}
subResource=""
#files={'file':open(path,'rb')}#xml data,need a try
#solution1
with open(path,'rb') as xmldata:
    r=httppost(files,headers,payload,xmldata,bucketname=bucketname,objectname=objectname,subResource=subResource)
print r,r.headers,r.text,r.url

'''
#solutin2
xmldata="""<CompleteMultipartUpload>
<Part>
<PartNumber>1</PartNumber>
<ETag>"a54357aff0632cce46d942af68356b38"</ETag>
</Part>
<Part>
<PartNumber>2</PartNumber>
<ETag>"0c78aef83f66abc1fa1e8477f296d394"</ETag>
</Part>
<Part>
<PartNumber>3</PartNumber>
<ETag>"acbd18db4cc2f85cedef654fccc4a4d8"</ETag>
</Part>
</CompleteMultipartUpload>"""
#********
'''
#********no.2 user-defined signature



    
