# coding: utf-8
import hmac
import hashlib
import base64
import datetime
import requests
def url_create(host="http://oos-bj2.ctyunapi.cn",bucket="",objectname=""):
    myurl=host+"/"+bucket+"/"+objectname
    return myurl
def authorize(headers={},httpverb="GET",date="",bucketname="",objectname=""):
    ak="58cc1dd2a52d5309a4f4"
    sk="5ac5b36ef3a394a46a816b8d6e833badd30db7a8"
    #StringToSign=httpverb+"\n\n\n"+date+"\n/"+bucketname+"/"+objectname
    Content_Type=""
    if(headers.get("Content-Type")):
        Content_Type=headers.get("Content-Type")
    Content_MD5=""
    if(headers.get("Content-MD5")):
        Content_Type=headers.get("Content-MD5")
    
    StringToSign=httpverb+"\n"+Content_MD5+"\n"+Content_Type+"\n"+date+"\n/"+bucketname+"/"+objectname
    signature=hmac.new(sk,StringToSign,hashlib.sha1).digest()
    signature= base64.b64encode(signature)
    #signature=hmac.new(sk.encode('utf-8'),StringToSign.encode('utf-8'),hashlib.sha1).digest().encode('base64').rstrip()
    authorization="AWS "+ak+":"+signature
    return authorization


def httpput(files,headers,host="http://oos-bj2.ctyunapi.cn",bucketname="",objectname=""):
    date=datetime.datetime.utcnow().strftime('%a, %d %b %Y %X +0000')
    myurl=host+"/"+bucketname+"/"+objectname
    authorization=authorize(headers,"PUT",date,bucketname,objectname)
    headers["Date"]=date
    headers["Authorization"]=authorization
    r=requests.put(myurl,headers=headers,files=files)
    print r,r.text,r.url,r.headers
    
#date=datetime.datetime.utcnow().strftime('%a, %d %b %Y %X +0000')
headers={'Content-Type': 'bat'}
bucketname="picture2"
objectname="c.bat"
path="C:/Users/admin/Desktop/a.bat"
files={'file':open(path,'rb')}
#files={}
httpput(files,headers,bucketname=bucketname,objectname=objectname)






    
