import rsa,base64,requests
import json,uuid
from flask import Flask, jsonify, request, abort

app=Flask(__name__)
def sort_(obj):

    r_char = []
    stlist = sorted(obj)
    for i in stlist:
        if i == "sign" or i == "signType":
            continue
        if isinstance(obj[i],dict):
            r_char.append(i+'={'+str(sort_(obj[i]))+'}')
        else:
            r_char.append(i+ '=' +str(obj[i]))
    return "&".join(r_char)


def res_api(url,data):
    a = data
    bs4 = base64.b64encode(sort_(a).encode())

    with open(r'rsa_private_key.pem','r') as f:
        privkey = rsa.PrivateKey.load_pkcs1(f.read())

    result = rsa.sign(bs4, privkey,'SHA-256')

    a["sign"] = str(base64.b64encode(result),encoding="utf8")

    data=json.dumps(a)
    print(data)
    print(url)
    header = {"content-type":"application/json"}
    test_api = requests.post(url,data=data,headers=header)

    return test_api

def verif(test):
    res = test.json()
    s = test.json()['sign']
    s1 = base64.b64decode(s)
    s2 = base64.b64encode(sort_(res).encode())
    with open(r'','r') as f:
        pubk = rsa.PublicKey.load_pkcs1(f.read())
    result = rsa.verify(s1, s2, pubk)
@app.route('/3a',methods=['post','get'])
def start():
    data=request.get_data()
    data=json.loads(data)
    #outOrderNo=uuid.uuid1()
    #data['data']['outOrderNo']=str(outOrderNo)
    url=data['url']
    return res_api(url, data).text
if __name__ == "__main__":
    app.run(debug=True,host='192.168.2.224', port=5000)
