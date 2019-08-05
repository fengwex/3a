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
    a = {
        "appId": "CS0002",
        "randomString": "sdfsdfsdf",
        "requestTime": "2019-02-0114:32:00",
        # "data":"",
        # "signType":"RSA",
        "sign": "sign"
    }
    b = {
        "appId": "CS0002",
        "randomString": "sdfsdfsdf",
        "requestTime": "2019-02-0114:32:00",
        "data": {"orderType": "YRS", "bizNo": "132156497846167"},
        "sign": "sign"
    }
    c = {
        "appId": "CS0002",
        "randomString": "sdfsdfsdf",
        "requestTime": "2019-02-0114:32:00",
        "data": {"orderType": "THIRD_PARTY", "bizNo": "132156497846167"},
        "sign": "sign"
    }
    d = {
"appId":"CS0002",
"randomString":"你好%￥￥&&&*&*",
"requestTime":"2019-02-0114:32:00",
"data":{"outOrderNo":"111006746012110","payeeAccountNo":"6222021001090777002","payeeAccountName":"冯伟",
        "payeeAccountType":"123","amount":"5000","rechargeNo":"1234567891234567",
        "notifyUrl":"http://www.baidu.com/","remark":"僅僅是测试"},
"sign":"sign"
}
    # print(res_api("http://118.190.88.89:7115/query/balance", a).text)
    # test = res_api("http://118.190.88.89:7115/query/order", b)
    # print(res_api("http://118.190.88.89:7115/apply/order", d).text)


    # print(test.json())
