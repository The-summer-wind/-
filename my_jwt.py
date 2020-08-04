import json
import base64
import time
import hmac
import copy

class Jwt():

    def __init__(self):
        pass

    @staticmethod
    def encode(payload, key, exp=300):
        #生成jwt token

        #init header
        header = {'alg':'HS256', 'typ':'JWT'}
        #separators 参数为元祖,元祖第一项为 键值对之间拿什么符号分隔, 第二项 键与值之间拿什么符号分隔
        #sort_keys=True 保证输出的json串中key具备有序性
        header_json = json.dumps(header, separators=(',',':'), sort_keys=True)
        header_bs = Jwt.b64encode(header_json.encode())

        # init payload
        payload_data = copy.deepcopy(payload)
        payload_data['exp'] = time.time() + int(exp)
        payload_json = json.dumps(payload_data, separators=(',',':'), sort_keys=True)
        payload_bs = Jwt.b64encode(payload_json.encode())

        #init sign
        hm = hmac.new(key.encode(), header_bs + b'.' + payload_bs, digestmod='SHA256')
        hm_bs = Jwt.b64encode(hm.digest())

        return header_bs + b'.' + payload_bs + b'.' + hm_bs

    @staticmethod
    def decode(token, key):
        #  注意 当初替换掉的空格, 要想办法补回来

        # 1)校验签名, 以生成token第三部分的流程 再次计算一次 sign; 比对两者的值
        #   校验失败 raise
        header_bs, payload_bs, sign = token.split(b'.')
        hm = hmac.new(key.encode(), header_bs + b'.' + payload_bs, digestmod='SHA256')

        if sign != Jwt.b64encode(hm.digest()):
            raise

        #解析payload
        #b64 -> json字符串  -> 补全丢掉的等号
        payload_js = Jwt.b64decode(payload_bs)
        #json字符串 -> dict
        payload = json.loads(payload_js)
        # 2) exp -> 检查是否已经过期
        #   校验失败 raise
        exp = payload['exp']
        now = time.time()
        if now > exp:
            #过期
            raise
        # 最终 返回 payload 部分的 字典
        return payload


    @staticmethod
    def b64decode(b_s):
        rem = len(b_s) % 4
        if rem > 0:
            #补等号
            b_s += b'=' * (4-rem)
        return base64.urlsafe_b64decode(b_s)

    @staticmethod
    def b64encode(j_s):
        return base64.urlsafe_b64encode(j_s).replace(b'=',b'')






if __name__ == '__main__':

    s = Jwt.encode({'username':'guoxiaonao'},'abcdef', 3)

    time.sleep(4)

    #print(s)
    print(Jwt.decode(s, 'abcdef'))

    #b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTM0MTI2NDMuNTIyNDYyMSwidXNlcm5hbWUiOiJndW94aWFvbmFvIn0=.3ESGnbTku5xVuARXGXs4TvYP5R_gaUwpxqJdoStKdSo='

    #b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTM0MTM1NzcuMTgyNDA3LCJ1c2VybmFtZSI6Imd1b3hpYW9uYW8ifQ.8DCBVc5kI2sDWJzhwAsiB8ddAz4Xc5mo_v3zkc478Pk'

    #8DCBVc5kI2sDWJzhwAsiB8ddAz4Xc5mo_v3zkc478Pk

















