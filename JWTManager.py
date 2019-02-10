import jwt
import uuid
import secrets
import time,datetime
import abc

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

class MyJWT(abc.ABC):
    _timeout = 3
    __algorithm=""
    def __init__(self,algo):
        self.__algorithm=algo
    @abc.abstractmethod
    def _getKey(self):
        pass
    @abc.abstractmethod
    def _getVerifyKey(self):
        pass

    def __call__(self,Username,Password):
	    # Authentication Check
        #Check if username password match in SQL and gets the role
        Exist = True
        Role = "Admin"
		#=========================================================
        if (Username and Password and Role and Exist):
            json = {"Username":Username,
              "Role":Role,
              "Expiration":time.mktime(datetime.datetime.today().timetuple())+self._timeout,
              "Int":secrets.randbelow(199999999999)}
            if (self._getKey()):
                Token = jwt.encode(json,self._getKey(),algorithm=self.__algorithm)
                return(Token)
				
    def Authorization(self,Token):
        try:
            decodedJwt = jwt.decode(Token,self._getVerifyKey().rstrip(), algorithms=self.__algorithm)
        except:
            return False
        if (decodedJwt["Expiration"] > time.mktime(datetime.datetime.today().timetuple())):
            return True
        return False

class JWTSymetricKey(MyJWT):

    __secret=""
	
    def __init__(self):
        super().__init__('HS256')
        for i in range (0,100):
            self.__secret = self.__secret+str(uuid.uuid4()) + (secrets.token_urlsafe())
        #print(self.__secret)

    def _getKey(self):
        return self.__secret
		
    def _getVerifyKey(self):
        return self._getKey()

class JWTRSA(MyJWT):

    __private_key=""
    public_key=""
	
    def __init__(self):
        super().__init__('RS256')
        key = rsa.generate_private_key(
            backend=default_backend(),
            public_exponent=65537,
            key_size=4096 #8192
        )
        self.__private_key = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
            )
        self.public_key = key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH
            )
        #print(self.__private_key)
        #print(self.public_key)

    def _getKey(self):
        return self.__private_key
		
    def _getVerifyKey(self):
        return self.public_key
		
class JWTManager():
    __JwtInstance = None
    def RSA(self):
        self.__JwtInstance = JWTRSA()

    def Symetric(self):
        self.__JwtInstance = JWTSymetricKey()

    def Authentication(self,Username,Password):
        return self.__JwtInstance(Username,Password).decode("utf-8")
	
    def Authorization(self,Token):
        return self.__JwtInstance.Authorization(Token)

    def Example(self):
        Example(self.__JwtInstance)
	
def Example(JWTInstance):
    print("======= JWT example of:",JWTInstance.__class__.__name__," =======")
    NewToken = JWTInstance("Yarden","AKGHJKeesfe123#")
    print("New Token was created:",NewToken.decode("utf-8"))
    time.sleep(1)
    print('Is token valid?',str(JWTInstance.Authorization(NewToken)))
    time.sleep(3)
    print('Is token valid?',str(JWTInstance.Authorization(NewToken)))
    print("Creating same token with invalid sign")
    Unauthenticated = JWTRSA()
    unauth_token = Unauthenticated("Yarden","AKGHJKeesfe123#")
    print('Is other token valid?',str(JWTInstance.Authorization(unauth_token)))
    print("==============================================")

def main():
    jwtman = JWTManager()
    jwtman.RSA()
    #jwtman.Example()
    #jwtman.Symetric()
    #jwtman.Example()
    print(jwtman.Authentication("Yarden","aLGJskalk23@!"))
    
    

if __name__ == '__main__':
    main()