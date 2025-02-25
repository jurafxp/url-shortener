import redis
import base64
import hashlib
from . import config
import sys

class UrlShortener:
    def __init__(self):
        self.redis = redis.client.Redis(host=config.REDIS_HOST,
                                        port=config.REDIS_PORT,
                                        db=config.REDIS_DB)
        
    def shortcode(self, url):
        """
        Our main shortening function. The rationale here is that
        we are relying on the fact that for similarly sized inputs
        such as URLs the potential for collision in the 32 last bits
        of the MD5 hash is rather unlikely.
        
        The following things happen, in order:
        
        * compute the md5 digest of the given source
        * extract the lower 4 bytes
        * base64 encode the result
        * remove trailing padding if it exists
        
        Of course, should a collision happen, we will evict the previous
        key.
        
        """
        m = hashlib.md5()
        m.update(url.encode())
        return base64.b64encode(m.digest()[-4:]).decode().replace('=','').replace('/','_')

    def shorten(self, url, **kwargs):
        """
        The shortening workflow is very minimal. We try to
        set the redis key to the url value. We catch any
        exception in the process to properly report failures
        in the client
        """

        if "label" in kwargs:
            code = kwargs['label']
        else:
            code = self.shortcode(url)
        
        try:
            self.redis.set(config.REDIS_PREFIX + code, url)
            return {'success': True,
                    'url': url,
                    'code': code,
                    'shorturl': config.URL_PREFIX + code}
        except:
            return {'success': False}

    def lookup(self, code):
        """
        The same strategy is used for the lookup than for the
        shortening. Here a None reply will imply either an
        error or a wrong code.
        """
        try:
            return self.redis.get(config.REDIS_PREFIX + code)
        except:
            return None

    
    

