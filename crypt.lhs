
> import Data.Word
> import qualified Data.ByteString.Base64 as Base64
> import qualified Data.ByteString as BS
> import Data.HMAC (hmac_sha1)
> import PBKDF2Fixed

> char2word8 :: [Char] -> [Word8]
> char2word8 = map (toEnum.fromEnum)

> rawSalt :: [Word8]
> rawSalt = [0x0d, 0x02, 0x17, 0x25, 0x4d, 0x37, 0xf2, 0xee, 0x0f, 0xec, 0x57, 0x6c, 0xb8, 0x54, 0xd8, 0xff]

> rawPass :: [Word8]
> rawPass = char2word8 "password"

> pass = Password rawPass
> salt = Salt rawSalt

> bar = Base64.encode . BS.pack $ checksum where 
>   HashedPass checksum = atlassian_pbkdf2_sha pass salt

iterations: 10000
output size: 32

> atlassian_pbkdf2_sha = pbkdf2' (hmac_sha1, 20) 10000 32

 import qualified Data.Digest.SHA1 as SHA1
 import Numeric
 import Data.Bits
 import Data.Digest.Pure.SHA
 import Codec.Utils (toTwosComp)

> test = pbkdf2' (hmac_sha1, 20) 1 20 pass testSalt where
>   testSalt = (Salt . char2word8 $ "salt")

> test2 = pbkdf2' (hmac_sha1, 20) 2 20 pass testSalt where
>   testSalt = (Salt . char2word8 $ "salt")

> test3 = pbkdf2' (hmac_sha1, 20) 4096 25 pass testSalt where
>   testSalt = (Salt . char2word8 $ "saltSALTsaltSALTsaltSALTsaltSALTsalt")
>   testPass = (Password . char2word8 $ "passwordPASSWORDpassword")

change logical or to concatenation..

 test = pbkdf2' (sha512, 20) 1 20 pass testSalt where
   testSalt = (Salt . char2word8 $ "salt")



BS.unpack . handle . Base64.decode . BS.pack . char2word8 $ rawSalt

salt in hexadecimal octects...

 foo :: String -> [Word8]
 foo = map (fromInteger . handle . readHex . return ) where
   handle r = case r of
     [(x, "")] -> x
     _         -> error "bad parse"

 handle r = case r of 
   Left msg -> error msg
   Right x  -> x

a sha1 digest is 20 bytes 

before I forget, both hmac_sha1 and utils.get_prf("hmac-sha1") produce the same results.

proof:

$ hmac_sha1("password", bytes("salt"))
'\xa2\xbc\x8e\r\x99vB\xc2]\xabA\x990\xb15\x83(\xbb\x93\xb9'
$ hex(162)
'0xa2'
$ hex(188)
'0xbc'

*Main> hmac_sha1 (char2word8 "password")  (char2word8 "salt")
[162,188,142,13,153,118,66,194,93,171,65,153,48,177,53,131,40,187,147,185]






The salt needs to be 16 bytes

 atlassian_pbkdf2_sha = pbkdf2' (hmac_sha1, 20) 10000 32

    this is the code that calculates the digest in the passlib library...
    it seems straightforward, but what are those translate things?   

    digest_const = getattr(hashlib, digest, None)
    if not digest_const:
        raise ValueError("unknown hash algorithm: %r" % (digest,))
    tmp = digest_const()
    block_size = tmp.block_size
    assert block_size >= 16, "unacceptably low block size"
    digest_size = tmp.digest_size
    del tmp
    def prf(key, msg):
        # simplified version of stdlib's hmac module
        if len(key) > block_size:
            key = digest_const(key).digest()
        key += _BNULL * (block_size - len(key))
        tmp = digest_const(key.translate(_trans_36) + msg).digest()
        return digest_const(key.translate(_trans_5C) + tmp).digest()
    tag_wrapper(prf)
    return prf, digest_size


well, this sha1 is working at least

remember when I tried to reimpliment hmac? yeah i don't either...

 prf key msg = r  where
   key'  = if length(key) > block_size then sha1 key else key
   key'' = key' ++ (take (block_size - length(key')) (repeat 0xffffffff))
   tmp   = sha1 ((map (\x -> xor x 0x36) key) ++ msg)
   r     = sha1 ((map (\x -> xor x 0x5C) key) ++ tmp)
   block_size = 64

 sha1 = word160ToOctets . SHA1.hash

 word160ToOctets (SHA1.Word160 a b c d e) = word32ToOctets a ++ word32ToOctets b ++ word32ToOctets c ++ word32ToOctets d ++ word32ToOctets e

 word32ToOctets :: Word32 -> [Word8]
 word32ToOctets w = 
    [ fromIntegral (w `shiftR` 24)
    , fromIntegral (w `shiftR` 16)
    , fromIntegral (w `shiftR` 8)
    , fromIntegral w
    ]


