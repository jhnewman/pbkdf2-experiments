
module BPKDF2 (
  Hasher,
  pbkdf2
) where

import Data.Word
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString as BS
import Data.HMAC (hmac_sha1)
import Data.List (unfoldr)
import Data.Bits (xor, shiftR)

-- A hash function and the length of the output of the function
data Hasher = Hasher ([Word8] -> [Word8] -> [Word8]) Int

-- For example, hmac_sha1 outputs 160 bits, or 20 octets
hmac_sha1' = Hasher hmac_sha1 20

-- Implementation of pbkdf2 algorithm speicified in rfc2898
-- lazy evaluation really simplifies the code a lot!
pbkdf2 :: Hasher -> Int -> Int -> [Word8] -> [Word8] -> [Word8]
pbkdf2 (Hasher prf hLen) c dkLen pass salt = dk where
  ts   = map f [1..]                              -- infinite list of blocks
  f i  = foldr1 (zipWith xor) . take c $ us where -- make block from index
    us = unfold (prf pass) (salt ++  encode i)    -- hash of a hash of a hash...
    encode x = word32ToOctets . fromIntegral $ x  -- turn i into a [Word8]
  dk   = take dkLen . concat $ ts                 -- derived key 

-- atlassian_pbkdf2_sha is pbkdf2 with:
--   iterations: 10000
--   output size: 32
--   prf: hmac_sha1
atlassian_pbkdf2_sha pass salt = BS.unpack . Base64.encode . BS.pack $salt ++ checksum where
  checksum = pbkdf2 hmac_sha1' 10000 32 pass salt

test expected iterations pass salt = expected == actual where
  actual = pbkdf2 hmac_sha1' iterations (length expected) (char2word8 pass) (char2word8 salt)

-- Tests Vectors specified in rfc6070
tests = foldr (&&) True [
    test 
      [0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6]
      1
      "password"
      "salt",
    test 
      [0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57]
      2
      "password"
      "salt",
    test
      [0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0, 0x65, 0xa4, 0x29, 0xc1]
      4096
      "password"
      "salt",
    test
      [0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b, 0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a, 0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70, 0x38]
      4096
      "passwordPASSWORDpassword"
      "saltSALTsaltSALTsaltSALTsaltSALTsalt"
    
  ]

word32ToOctets :: Word32 -> [Word8]
word32ToOctets w = 
   [ fromIntegral (w `shiftR` 24)
   , fromIntegral (w `shiftR` 16)
   , fromIntegral (w `shiftR` 8)
   , fromIntegral w
   ]

-- simplified unfoldr
unfold f = unfoldr (\x -> let x' = f x in Just (x', x'))  

-- dumb way to map from [Char] to [Word8]
char2word8 :: [Char] -> [Word8]
char2word8 = map (toEnum.fromEnum)

-- testing atlassian
rawSalt = [0x0d, 0x02, 0x17, 0x25, 0x4d, 0x37, 0xf2, 0xee, 0x0f, 0xec, 0x57, 0x6c, 0xb8, 0x54, 0xd8, 0xff]

rawPass = char2word8 "password"

testAtlassian = char2word8 "DQIXJU038u4P7FdsuFTY/+35bm41kfjZa57UrdxHp2Mu3qF2uy+ooD+jF5t1tb8J" == atlassian_pbkdf2_sha rawPass rawSalt 

