{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE OverloadedStrings #-}
module Main where

import Codec.Binary.Base64.String (decode)
import Data.ByteString.Char8 (ByteString)
import Data.Either
import Data.List
import Foreign.C.String
import Foreign.C.Types
import Foreign.Marshal.Alloc
import Foreign.Ptr
import Network.CGI
import Network.Socket
import Network.Socket.ByteString (recv, sendAll)
import System.IO

foreign import ccall "crypt_checkpass"
        crypt_checkpass :: CString -> CString -> IO CInt
foreign import ccall "crypt_newhash" 
        crypt_newhash :: CString -> CString -> CString -> Int -> IO CInt
foreign import ccall "unveil"
        unveil :: CString -> CString -> IO CInt
foreign import ccall "pledge"
        pledge :: CString -> CString -> IO CInt

readFileStrict :: String -> IO String
readFileStrict file = withFile file ReadMode $ \handle ->
        hGetContents handle >>= \s -> length s `seq` return s

writeFile' :: String -> String -> IO ()
writeFile' file = withFile file WriteMode . flip hPutStr 

cryptCheckPass :: String -> String -> IO Bool
cryptCheckPass pwd hash = fmap (==0) $
        withCString pwd  $ \pwd' -> 
        withCString hash $ \hash' -> do
                crypt_checkpass pwd' hash'

cryptNewHash :: String -> IO (Either String String)
cryptNewHash pwd = 
        withCString pwd $ \pwd' -> 
        withCString "bcrypt,8" $ \options ->
        allocaBytes _PASSWORD_LEN $ \ptr -> do
                res <- crypt_newhash pwd' options ptr _PASSWORD_LEN
                if res == 0 
                then fmap Right $ peekCString ptr
                else return $ Left $ "error: crypt_newhash, " ++ (show res)
        -- _PASSWORD_LEN = 128 (without \0, cf. pwd.h)
        where _PASSWORD_LEN = 128 + 1

newEntry :: String -> String -> IO (Either String String)
newEntry user pwd = cryptNewHash pwd >>= return . fmap (prepend user)
        where prepend u = ((u++":")++)

processEntry :: String -> String -> String -> String -> CGI (Either String String)
processEntry email oldpw newpw line = 
        case break (=='@') email of
                ("", _) -> return $ Right line
                (user, _) | user `isPrefixOf` line -> 
                        case break (==':') line of
                                (_, _:hash) -> do
                                        passOk <- liftIO $ cryptCheckPass oldpw hash
                                        if passOk 
                                        then liftIO $ newEntry user newpw
                                        else return $ Left "error: incorrect oldpw"
                                _ -> return $ Right line
                          | otherwise -> return $ Right line

cgiMain :: CGI CGIResult
cgiMain = do
        liftIO $ do
                call unveil "/etc/mail/vpasswd" "rcw"
                call unveil "/rlsmtpctl.sock" "rw"
                call pledge "stdio rpath wpath cpath unix" "NULL"
        setHeader "Content-type" "text/plain"
        c <- getVar "CONTENT_TYPE"
        if c == Just "application/x-www-form-urlencoded"
        then do inputs <- mapM getInput ["email", "oldpw", "newpw"]
                case map (fmap decode) inputs of
                        [Just email, Just oldpw, Just newpw] -> do
                                fcont <- liftIO $ readFileStrict "/etc/mail/vpasswd"
                                new_cont <- mapM (processEntry email oldpw newpw) $ lines fcont
                                let new_fcont = unlines $ map (fromRight "") new_cont
                                if any isLeft new_cont || fcont == new_fcont
                                then outputError 422 "Unprocessable Entity" ["processing error"
                                                                            , unlines $ map (fromLeft "") new_cont]
                                else do msg <- liftIO $ do
                                                writeFile' "/etc/mail/vpasswd" new_fcont
                                                sock <- socket AF_UNIX Stream defaultProtocol
                                                connect sock $ SockAddrUnix "/rlsmtpctl.sock"
                                                sendAll sock "smtpctl"
                                                msg <- recv sock 1024
                                                close sock
                                                return msg
                                        logCGI $ show msg
                                        setStatus 204 "No Content"
                                        outputNothing
                        _ -> outputError 422 "Unprocessable Entity" ["inputs"]
        else  outputError 406 "Not Acceptable" ["no x-www-form-urlencoded"]
        where call syscall str1 "NULL" =
                withCString str1 $ \p1 -> syscall p1 nullPtr
              call syscall str1 str2 = 
                withCString str1 $ \p1 -> withCString str2 $ \p2 -> syscall p1 p2

main :: IO ()
main = runCGI (handleErrors cgiMain)
