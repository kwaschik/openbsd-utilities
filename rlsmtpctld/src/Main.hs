{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ForeignFunctionInterface #-}
module Main where

import Control.Monad (forever)
import Control.Exception (finally)
import Data.ByteString.Char8 (append, isPrefixOf, pack)
import Foreign.C.String
import Foreign.C.Types
import Foreign.Ptr
import Network.Socket
import Network.Socket.ByteString (recv, sendAll)
import System.Directory (removeFile)
import System.IO (hGetContents)
import System.Posix.Daemonize (daemonize)
import System.Posix.Files (setOwnerAndGroup)
import System.Posix.User (UserEntry(..), getUserEntryForName)
import System.Posix.Signals
import System.Process (createProcess, proc, std_out, StdStream(CreatePipe))

foreign import ccall "unveil"
        unveil :: CString -> CString -> IO CInt
foreign import ccall "pledge"
        pledge :: CString -> CString -> IO CInt


sockfile = "/var/www/rlsmtpctl.sock"

cleanUp :: Socket -> String -> IO ()
cleanUp s f = close s >> removeFile f

main :: IO ()
main = daemonize $ do
        call unveil sockfile "rwc"
        call unveil "/usr/sbin/smtpctl" "x"
        call pledge "stdio unix rpath cpath getpw chown proc exec" "NULL"
        sock <- socket AF_UNIX Stream defaultProtocol
        bind sock $ SockAddrUnix sockfile
        installHandler sigTERM (Catch $ cleanUp sock sockfile) Nothing
        www <- getUserEntryForName "www"
        setOwnerAndGroup sockfile (userID www) (userGroupID www)
        listen sock 5
        call pledge "stdio unix cpath proc exec" "NULL"
        (forever $ do
                (csock, peer) <- accept sock
                msg <- recv csock 1024
                answer <- if "smtpctl" `isPrefixOf` msg
                          then fmap pack smtpctl
                          else return "unknown command\n"
                sendAll csock answer
                gracefulClose csock 1000) `finally` 
                (cleanUp sock sockfile)
        where call syscall str1 "NULL" =
                withCString str1 $ \p1 -> syscall p1 nullPtr
              call syscall str1 str2 = 
                withCString str1 $ \p1 -> withCString str2 $ \p2 -> syscall p1 p2
              smtpctl = do
                (_, Just hout, _, _) <-
                        createProcess (proc "smtpctl" ["update", "table", "vpasswd"]) { 
                                std_out = CreatePipe
                        }
                hGetContents hout
