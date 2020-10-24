{-# LANGUAGE OverloadedStrings #-}
module Main where

import Control.Monad (forever)
import Control.Exception (finally)
import Data.ByteString.Char8 (append, isPrefixOf, pack)
import Network.Socket
import Network.Socket.ByteString (recv, sendAll)
import System.Directory (removeFile)
import System.IO (hGetContents)
import System.Posix.Daemonize (daemonize)
import System.Posix.Files (setOwnerAndGroup)
import System.Posix.Signals
import System.Process (createProcess, proc, std_out, StdStream(CreatePipe))


sockfile = "/var/www/rlsmtpctl.sock"

cleanUp :: Socket -> String -> IO ()
cleanUp s f = close s >> removeFile f

main :: IO ()
main = daemonize $ do
        sock <- socket AF_UNIX Stream defaultProtocol
        bind sock $ SockAddrUnix sockfile
        installHandler sigTERM (Catch $ cleanUp sock sockfile) Nothing
        setOwnerAndGroup sockfile 1000 1000
        listen sock 5
        (forever $ do
                (csock, peer) <- accept sock
                msg <- recv csock 1024
                answer <- if "smtpctl" `isPrefixOf` msg
                          then fmap pack smtpctl
                          else return "wrong command"
                sendAll csock answer
                gracefulClose csock 1000) `finally` 
                (cleanUp sock sockfile)
        where smtpctl = do
                (_, Just hout, _, _) <-
                        createProcess (proc "smtpctl" ["update", "table", "vpasswd"]) { 
                                std_out = CreatePipe
                        }
                hGetContents hout
