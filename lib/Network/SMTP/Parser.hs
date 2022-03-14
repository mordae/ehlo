-- |
-- Module      :  Network.SMTP.Parser
-- Copyright   :  Jan Hamal Dvořák
-- License     :  MIT
--
-- Maintainer  :  mordae@anilinux.org
-- Stability   :  unstable
-- Portability :  non-portable (ghc)
--

module Network.SMTP.Parser
  ( recvSmtp
  )
where
  import Prelude hiding (lines)

  import Data.Attoparsec.ByteString.Char8
  import Hookup (Connection, recv)
  import Data.ByteString (ByteString)


  recvSmtp :: Connection -> IO (Either String (Int, [ByteString]))
  recvSmtp conn = parseMore conn (parse smtpParser)


  parseMore :: Connection
            -> (ByteString -> Result a)
            -> IO (Either String a)
  parseMore conn cont0 = do
    bstr <- recv conn 1000

    case cont0 bstr of
      Fail _ _ reason -> return $ Left reason
      Done _ result   -> return $ Right result
      Partial cont1   -> parseMore conn cont1


  smtpParser :: Parser (Int, [ByteString])
  smtpParser = do
    lines <- many' (lineSeptBy '-')
    final <- lineSeptBy ' '
    return (fst final, map snd lines <> [snd final])


  lineSeptBy :: Char -> Parser (Int, ByteString)
  lineSeptBy sep = do
    code <- decimal
    _    <- char sep
    text <- takeTill \x -> x == '\r' || x == '\n'
    _    <- option '\r' (char '\r')
    _    <- char '\n'

    return (code, text)

-- vim:set ft=haskell sw=2 ts=2 et:
