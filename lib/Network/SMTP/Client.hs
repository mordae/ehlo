-- |
-- Module      :  Network.SMTP.Client
-- Copyright   :  Jan Hamal Dvořák
-- License     :  MIT
--
-- Maintainer  :  mordae@anilinux.org
-- Stability   :  unstable
-- Portability :  non-portable (ghc)
--
-- This module provides means to connect to a SMTP server and submit an email.
--

module Network.SMTP.Client
  ( sendMail
  , defaultSmtpSettings
  , SmtpSettings(..)
  , SmtpResult(..)
  )
where
  import Prelude hiding (lines)

  import Network.SMTP.Parser

  import Data.Typeable
  import GHC.Generics

  import Control.Exception (bracket)
  import Control.Monad.IO.Class (MonadIO, liftIO)
  import Control.Monad.Trans.Reader (ReaderT, runReaderT, ask)
  import Control.Monad (when, unless, forM_)

  import Data.Char (isAscii)
  import Data.Text (Text)

  import Hookup
  import Network.Socket (PortNumber)

  import OpenSSL
  import OpenSSL.EVP.Base64 (encodeBase64BS)

  import qualified Data.ByteString as BS
  import qualified Data.ByteString.Lazy as LBS
  import qualified Data.Text as T
  import qualified Data.Text.Encoding as T


  -- |
  -- Settings for connecting to the SMTP server.
  --
  data SmtpSettings
    = SmtpSettings
      { smtpHost       :: Text
        -- ^ Server to connect to.

      , smtpSender     :: Text
        -- ^ Our domain name to use in EHLO.
        --   Better tell truth or risk getting spammer treatment.

      , smtpOverSSL    :: Bool
        -- ^ Force SSL instead of trying STARTTLS.

      , smtpSecure     :: Bool
        -- ^ Abort if STARTTLS gets rejected.
        --   Better keep this on when MITM attack is a concern.

      , smtpPort       :: PortNumber
        -- ^ Port to connect to. Usually either 587 or 465 (SSL).

      , smtpAuth       :: Maybe (Text, Text)
        -- ^ Login and password to be used.
        --   Can be skipped for internal servers that whitelist IPs.
        --   Supports only @PLAIN@ authentication method.

      , smtpDebug      :: Bool
        -- ^ Print the SMTP exchange (as understood by the client) to stdout.
      }
    deriving (Show, Eq, Typeable, Generic)


  -- |
  -- Result of the 'sendMail' function.
  --
  data SmtpResult
    = SmtpError Int [BS.ByteString]  -- ^ Server has rejected our attempt.
    | SmtpGibberish String           -- ^ Failed to parse server reply.
    | SmtpSuccess                    -- ^ Messages was queued successfully.
    deriving (Show, Eq, Typeable, Generic)


  -- |
  -- Default settings:
  --
  -- @
  -- SmtpSettings { smtpHost    = \"localhost\"
  --              , smtpSender  = \"localhost\"
  --              , smtpOverSSL = False
  --              , smtpSecure  = True
  --              , smtpPort    = 587
  --              , smtpAuth    = Nothing
  --              , smtpDebug   = False
  --              }
  -- @
  --
  defaultSmtpSettings :: SmtpSettings
  defaultSmtpSettings = SmtpSettings { smtpHost    = "localhost"
                                     , smtpSender  = "localhost"
                                     , smtpOverSSL = False
                                     , smtpSecure  = True
                                     , smtpPort    = 587
                                     , smtpAuth    = Nothing
                                     , smtpDebug   = False
                                     }


  -- |
  -- Attempt to submit an email to be sent.
  --
  -- Can throw a "Hookup.ConnectionFailure" exception.
  --
  sendMail :: (MonadIO m)
           => SmtpSettings   -- ^ Bunch of mandatory and/or useful settings.
           -> Text           -- ^ Sender. This is usually the @Reply-To@.
           -> [Text]         -- ^ Mail recipients in @To@ and @Cc@ + others.
           -> LBS.ByteString -- ^ Encoded email. Use @mime-mail@ package.
           -> m SmtpResult
  sendMail envSettings envSender envRecipients envBody = do
    liftIO do
      withOpenSSL do
        let params = settingsToParams envSettings
         in bracket (connect params) close \envConnection -> do
           runReaderT start Env {..}


  settingsToParams :: SmtpSettings -> ConnectionParams
  settingsToParams SmtpSettings{..} =
    ConnectionParams { cpHost  = T.unpack smtpHost
                     , cpPort  = smtpPort
                     , cpSocks = Nothing
                     , cpTls   = if smtpOverSSL then Just tls else Nothing
                     , cpBind  = Nothing
                     }
    where tls = defaultTlsParams { tpInsecure = not smtpSecure }


  -- State Machine -----------------------------------------------------------


  type State = ReaderT Env IO SmtpResult


  -- |
  -- Local environment for our state machine.
  --
  data Env
    = Env
      { envSettings    :: SmtpSettings
      , envSender      :: Text
      , envRecipients  :: [Text]
      , envBody        :: LBS.ByteString
      , envConnection  :: Connection
      }


  start :: State
  start = do
    withSuccess [] do
      starttls


  starttls :: State
  starttls = do
    Env{envSettings = SmtpSettings{..}, envConnection} <- ask

    if smtpOverSSL
       then ehlo
       else do
         withResult [ "STARTTLS" ] \code rows -> do
           case (isOk code, smtpSecure) of
             (False, True) -> quit $ SmtpError code rows
             (False, False) -> ehlo
             (True, _) -> do
               let tls = defaultTlsParams { tpInsecure    = not smtpSecure
                                          , tpCipherSuite = "DEFAULT"
                                          }

               liftIO $ upgradeTls tls (T.unpack smtpHost) envConnection
               ehlo


  ehlo :: State
  ehlo = do
    Env{envSettings = SmtpSettings{smtpSender}} <- ask
    withSuccess [ "EHLO ", T.encodeUtf8 smtpSender ] authenticate


  authenticate :: State
  authenticate = do
    Env{envSettings = SmtpSettings{..}} <- ask

    case smtpAuth of
      Nothing -> mailFrom
      Just auth -> do
        withSuccess [ "AUTH PLAIN ", authString auth ] mailFrom


  mailFrom :: State
  mailFrom = do
    Env{envSender, envRecipients} <- ask

    withSuccess [ "MAIL FROM:<"
                , T.encodeUtf8 envSender, ">"
                , if all isTextAscii (envSender : envRecipients)
                     then ""
                     else " SMTPUTF8"
                , " BODY=8BITMIME"
                ] rcptTo


  rcptTo :: State
  rcptTo = do
    Env{envRecipients} <- ask
    addRecipients envRecipients


  addRecipients :: [Text] -> State
  addRecipients [] = data_
  addRecipients (r:rs) = do
    withSuccess [ "RCPT TO:<", T.encodeUtf8 r, ">" ] do
      addRecipients rs


  data_ :: State
  data_ = do
    Env{envBody, envConnection} <- ask

    withSuccess [ "DATA" ] do
      liftIO do
        sendLines envConnection (LBS.split 10 envBody)

      withSuccess [ "." ] do
        quit $ SmtpSuccess


  quit :: SmtpResult -> State
  quit res = command [ "QUIT" ] >> return res


  -- Utilities ---------------------------------------------------------------


  sendLines :: Connection -> [LBS.ByteString] -> IO ()
  sendLines conn lines = do
    case lines of
      [] -> return ()
      [""] -> return ()
      (line:more) -> do
        if LBS.take 1 line == "."
           then send conn (LBS.toStrict $ "." <> line <> "\n")
           else send conn (LBS.toStrict $        line <> "\n")

        sendLines conn more


  authString :: (Text, Text) -> BS.ByteString
  authString (login, password) =
    encodeBase64BS $ mconcat [ T.encodeUtf8 login, "\0"
                             , T.encodeUtf8 login, "\0"
                             , T.encodeUtf8 password, "\0"
                             ]


  command :: [BS.ByteString] -> ReaderT Env IO (Either String (Int, [BS.ByteString]))
  command parts = do
    Env{envConnection, envSettings = SmtpSettings{smtpDebug}} <- ask

    liftIO do
      when smtpDebug do
        BS.putStr $ mconcat [ "C: ", mconcat parts ]
        putStrLn ""

      unless ([] == parts) do
        send envConnection (mconcat parts <> "\r\n")

      res <- recvSmtp envConnection

      when smtpDebug do
        case res of
          Left reason -> do
            putStrLn $ "E: " <> reason

          Right (code, lines) -> do
            forM_ lines \line -> do
              putStr $ mconcat [ "S: ", show code, " " ]
              BS.putStr line
              putStrLn ""

      return res


  withResult :: [BS.ByteString] -> (Int -> [BS.ByteString] -> State) -> State
  withResult parts body = do
    res <- command parts

    case res of
      Left reason -> return $ SmtpGibberish reason
      Right (code, rows) -> body code rows


  withSuccess :: [BS.ByteString] -> State -> State
  withSuccess parts body = do
    withResult parts \code rows ->
      if isOk code
         then body
         else quit $ SmtpError code rows


  isOk :: Int -> Bool
  isOk x = x >= 200 && x < 400


  isTextAscii :: Text -> Bool
  isTextAscii = all isAscii . T.unpack


-- vim:set ft=haskell sw=2 ts=2 et:
