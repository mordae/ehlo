# ehlo

**Minimalistic SMTP client for Haskell**

It has a single mission:

1. Connect to a SMTP server and setup a secure channel,
2. authenticate, if desired,
3. say `EHLO`, `MAIL FROM`, `RCPT TO` and `DATA`,
4. transmit our email, taking care to properly escape it`.`
5. Finish and `QUIT`.

Usage:

```haskell
let settings = SmtpSettings { smtpHost    = "example.org"
                            , smtpSender  = "mailer.example.org"
                            , smtpOverSSL = False
                            , smtpSecure  = True
                            , smtpPort    = 587
                            , smtpAuth    = Just ("login", "password")
                            , smtpDebug   = False
                            }

sendMail settings sender [recipient] email
```
