sqlsess is a simple package for managing database backed sessions which can be 
used as a 
[gorilla/sessions.Store](http://godoc.org/github.com/gorilla/sessions#Store).

* A single cookie is used to track session IDs. Cookies are AES encrypted
  by default and verified with HMAC.
* A simple key-value session table is used. Keys are added or changed
  with a standard 
  [gorilla/sessions.Session](https://github.com/gorilla/sessions/blob/master/sessions.go#L47)
  value.
* Stale sessions can be removed after a specified amount of time by running
  the `Clean` method with any timeout.


### Installation

    go get github.com/BurntSushi/sqlsess


### Beta

This package is emphatically in BETA. Although most of the API is determined by 
the `gorilla/sessions` package, there are still some pieces that may need some 
changing. (For example, to allow key rotation.)

