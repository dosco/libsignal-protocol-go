# libsignal-protocol-go

#### A GoLang library for communicating using the Signal .

This library currently implements the "X3DH" (or "Extended Triple Diffie-Hellman") key agreement protocol. X3DH establishes a shared secret key between two parties who mutually authenticate each other based on public keys. X3DH provides forward secrecy and cryptographic deniability. Work is currently on to implement the Double Ratchet Algorithm that provides perfect forward secrecy.

1. [https://signal.org/docs/specifications/x3dh](https://signal.org/docs/specifications/x3dh)
2. [https://signal.org/docs/specifications/doubleratchet/](https://signal.org/docs/specifications/doubleratchet/)


##### Try the end-to-end sending and receiving signal protocol flow

```console
go test -v -timeout 30s github.com/dosco/signal-go -run ^TestFlow$
```
