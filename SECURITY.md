# Security

## Reporting a problem

Please do not open a public issue for a security problem. Use GitHub's private vulnerability reporting on this repository (**Security → Report a vulnerability**). Say what is affected, how to reproduce it and what an attacker gains. You will get an answer within a week.

Problems we especially want to hear about:

- breaking the Noise handshake or SecretStream in `components/hdht`, or reading or changing a stream;
- a way to forge or replay messages that `components/hdht_mqtt` signs, or the receipts it checks;
- getting a device to accept a credential (`hdht_cred`) or a firmware update (`hdht_ota`) that its issuer or publisher did not sign;
- memory safety problems in anything that parses network input (`hdht`, `libudx`, `hdht_mqtt`, `zk`).

Problems in the network built on this (contracts, nodes, the testnet) belong to [xid-network](https://github.com/linyao0177/xid-network/security).

## Supported versions

Only the `main` branch gets fixes. This is experimental software.
