# Streaming over Redis database
This is a really simple VPN that uses Redis as message bus and routes your traffic through your VPN server with it.
It uses AES-256-GCM encryption, well this dosent stop fucking dpi with its mitm technique to stopping me using the database endpoint 

# Installation
Put outside directory in your vps and run these commands
```
npm install
```
Then put your redis database string in config, use rediss database strings for enabling TLS encryptions
After that
```
npm run dev
```

Same operation applies for the proxy :)

oh btw the port is 1080

# TODO
- change bandwidth with rtt
