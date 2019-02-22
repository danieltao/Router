# Router
The repository simulates a simple router with a static routing table. It will receive raw Ethernet frames. It will process the packets just like a real router, then forward them to the correct outgoing interface. 

The router will route real packets from a emulated host (client) to two emulated application servers (http server 1/2) sitting behind it. The application servers are each running an HTTP server. In addition, the router is able to ping and traceroute to and through a functioning Internet router
