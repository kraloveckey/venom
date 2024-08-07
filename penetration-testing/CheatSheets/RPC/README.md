# RPC - Remote Procedure Call

### rpcclient

Connect to an RPC share without a username and password and enumerate privileges:

`rpcclient --user="" --command=enumprivs -N 172.20.10.5`

Connect to an RPC share with a username and enumerate privileges:

`rpcclient --user="<Username>" --command=enumprivs 172.20.10.5`