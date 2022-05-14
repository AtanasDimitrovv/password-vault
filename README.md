# Password vault

Password manager client-server application. The server allows multiple users to use it simultaneously. Every user has to either 
create a new account or log in an already existing one. Once logged, he can add passwords into his account, remove some of 
them or retrieve a password he has stored before. The server checks if a password is safe and requires a new one if it's not. 
The information is stored in files by using either hashing or cryptographic algorithms.

Commands supported by the server:

- register <user> <password> <password-repeat> - create new account with username <user> and password
- login <user> <password> - log in the account with username <user>
- logout - leave the account
- retrieve-credentials <website> <user> - retrieve <user> and password of the account in <website>
- add-password <website> <user> <password> - add information for account in <website>. Succeeds only if the password is secure.
- remove-password <website> <user> - remove account information for <website>
- disconnect - leave the server
