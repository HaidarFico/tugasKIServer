## Current Used Packages:
- pycryptodome <br/>
we use pycryptodome over pycrypto because of a better performance and more up to date. The use of pycryptodome is to ensures that the code is using a reliable and secure library for cryptographic operations.
- requests <br/>
request here is used to access the form data sent with the request. The username, password, and key variables are set to the values of the corresponding form fields.
- mysqlclient
- flask <br/>
Flask is being used as a web framework for this project. for defining API routes and handle HTTP requests and responses.
- flask-mysqldb


## Cipher Differences
To measure the running time we measure the data from downloading 10 time. And here is the result.

| AES (16 char)           | DES (16 char)            | RC4(8 char)           |   |   |
|---------------|----------------|----------------|---|---|
| 0.03018565178 s | 0.008216905594 s | 0.005313539505 s  |   |   |