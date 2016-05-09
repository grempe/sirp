Test authentication mechanism:

* Install required gems

```
cd example
```

* Launch Ruby server in Terminal 1

```
bundle install
./server.rb
```

* Authenticate with Python client in Terminal 2

```
python client.py <username> <password>
```

You can find correct username : password combinations in `server.rb`
