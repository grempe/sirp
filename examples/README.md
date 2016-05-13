# Secure Remote Password : Example

## Install Ruby Dependencies

```
$ cd examples
$ bundle install
```

## Run Server

```sh
# run this in the first terminal window
$ ./server.rb
```

## Authenticate with Ruby Client

```sh
# run this in the second terminal window
$ cd clients/ruby/
$ ./client.rb
```

## Authenticate with JavaScript Client

```sh
# see the output of the JS client in the browser's JS console
$ cd clients/javascript/
$ npm install
$ open index.html
```

You can find other username : password combinations in `server.rb`
