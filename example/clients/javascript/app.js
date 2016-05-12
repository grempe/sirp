var client = new jsrp.client()

var serverAddr   = 'http://localhost:4567/authenticate'
var username     = 'leonardo'
var password     = 'capricciosa'
var prime_length = 2048


$(document).ready(function () {
  'use strict'

  console.log('Start authentication')


  client.init({ username: username, password: password, length: 2048 }, function () {

    client.srp.params.hash = 'sha1'

    client.createVerifier(function (err, result) {
      // result will contain the necessary values the server needs to
      // authenticate this user in the future.

      console.log(client.srp.params)

      // sendSaltToServer(result.salt)
      // sendVerifierToServer(result.verifier)

      // Hex 'A' value
      var A = client.getPublicKey()

      console.log('Sending username and A to server')

      $(document).ajaxError(function( event, request, settings ) {
        console.log(request)
      })

      // Client => Server: username, A
      // Server => Client: salt, B
      $.post(serverAddr, { username: username, A: A }, function( data ) {
        client.setSalt(data.salt)
        client.setServerPublicKey(data.B)

        var clientM = client.getProof()
        console.log('clientM', clientM)

        // Client => Server: username, M
        // Server => Client: H(AMK)
        $.post(serverAddr, { username: username, M: clientM }, function( data ) {
          console.log('data', data)
          console.log('H_AMK', data.H_AMK)
          console.log('checkServerProof', client.checkServerProof(data.H_AMK))

          if (client.checkServerProof(data.H_AMK)) {
            console.log('shared key K: ', client.getSharedKey())
          } else {
            console.log('failed')
          }
        }, 'json')
      }, 'json')

    })
  })
})
