var client = new jsrp.client()
var serverAddr = 'http://localhost:4567/authenticate'
var username = 'leonardo'
var password = 'capricciosa'

$(document).ready(function () {
  'use strict'

  console.log('Starting Authentication')

  $(document).ajaxError(function (event, request, settings) {
    console.log(event)
    console.log(request)
    console.log(settings)
  })

  client.init({ username: username, password: password, length: 4096 }, function () {
    client.createVerifier(function (err, result) {
      // result will contain the necessary values the server needs to
      // authenticate this user in the future.
      // sendSaltToServer(result.salt)
      // sendVerifierToServer(result.verifier)

      if (err) {
         console.log(err.stack);
       }

      var A = client.getPublicKey()

      // Auth Phase 1
      console.log('P1 : Sending username and A to server')
      $.post(serverAddr, { username: username, A: A }, function (data) {
        console.log('P1 : Received salt : ', data.salt)
        console.log('P1 : Received B : ', data.B)
        client.setSalt(data.salt)
        client.setServerPublicKey(data.B)

        var clientM = client.getProof()
        console.log('P1 : calculated client M : ', clientM)

        // Auth Phase 2
        console.log('P2 : Sending username and M to server')
        $.post(serverAddr, { username: username, M: clientM }, function (data) {
          console.log('P2 : Received server H_AMK : ', data.H_AMK)
          if (client.checkServerProof(data.H_AMK)) {
            console.log('P2 : Client and server H_AMK match. Authenticated!')
            console.log('P2 : Client and server negotiated shared key K : ', client.getSharedKey())
            $('#status').html('Authenticated!')
            $('#username').html(username)
            $('#K').html(client.getSharedKey())
          } else {
            $('#status').html('Authenticated FAILED')
            console.log('P2 : Client and server H_AMK DO NOT match. Authentication failed!')
          }
        }, 'json')
      }, 'json')
    })
  })
})
