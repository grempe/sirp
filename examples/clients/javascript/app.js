var client = new jsrp.client()
var serverAddr = 'http://localhost:4567/authenticate'
var username = 'leonardo'
var password = 'capricciosa'
var length = 4096

$(document).ready(function () {
  'use strict'

  $('#statusP0').append('P1 : START\n')
  $('#statusP0').append('P1 : username : ' + username + '\n')
  $('#statusP0').append('P1 : password : ' + password + '\n')
  $('#statusP0').append('P1 : length : ' + length + ' bits\n')

  $(document).ajaxError(function (event, request, settings) {
    console.error(event)
    console.error(request)
    console.error(settings)
  })

  client.init({ username: username, password: password, length: length }, function () {
    client.createVerifier(function (err, result) {
      if (err) {
        console.error(err.stack)
      }

      $('#statusP0').append('P0 : generated client salt : ' + result.salt + '\n')
      $('#statusP0').append('P0 : generated client verifier : ' + result.verifier + '\n')
      $('#statusP0').append('P0 : (SIMULATED) registering user with username, salt, and verifier.\n')

      // Phase 1
      // Send : username and A
      // Receive : salt and B
      // Calculate : M
      //
      var A = client.getPublicKey()
      $('#statusP1').append('P1 : client A : ' + A + '\n')
      $('#statusP1').append('P1 : Sending username and A to server\n')
      $.post(serverAddr, { username: username, A: A }, function (data) {
        $('#statusP1').append('P1 : Received salt : ' + data.salt + '\n')
        $('#statusP1').append('P1 : Received B : ' + data.B + '\n')
        client.setSalt(data.salt)
        client.setServerPublicKey(data.B)

        var clientM = client.getProof()
        $('#statusP1').append('P1 : calculated client M : ' + clientM + '\n')

        // Phase 2
        // Send : username and M
        // Receive : H_AMK
        // Confirm client and server H_AMK values match, use shared key K
        //
        $('#statusP2').append('P2 : Sending username and client M to server\n')
        $.post(serverAddr, { username: username, M: clientM }, function (data) {
          $('#statusP2').append('P2 : Received server H_AMK : ' + data.H_AMK + '\n')
          if (client.checkServerProof(data.H_AMK)) {
            $('#statusP2').append('P2 : H_AMK values match!\n')
            $('#statusP2').append('P2 : Shared Secret K : ' + client.getSharedKey() + '\n')
            $('#statusP2').append('\nAUTHENTICATION COMPLETE!')
          } else {
            $('#statusErr').append('P2 : Error : Auth Failed : Client and server H_AMK did not match.')
          }
        }, 'json')
      }, 'json')
    })
  })
})
