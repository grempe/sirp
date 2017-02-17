RSpec.describe SIRP do
  # Simulate actual authentication scenario over HTTP
  # when the server is RESTful and has to persist authentication
  # state between challenge and response.
  #
  xcontext 'simulated authentication' do
    let(:username) { 'leonardo' }
    let(:password) { 'icnivad' }

    it 'should authenticate with matching server and client params' do

    end

    it 'should not authenticate when a bad password is injected in the flow' do

    end

    it 'should authenticate when simulating a stateless server' do

    end
  end
end
