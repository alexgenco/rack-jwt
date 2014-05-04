require "helper"
require "jwt"

describe Rack::JWT do
  include Rack::Test::Methods
  let(:app) do
    inner = lambda { |env| [200, env, []] }
    Rack::JWT.new(inner, "secret")
  end

  it "sets the rack.jwt.claim header" do
    jwt = ::JWT.encode({user_id: 123}, "secret")
    get "/", {}, {"Authorization" => jwt}
    expect(last_response.header["rack.jwt.claim"]).to eq("user_id" => 123)
  end

  it "returns 401 if the jwt signature is invalid" do
    jwt = ::JWT.encode({user_id: 123}, "secret") + "abc"
    get "/", {}, {"Authorization" => jwt}
    expect(last_response.status).to eq(401)
    expect(last_response.body).to eq("Unauthorized")
  end
end
