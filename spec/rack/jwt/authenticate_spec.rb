require "helper"
require "jwt"

describe Rack::JWT::Authenticate do
  include Rack::Test::Methods

  let(:app) do
    inner = lambda { |env| [200, env, ["Hello"]] }
    Rack::JWT::Authenticate.new(inner, secret: "secret")
  end

  it "calls through for an authorized user" do
    jwt = ::JWT.encode({user_id: 123}, "secret")
    get "/", {}, {"Authorization" => "JWT #{jwt}"}
    expect(last_response.status).to eq(200)
    expect(last_response.body).to eq("Hello")
  end

  it "sets the rack.jwt.claim header" do
    jwt = ::JWT.encode({user_id: 123}, "secret")
    get "/", {}, {"Authorization" => "JWT #{jwt}"}
    expect(last_response.header["rack.jwt.claim"]).to eq("user_id" => 123)
  end

  it "returns 401 if the authorization header is missing" do
    get "/"
    expect(last_response.status).to eq(401)
    expect(last_response.headers["WWW-Authenticate"]).to eq("JWT realm=\"api\"")
  end

  it "returns 401 if the jwt signature is invalid" do
    invalid_jwt = ::JWT.encode({user_id: 123}, "invalid")
    get "/", {}, {"Authorization" => "JWT #{invalid_jwt}"}
    expect(last_response.status).to eq(401)
    expect(last_response.headers["WWW-Authenticate"]).to eq("JWT realm=\"api\"")
  end
end
