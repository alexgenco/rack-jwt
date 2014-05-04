require "helper"
require "json"
require "jwt"

describe Rack::JWT do
  include Rack::Test::Methods
  let(:app) do
    inner = lambda { |env| [200, env, ["Hello"]] }
    options = {secret: "secret", auth_path: "/authenticate"}

    Rack::JWT.new(inner, options) do |request|
      if request.POST["username"] == "alex" && request.POST["password"] == "password"
        {user_id: 123}
      end
    end
  end

  context "granting a token" do
    it "returns a jwt for an authentic username and password" do
      jwt = ::JWT.encode({user_id: 123}, "secret")
      post "/authenticate", username: "alex", password: "password"
      expect(last_response.status).to eq(201)
      expect(JSON.parse(last_response.body)).to eq("token" => jwt)
    end

    it "returns 401 for an unauthentic username and password" do
      post "/authenticate", username: "alex", password: "wrong-password"
      expect(last_response.status).to eq(401)
      expect(last_response.body).to eq("Unauthorized")
    end
  end

  context "receiving a token" do
    it "calls through for an authorized user" do
      jwt = ::JWT.encode({user_id: 123}, "secret")
      get "/", {}, {"Authorization" => "Bearer #{jwt}"}
      expect(last_response.status).to eq(200)
      expect(last_response.body).to eq("Hello")
    end

    it "sets the rack.jwt.claim header" do
      jwt = ::JWT.encode({user_id: 123}, "secret")
      get "/", {}, {"Authorization" => "Bearer #{jwt}"}
      expect(last_response.header["rack.jwt.claim"]).to eq("user_id" => 123)
    end

    it "returns 401 if the authorization header is missing" do
      get "/"
      expect(last_response.status).to eq(401)
      expect(last_response.body).to eq("Unauthorized")
    end

    it "returns 401 if the jwt signature is invalid" do
      invalid_jwt = ::JWT.encode({user_id: 123}, "invalid")
      get "/", {}, {"Authorization" => invalid_jwt}
      expect(last_response.status).to eq(401)
      expect(last_response.body).to eq("Unauthorized")
    end
  end
end
