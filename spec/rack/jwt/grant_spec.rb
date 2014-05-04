require "helper"

describe Rack::JWT::Grant do
  include Rack::Test::Methods

  let(:app) do
    inner = lambda { |env| [200, env, ["Hello"]] }
    options = {
      secret: "secret",
      path: "/authenticate",
    }

    Rack::JWT::Grant.new(inner, options) do |request|
      if request.POST["username"] == "alex" && request.POST["password"] == "password"
        {user_id: 123}
      end
    end
  end

  it "returns a jwt for an authentic request" do
    jwt = ::JWT.encode({user_id: 123}, "secret")
    post "/authenticate", username: "alex", password: "password"
    expect(last_response.status).to eq(201)
    expect(JSON.parse(last_response.body)).to eq("token" => jwt)
  end

  it "returns 401 for an unauthentic username and password" do
    post "/authenticate", username: "alex", password: "wrong-password"
    expect(last_response.status).to eq(401)
    expect(last_response.headers["WWW-Authenticate"]).to eq("JWT realm=\"api\"")
  end
end
