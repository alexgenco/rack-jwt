require "jwt"
require "rack/jwt/version"

module Rack
  class JWT
    def initialize(app, secret)
      @app = app
      @secret = secret
    end

    def call(env)
      jwt = env["Authorization"]
      claim = ::JWT.decode(jwt, @secret)
      env["rack.jwt.claim"] = claim
      @app.call(env)
    end
  end
end
