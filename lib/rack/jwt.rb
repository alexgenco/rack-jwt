require "jwt"
require "json"
require "rack"

require "rack/jwt/version"

module Rack
  class JWT
    def initialize(app, options={}, &block)
      @app = app
      @secret = options.fetch(:secret)
      @auth_path = options.fetch(:auth_path)
      @auth_block = block
    end

    def call(env)
      request = Request.new(env)

      if request.post? && request.path == @auth_path
        create_token(request)
      else
        authorize(request)
      end
    end

    private

    def create_token(request)
      claim = @auth_block.call(request)

      if claim
        jwt = ::JWT.encode(claim, @secret)
        payload = JSON.dump(token: jwt)
        Response.new([payload], 201).finish
      else
        unauthorized
      end
    end

    def authorize(request)
      env = request.env

      if authorization = env["Authorization"]
        jwt = authorization.split(" ")[-1]
        claim = ::JWT.decode(jwt, @secret)
        env["rack.jwt.claim"] = claim

        @app.call(env)
      else
        unauthorized
      end
    rescue ::JWT::DecodeError
      unauthorized
    end

    def unauthorized
      Response.new(["Unauthorized"], 401).finish
    end
  end
end
