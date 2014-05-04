module Rack
  module JWT
    class Authenticate
      def initialize(app, options={})
        @app = app
        @secret = options.fetch(:secret)
      end

      def call(env)
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

      private

      def unauthorized
        headers = {"WWW-Authenticate" => "JWT realm=\"api\""}
        Response.new(["Unauthorized"], 401, headers).finish
      end
    end
  end
end
