require "json"
require "jwt"

module Rack
  module JWT
    class Grant
      def initialize(app, options={}, &block)
        @app = app
        @secret = options.fetch(:secret)
        @path = options.fetch(:path)
        @auth_block = block
      end

      def call(env)
        request = Request.new(env)

        if request.post? && request.path == @path
          create_token(request)
        else
          @app.call(env)
        end
      end

      private

      def create_token(request)
        if claim = @auth_block.call(request)
          token = ::JWT.encode(claim, @secret)
          payload = JSON.dump(token: token)

          Response.new([payload], 201).finish
        else
          headers = {"WWW-Authenticate" => "JWT realm=\"api\""}
          Response.new([], 401, headers).finish
        end
      end
    end
  end
end
