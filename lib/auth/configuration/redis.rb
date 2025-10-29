require 'redis'

module Auth
  module Configuration
    module Redis

      mattr_accessor :instance
      mattr_accessor :url

      @@url = "redis://localhost:6379/0"
      @@instance = ::Redis.new(url: @@url)

      def self.setup &block
        raise "Block is not provided" unless block_given?
        block.arity.zero? ? instance_eval(&block) : yield(self)
      end

      def self.url &block
        if block_given?
          @@url = yield
        else
          @@url
        end
      end

      def self.instance &block
        if block_given?
          @@instance = yield
        else
          @@instance
        end
      end

    end
  end
end