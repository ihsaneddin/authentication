module Auth
  module Models
    module Decorators
      module Code
        module Encryptable

          extend ::Auth::Models::Decorators::Code::Object

          def self.default_options
            {
              algorithm: "sha256", # :sha256, :plain
              encryption_opts: {},
              encode_code: proc { |code|
                case encryptable_algorithm.to_s.to_sym
                when :sha256
                  Digest::SHA256.hexdigest(code)
                else
                  code
                end
              }
            }
          end

          def self.included(base)
            base.extend ClassMethods
          end

          module ClassMethods
            def encryptable(**opts, &block)
              ::Auth::Models::Decorators::Code::Object.config_class.setup(
                self,
                "encryptable_config",
                opts,
                ::Auth::Models::Decorators::Code::Encryptable.default_options,
                method_prefix: "encryptable",
                &block
              )

              define_inheritable_singleton_method(:encryptable?) { true }

              include InstanceMethods

            end
          end

          module InstanceMethods

            extend ActiveSupport::Concern

            included do

              def self.find_by_code code
                return if code.blank?
                digest = encryptable_encode_code(code)
                super(digest)
              end

            end

            def code=(val)
              super(val)
              self.code_digest = encryptable_encode_code(val) if val.present?
            end

          end

        end
      end
    end
  end
end
