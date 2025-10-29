module Auth
  module Models
    module Decorators
      module Code
        module Storage
          module Redis

            extend ::Auth::Models::Decorators::Code::Storage
            extend ActiveSupport::Concern

            included do

              attribute :metadata, :json, default: {}
              attribute :code_digest, :string
              attribute :id, :string

              validates :code, presence: true

              class_attribute :redis_prefix, default: "auth:code"
              class_attribute :redis_ttl, default: 10.minutes # seconds
            end

            class_methods do
              def redis_instance
                ::Auth.config.redis.instance
              end

              #
              # ===== Core persistence API =====
              #
              def find(id)
                return if id.blank?
                data = redis_instance.hgetall(redis_key_for(id))
                return if data.blank?
                instantiate_from_redis(data)
              end

              def find_by_session(session_id)
                return if session_id.blank?
                id = redis_instance.get(redis_session_key_for(session_id))
                find(id)
              end

              def find_by_code(code)
                return if code.blank?
                digest = code
                id = redis_instance.get(redis_code_key_for(digest))
                find(id)
              end

              def create!(attrs)
                obj = new(attrs)
                obj.save!
                obj
              end

              def delete(id)
                return false if id.blank?
                redis_instance.del(redis_key_for(id))
                true
              end

              #
              # ===== Utility helpers =====
              #
              def redis_key_for(id)
                "#{redis_prefix}:#{id}"
              end

              def redis_session_key_for(session_id)
                "#{redis_prefix}:session:#{session_id}"
              end

              def redis_code_key_for(code_digest)
                "#{redis_prefix}:code:#{code_digest}"
              end

              def instantiate_from_redis(data)
                # Rebuild the OTP object from Redis hash
                obj = new
                data.each do |k, v|
                  next unless obj.respond_to?("#{k}=")
                  value =
                    if k == "metadata"
                      parse_metadata(v)
                    else
                      v
                    end
                  obj.public_send("#{k}=", value)
                end
                obj
              end

              def parse_metadata(val)
                case val
                when String
                  JSON.parse(val) rescue {}
                when Hash
                  val
                else
                  {}
                end
              end
            end

            #
            # ===== Instance Methods =====
            #
            def code=(val)
              super(val)
              self.code_digest = val
            end

            def code
              @code || self.code_digest
            end

            def redis
              self.class.redis_instance
            end

            def redis_key
              self.class.redis_key_for(id)
            end

            #
            # ===== Persistence behavior =====
            #
            def save!
              raise ActiveRecord::RecordInvalid.new(self) unless valid?

              self.id ||= SecureRandom.uuid

              data = as_json.compact.stringify_keys
              data["code_digest"] ||= code
              data["id"] = id

              redis.multi do |r|
                r.hmset(redis_key, *data.to_a.flatten)
                r.expire(redis_key, self.class.redis_ttl)

                if session_id.present?
                  r.set(self.class.redis_session_key_for(session_id), id, ex: self.class.redis_ttl)
                end

                if code_digest.present?
                  r.set(self.class.redis_code_key_for(code_digest), id, ex: self.class.redis_ttl)
                end
              end

              true
            end

            def update!(attrs)
              attrs.each { |k, v| public_send("#{k}=", v) if respond_to?("#{k}=") }
              save!
            end

            def destroy!
              redis.multi do |r|
                r.del(redis_key)
                r.del(self.class.redis_session_key_for(session_id)) if session_id.present?
                r.del(self.class.redis_code_key_for(code_digest)) if code_digest.present?
              end
              true
            end

            def persisted?
              redis.exists?(redis_key)
            end

          end
        end
      end
    end
  end
end
