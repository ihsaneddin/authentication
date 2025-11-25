module Auth
  module Models
    module Decorators
      module TwoFactorAuthenticationSession
        module Object

          class Metadata

            include ::StoreModel::Model

            attribute :sent_at,           :datetime
            attribute :sent_count,        :integer, default: 0
            attribute :delivery_status,   :string, default: "pending" # pending/sent/throttled/failed
            attribute :next_allowed_delivery_at,   :datetime
            attribute :error_code,        :string
            attribute :error_message,     :string
            attribute :channel,           :string

          end

          extend ActiveSupport::Concern

          included do

            include Plugins::Models::Concerns::IdempotencyLockable
            include Plugins::Models::Concerns::CustomAttributes

            belongs_to :provider, class_name: "Auth::TwoFactorAuthenticationProvider", foreign_key: "provider_id"

            scope :unverified, -> { where(verified_at: nil) }
            scope :not_expired, -> { where("expires_at IS NULL OR expires_at > ?", Time.current) }
            scope :with_attempts_left, ->(limit) { where("attempts < ?", limit) }
            scope :cooling_down, ->(limit, cooldown) {
              unverified.not_expired
                .where("attempts >= ?", limit)
                .where("updated_at >= ?", Time.current - cooldown)
            }

            attr_accessor :current_authentication

            custom_attributes_definition :metadata, Metadata, accessor: true, prefix: ""

            validates :session_uid, presence: true

            before_validation do
              self.session_uid ||= "#{SecureRandom.hex(8)}"
            end

            before_validation on: :create do
              self.started_at = Time.now
            end

            after_validation on: :create do
              self.expires_at ||= Time.now + 10.minutes
            end


            [:before_validation, :validate, :after_validation, :before_create, :after_create, :before_save, :after_save].each do |callback|
              send(callback) do
                if provider && provider.config
                  provider.config.session.callbacks.with_context(self) do
                    provider.config.session.callbacks.send(callback)
                  end
                end
              end
            end

          end

          def attempt! max_attempts: 3, now: Time.current, &block
            raise ::Auth::Errors::TwoFactorAuthentication::SessionMaxAttemptsReached if attempts >= max_attempts
            raise ::Auth::Errors::TwoFactorAuthentication::SessionAlreadyVerified if verified_at.present?
            raise ::Auth::Errors::TwoFactorAuthentication::SessionExpired if expires_at.present? && expires_at <= now
            result = yield
            increment(:attempts)
            if result
              self.verified_at= now
            end
            save(:validate => false)
            result
          end

          def expire!(now = Time.current)
            update!(expire_at: now)
          end

          def expired?(now = Time.current)
            expires_at >= now
          end

          def max_attempt_reached_and_failed?
            attempts >= max_attempts && verified_at.nil?
          end

        end
      end
    end
  end
end