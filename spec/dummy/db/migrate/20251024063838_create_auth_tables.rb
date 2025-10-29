class CreateAuthTables < ActiveRecord::Migration[7.0]
  def change
    #
    # === auth_identities
    #
    create_table :auth_identities do |t|
      t.references :authenticatable, polymorphic: true, null: false
      t.string  :provider, null: false   # e.g. "google_oauth2", "phone"
      t.string  :uid,      null: false   # provider-specific UID
      t.jsonb   :info,        default: {}
      t.jsonb   :credentials, default: {}
      t.timestamps

      t.index [:provider, :uid], unique: true, name: "index_auth_identities_on_provider_and_uid"
    end

    #
    # === auth_two_factor_authentication_providers
    #
    create_table :auth_two_factor_authentication_providers do |t|
      t.references :authenticatable, polymorphic: true, null: false, index: false
      t.string    :name, null: false
      t.string    :secret     # compatible with Rails encrypts :secret
      t.jsonb     :data, default: {}
      t.datetime  :enabled_at
      t.string    :type
      t.timestamps

      t.index [:authenticatable_type, :authenticatable_id],
              unique: true,
              name: "index_auth_2fa_providers_authenticatable_id_and_type"

      t.index [:authenticatable_type, :authenticatable_id, :type, :name],
              unique: true,
              name: "index_auth_2fa_providers_unique_per_authenticatable_and_type"
    end

    #
    # === auth_otp_sessions
    #
    create_table :auth_two_factor_authentication_sessions do |t|
      t.references :provider, null: false
      t.string  :session_uid, null: false           # UUID or token to correlate requests
      t.integer :attempts, default: 0, null: false  # total attempts in this session
      t.datetime :started_at, null: false
      t.datetime :verified_at
      t.datetime :expires_at
      t.jsonb   :metadata, default: {}
      t.timestamps

      t.index [:provider_id, :session_uid], unique: true,
            name: "index_auth_2fa_sessions_on_provider_and_uid"
    end

    #
    # === auth_codes
    #

    create_table :auth_codes do |t|
      t.references :session, null: false, foreign_key: { to_table: :auth_two_factor_authentication_sessions }
      t.string   :code_digest, null: false   # hashed code if stored
      t.datetime :expires_at,  null: false
      t.datetime :consumed_at
      t.jsonb    :metadata,    default: {}
      t.string   :type
      t.timestamps

      t.index :expires_at, name: "index_auth_codes_on_expires_at"
    end

    reversible do |dir|
      dir.up do
        if connection.adapter_name.downcase.include?("postgresql")
          # Unique index for unconsumed codes per session
          execute <<-SQL.squish
            CREATE UNIQUE INDEX index_auth_codes_one_active_per_session
            ON auth_codes (session_id)
            WHERE consumed_at IS NULL;
          SQL
        end
      end

      dir.down do
        if connection.adapter_name.downcase.include?("postgresql")
          execute "DROP INDEX IF EXISTS index_auth_codes_one_active_per_session;"
        end
      end
    end

    #
    # === oauth_applications
    #
     create_table :oauth_applications do |t|
      t.string  :name,    null: false
      t.string  :uid,     null: false
      # Remove `null: false` or use conditional constraint if you are planning to use public clients.
      t.string  :secret,  null: false

      # Remove `null: false` if you are planning to use grant flows
      # that doesn't require redirect URI to be used during authorization
      # like Client Credentials flow or Resource Owner Password.
      t.text    :redirect_uri, null: false
      t.string  :scopes,       null: false, default: ''
      t.boolean :confidential, null: false, default: true
      t.timestamps             null: false
    end

    add_index :oauth_applications, :uid, unique: true

    #
    # === oauth_access_grants
    #
    create_table :oauth_access_grants do |t|
      t.references :resource_owner,  polymorphic: true, index: false
      t.references :application,     null: false
      t.string   :token,             null: false
      t.integer  :expires_in,        null: false
      t.text     :redirect_uri,      null: false
      t.string   :scopes,            null: false, default: ''
      t.datetime :created_at,        null: false
      t.datetime :revoked_at
    end

    add_index :oauth_access_grants, :token, unique: true
    add_index :oauth_access_grants,
              [:resource_owner_id, :resource_owner_type],
              name: 'polymorphic_owner_oauth_access_grants'
    add_foreign_key(
      :oauth_access_grants,
      :oauth_applications,
      column: :application_id
    )

    #
    # === oauth_access_tokens
    #

    create_table :oauth_access_tokens do |t|
      t.references :resource_owner, polymorphic: true, index: false

      # Remove `null: false` if you are planning to use Password
      # Credentials Grant flow that doesn't require an application.
      t.references :application

      # If you use a custom token generator you may need to change this column
      # from string to text, so that it accepts tokens larger than 255
      # characters. More info on custom token generators in:
      # https://github.com/doorkeeper-gem/doorkeeper/tree/v3.0.0.rc1#custom-access-token-generator
      #
      t.text :token, null: false
      #t.string :token, null: false

      t.string   :refresh_token
      t.integer  :expires_in
      t.string   :scopes
      t.datetime :created_at, null: false
      t.datetime :revoked_at

      # The authorization server MAY issue a new refresh token, in which case
      # *the client MUST discard the old refresh token* and replace it with the
      # new refresh token. The authorization server MAY revoke the old
      # refresh token after issuing a new refresh token to the client.
      # @see https://datatracker.ietf.org/doc/html/rfc6749#section-6
      #
      # Doorkeeper implementation: if there is a `previous_refresh_token` column,
      # refresh tokens will be revoked after a related access token is used.
      # If there is no `previous_refresh_token` column, previous tokens are
      # revoked as soon as a new access token is created.
      #
      # Comment out this line if you want refresh tokens to be instantly
      # revoked after use.
      t.string   :previous_refresh_token, null: false, default: ""
    end

    add_index :oauth_access_tokens, :token, unique: true
    add_index :oauth_access_tokens,
              [:resource_owner_id, :resource_owner_type],
              name: 'polymorphic_owner_oauth_access_tokens'

    # See https://github.com/doorkeeper-gem/doorkeeper/issues/1592
    if ActiveRecord::Base.connection.adapter_name == "SQLServer"
      execute <<~SQL.squish
        CREATE UNIQUE NONCLUSTERED INDEX index_oauth_access_tokens_on_refresh_token ON oauth_access_tokens(refresh_token)
        WHERE refresh_token IS NOT NULL
      SQL
    else
      add_index :oauth_access_tokens, :refresh_token, unique: true
    end

    add_foreign_key(
      :oauth_access_tokens,
      :oauth_applications,
      column: :application_id
    )

    # Uncomment below to ensure a valid reference to the resource owner's table
    # add_foreign_key :oauth_access_grants, <model>, column: :resource_owner_id
    # add_foreign_key :oauth_access_tokens, <model>, column: :resource_owner_id


  end
end
