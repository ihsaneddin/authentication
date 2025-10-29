# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[7.0].define(version: 2025_10_24_063849) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "plpgsql"

  create_table "auth_codes", force: :cascade do |t|
    t.bigint "session_id", null: false
    t.string "code_digest", null: false
    t.datetime "expires_at", null: false
    t.datetime "consumed_at"
    t.jsonb "metadata", default: {}
    t.string "type"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["expires_at"], name: "index_auth_codes_on_expires_at"
    t.index ["session_id"], name: "index_auth_codes_on_session_id"
    t.index ["session_id"], name: "index_auth_codes_one_active_per_session", unique: true, where: "(consumed_at IS NULL)"
  end

  create_table "auth_identities", force: :cascade do |t|
    t.string "authenticatable_type", null: false
    t.bigint "authenticatable_id", null: false
    t.string "provider", null: false
    t.string "uid", null: false
    t.jsonb "info", default: {}
    t.jsonb "credentials", default: {}
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["authenticatable_type", "authenticatable_id"], name: "index_auth_identities_on_authenticatable"
    t.index ["provider", "uid"], name: "index_auth_identities_on_provider_and_uid", unique: true
  end

  create_table "auth_two_factor_authentication_providers", force: :cascade do |t|
    t.string "authenticatable_type", null: false
    t.bigint "authenticatable_id", null: false
    t.string "name", null: false
    t.string "secret"
    t.jsonb "data", default: {}
    t.datetime "enabled_at"
    t.string "type"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["authenticatable_type", "authenticatable_id", "type", "name"], name: "index_auth_2fa_providers_unique_per_authenticatable_and_type", unique: true
    t.index ["authenticatable_type", "authenticatable_id"], name: "index_auth_2fa_providers_authenticatable_id_and_type", unique: true
  end

  create_table "auth_two_factor_authentication_sessions", force: :cascade do |t|
    t.bigint "provider_id", null: false
    t.string "session_uid", null: false
    t.integer "attempts", default: 0, null: false
    t.datetime "started_at", null: false
    t.datetime "verified_at"
    t.datetime "expires_at"
    t.jsonb "metadata", default: {}
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["provider_id", "session_uid"], name: "index_auth_2fa_sessions_on_provider_and_uid", unique: true
    t.index ["provider_id"], name: "index_auth_two_factor_authentication_sessions_on_provider_id"
  end

  create_table "oauth_access_grants", force: :cascade do |t|
    t.string "resource_owner_type"
    t.bigint "resource_owner_id"
    t.bigint "application_id", null: false
    t.string "token", null: false
    t.integer "expires_in", null: false
    t.text "redirect_uri", null: false
    t.string "scopes", default: "", null: false
    t.datetime "created_at", null: false
    t.datetime "revoked_at"
    t.index ["application_id"], name: "index_oauth_access_grants_on_application_id"
    t.index ["resource_owner_id", "resource_owner_type"], name: "polymorphic_owner_oauth_access_grants"
    t.index ["token"], name: "index_oauth_access_grants_on_token", unique: true
  end

  create_table "oauth_access_tokens", force: :cascade do |t|
    t.string "resource_owner_type"
    t.bigint "resource_owner_id"
    t.bigint "application_id"
    t.text "token", null: false
    t.string "refresh_token"
    t.integer "expires_in"
    t.string "scopes"
    t.datetime "created_at", null: false
    t.datetime "revoked_at"
    t.string "previous_refresh_token", default: "", null: false
    t.index ["application_id"], name: "index_oauth_access_tokens_on_application_id"
    t.index ["refresh_token"], name: "index_oauth_access_tokens_on_refresh_token", unique: true
    t.index ["resource_owner_id", "resource_owner_type"], name: "polymorphic_owner_oauth_access_tokens"
    t.index ["token"], name: "index_oauth_access_tokens_on_token", unique: true
  end

  create_table "oauth_applications", force: :cascade do |t|
    t.string "name", null: false
    t.string "uid", null: false
    t.string "secret", null: false
    t.text "redirect_uri", null: false
    t.string "scopes", default: "", null: false
    t.boolean "confidential", default: true, null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["uid"], name: "index_oauth_applications_on_uid", unique: true
  end

  create_table "users", force: :cascade do |t|
    t.string "email", default: "", null: false
    t.string "username", default: "", null: false
    t.string "encrypted_password", default: "", null: false
    t.string "reset_password_token"
    t.datetime "reset_password_sent_at"
    t.datetime "remember_created_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["email"], name: "index_users_on_email", unique: true
    t.index ["reset_password_token"], name: "index_users_on_reset_password_token", unique: true
  end

  add_foreign_key "auth_codes", "auth_two_factor_authentication_sessions", column: "session_id"
  add_foreign_key "oauth_access_grants", "oauth_applications", column: "application_id"
  add_foreign_key "oauth_access_tokens", "oauth_applications", column: "application_id"
end
