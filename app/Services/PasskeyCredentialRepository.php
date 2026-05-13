<?php

namespace FluentAuth\App\Services;

class PasskeyCredentialRepository
{
    public static function tableName()
    {
        global $wpdb;
        return $wpdb->prefix . 'fls_passkey_credentials';
    }

    public static function maybeCreateTable()
    {
        global $wpdb;

        $table = self::tableName();
        if ($wpdb->get_var("SHOW TABLES LIKE '$table'") == $table) {
            return;
        }

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $charsetCollate = $wpdb->get_charset_collate();
        $sql = "CREATE TABLE $table (
            id BIGINT UNSIGNED NOT NULL PRIMARY KEY AUTO_INCREMENT,
            user_id BIGINT UNSIGNED NOT NULL,
            credential_id_hash CHAR(64) NOT NULL,
            credential_id LONGTEXT NOT NULL,
            public_key LONGTEXT NOT NULL,
            cose_key LONGTEXT NULL,
            alg INT NULL,
            sign_count BIGINT UNSIGNED DEFAULT 0,
            transports TEXT NULL,
            aaguid VARCHAR(64) NULL,
            attestation_type VARCHAR(50) NULL,
            name VARCHAR(100) NULL,
            last_used_at DATETIME NULL,
            created_at DATETIME NULL,
            updated_at DATETIME NULL,
            UNIQUE KEY credential_id_hash (credential_id_hash),
            KEY user_id (user_id),
            KEY created_at (created_at)
        ) $charsetCollate;";

        dbDelta($sql);
    }

    public static function getByUserId($userId)
    {
        self::maybeCreateTable();

        return flsDb()->table('fls_passkey_credentials')
            ->where('user_id', (int)$userId)
            ->orderBy('created_at', 'DESC')
            ->get();
    }

    public static function getByCredentialId($credentialId)
    {
        self::maybeCreateTable();

        return flsDb()->table('fls_passkey_credentials')
            ->where('credential_id_hash', self::credentialHash($credentialId))
            ->first();
    }

    public static function create($data)
    {
        self::maybeCreateTable();

        $now = current_time('mysql');

        return flsDb()->table('fls_passkey_credentials')->insert([
            'user_id'            => (int)$data['user_id'],
            'credential_id_hash' => self::credentialHash($data['credential_id']),
            'credential_id'      => $data['credential_id'],
            'public_key'         => $data['public_key'],
            'cose_key'           => $data['cose_key'],
            'alg'                => (int)$data['alg'],
            'sign_count'         => (int)$data['sign_count'],
            'transports'         => maybe_serialize($data['transports']),
            'aaguid'             => sanitize_text_field($data['aaguid']),
            'attestation_type'   => sanitize_text_field($data['attestation_type']),
            'name'               => sanitize_text_field($data['name']),
            'created_at'         => $now,
            'updated_at'         => $now
        ]);
    }

    public static function updateUsed($id, $signCount)
    {
        self::maybeCreateTable();

        return flsDb()->table('fls_passkey_credentials')
            ->where('id', (int)$id)
            ->update([
                'sign_count'   => (int)$signCount,
                'last_used_at' => current_time('mysql'),
                'updated_at'   => current_time('mysql')
            ]);
    }

    public static function delete($id, $userId)
    {
        self::maybeCreateTable();

        return flsDb()->table('fls_passkey_credentials')
            ->where('id', (int)$id)
            ->where('user_id', (int)$userId)
            ->delete();
    }

    public static function credentialHash($credentialId)
    {
        return hash('sha256', $credentialId);
    }

    public static function formatCredential($credential)
    {
        return [
            'id'           => (int)$credential->id,
            'name'         => $credential->name ?: __('Passkey', 'fluent-security'),
            'created_at'   => $credential->created_at,
            'last_used_at' => $credential->last_used_at,
            'transports'   => maybe_unserialize($credential->transports) ?: []
        ];
    }
}
