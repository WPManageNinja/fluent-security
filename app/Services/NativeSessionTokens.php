<?php

namespace FluentAuth\App\Services;

/** Native storage with per-operation deltas, rather than stale whole-map replacement. */
class NativeSessionTokens extends \WP_User_Meta_Session_Tokens
{
    private static $creating = [];

    public static function selectManager($manager)
    {
        return !is_multisite() && self::nativeDatabase() && $manager === 'WP_User_Meta_Session_Tokens' ? self::class : $manager;
    }

    protected function update_session($verifier, $session = null)
    {
        if (!$this->nativeMetadata()) {
            return parent::update_session($verifier, $session);
        }
        $existed = (bool)$this->get_session($verifier);
        $this->write(function ($sessions) use ($verifier, $session, $existed) {
            if (!$session) {
                unset($sessions[$verifier]);
            } elseif (!$existed || isset($sessions[$verifier])) {
                $sessions[$verifier] = $session;
            }
            return $sessions;
        });
    }

    protected function destroy_other_sessions($verifier)
    {
        if (!$this->nativeMetadata()) {
            return parent::destroy_other_sessions($verifier);
        }
        $this->write(function ($sessions) use ($verifier) {
            return isset($sessions[$verifier]) ? [$verifier => $sessions[$verifier]] : [];
        });
    }

    protected function destroy_all_sessions()
    {
        if (!$this->nativeMetadata()) {
            return parent::destroy_all_sessions();
        }
        $this->write(function () { return []; });
    }

    public function pruneForLogin($token, $limit)
    {
        if (!$this->nativeMetadata()) {
            return false;
        }
        $key = hash('sha256', $token);
        $this->mutate(function ($sessions) use ($key, $limit) {
            if (!isset($sessions[$key])) {
                return null;
            }
            $others = $sessions;
            unset($others[$key]);
            uksort($others, function ($a, $b) use ($others) {
                return ((int)($others[$a]['login'] ?? 0) <=> (int)($others[$b]['login'] ?? 0)) ?: strcmp($a, $b);
            });
            foreach (array_slice(array_keys($others), 0, max(0, count($others) - $limit + 1)) as $old) {
                unset($sessions[$old]);
            }
            return $sessions;
        });
        // A metadata short-circuit may have performed the write itself. Verify its actual result too.
        $rows = $this->rows();
        $sessions = $rows === null ? null : $this->sessionsFromRows($rows);
        if ($sessions !== null && !isset($sessions[$key])) {
            return false;
        }
        if ($sessions === null || count($sessions) > $limit) {
            wp_die(esc_html__('We could not finish signing you in. Please try again.', 'fluent-security'), '', ['response' => 503]);
        }
        return true;
    }

    private function nativeMetadata()
    {
        return self::nativeDatabase() && apply_filters('get_user_metadata', null, $this->user_id, 'session_tokens', true, 'user') === null;
    }

    private static function nativeDatabase()
    {
        global $wpdb;
        return get_class($wpdb) === 'wpdb' && $wpdb->is_mysql;
    }

    private function rows()
    {
        global $wpdb;
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT umeta_id, meta_value FROM {$wpdb->usermeta} WHERE user_id = %d AND meta_key = %s ORDER BY umeta_id",
            $this->user_id, 'session_tokens'
        ));
        return $wpdb->last_error === '' && is_array($rows) ? $rows : null;
    }

    private function sessionsFromRows($rows)
    {
        $sessions = $rows ? maybe_unserialize($rows[0]->meta_value) : [];
        if (!is_array($sessions)) {
            return [];
        }
        return array_filter(array_map([$this, 'prepare_session'], $sessions), [$this, 'is_still_valid']);
    }

    private function write(callable $change)
    {
        if ($this->mutate($change) === false) {
            wp_die(esc_html__('We could not update your sign-ins. Please try again.', 'fluent-security'), '', ['response' => 503]);
        }
    }

    private function mutate(callable $change)
    {
        global $wpdb;
        $userId = (int)$this->user_id;
        for ($attempt = 0; $attempt < 3; $attempt++) {
            $rows = $this->rows();
            if ($rows === null) {
                return false;
            }
            $candidate = $change($this->sessionsFromRows($rows));
            if ($candidate === null) {
                return false;
            }
            $updating = (bool)$candidate;
            $next = $updating ? sanitize_meta('session_tokens', $candidate, 'user', get_object_subtype('user', $userId)) : [];
            $check = $updating
                ? apply_filters('update_user_metadata', null, $userId, 'session_tokens', $next, '')
                : apply_filters('delete_user_metadata', null, $userId, 'session_tokens', '', false);
            if ($check !== null) {
                return true; // The metadata provider owns this decision; lifecycle APIs return void.
            }
            if (!$rows) {
                if (!$updating) {
                    return true;
                }
                $inserted = $this->insertFirstRow($candidate);
                if ($inserted === null) {
                    continue;
                }
                return $inserted;
            }
            $serialized = maybe_serialize($next);
            $canonical = array_shift($rows);
            if ($rows && !$this->removeDuplicates($rows, $updating)) {
                return false;
            }
            if ($updating && $canonical->meta_value === $serialized) {
                return true;
            }
            $id = (int)$canonical->umeta_id;
            if ($updating) {
                do_action('update_user_meta', $id, $userId, 'session_tokens', $next);
            } else {
                do_action('delete_user_meta', [$id], $userId, 'session_tokens', '');
            }
            $where = $wpdb->prepare('WHERE umeta_id = %d AND user_id = %d AND meta_key = %s AND ', $id, $userId, 'session_tokens');
            $where .= $canonical->meta_value === null ? 'meta_value IS NULL'
                : $wpdb->prepare('BINARY meta_value = BINARY %s', $canonical->meta_value);
            $sql = $updating ? $wpdb->prepare("UPDATE {$wpdb->usermeta} SET meta_value = %s ", $serialized) : "DELETE FROM {$wpdb->usermeta} ";
            $updated = $wpdb->query($sql . $where);
            if ($updated === false) {
                return false;
            }
            if (!$updated) {
                continue;
            }
            wp_cache_delete($userId, 'user_meta');
            if ($updating) {
                do_action('updated_user_meta', $id, $userId, 'session_tokens', $next);
            } else {
                do_action('deleted_user_meta', [$id], $userId, 'session_tokens', '');
            }
            return true;
        }
        return false;
    }

    private function removeDuplicates($rows, $updating)
    {
        global $wpdb;
        $userId = (int)$this->user_id;
        if ($updating && apply_filters('delete_user_metadata', null, $userId, 'session_tokens', '', false) !== null) {
            return true;
        }
        $ids = array_map(function ($row) { return (int)$row->umeta_id; }, $rows);
        do_action('delete_user_meta', $ids, $userId, 'session_tokens', '');
        $removed = $wpdb->query($wpdb->prepare(
            "DELETE FROM {$wpdb->usermeta} WHERE user_id = %d AND meta_key = %s AND umeta_id IN (" . implode(',', array_fill(0, count($ids), '%d')) . ')',
            $userId, 'session_tokens', ...$ids
        ));
        if ($removed === false) {
            return false;
        }
        if ($removed) {
            wp_cache_delete($userId, 'user_meta');
            do_action('deleted_user_meta', $ids, $userId, 'session_tokens', '');
        }
        return true;
    }

    private function insertFirstRow($sessions)
    {
        global $wpdb;
        $userId = (int)$this->user_id;
        if (isset(self::$creating[$userId])) {
            return false;
        }
        // Usermeta has no unique (user,key) index. Coordinate only initial insertion, without polling.
        $name = 'fls_session_' . sha1(constant('DB_NAME') . ':' . $wpdb->usermeta . ':' . $userId);
        if ((string)$wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, 0)', $name)) !== '1') {
            return false;
        }
        self::$creating[$userId] = true;
        try {
            $rows = $this->rows();
            if ($rows === null) {
                return false;
            }
            if ($rows) {
                return null; // A competing initial insert won: recompute the delta against it.
            }
            $inserted = add_user_meta($userId, 'session_tokens', wp_slash($sessions));
            return (bool)$inserted || $wpdb->last_error === ''; // Preserve add-metadata short-circuits.
        } finally {
            unset(self::$creating[$userId]);
            $wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $name));
        }
    }
}
