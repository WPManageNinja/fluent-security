<?php

namespace FluentAuth\App\Services\Checks;

/**
 * The things a site has said are not for it.
 *
 * One list, one option, shared by every check that can be declined - so there is one place
 * a decision lives and the reader is never hunting for where they turned something off.
 *
 * Declining is not the same as doing. A check that has been declined leaves the score
 * altogether rather than counting as satisfied; each check expresses that by reporting the
 * dismissed finding as unscored. If it counted, turning everything down would be the quickest
 * route to a hundred per cent and the number would stop meaning anything.
 */
class Dismissals
{
    const OPTION = '__fls_dismissed_checks';

    /**
     * @return array
     */
    public static function all()
    {
        $dismissed = get_option(self::OPTION, []);

        return is_array($dismissed) ? $dismissed : [];
    }

    /**
     * @param string $key
     * @return bool
     */
    public static function has($key)
    {
        return in_array($key, self::all(), true);
    }

    /**
     * @param string $key
     * @return void
     */
    public static function add($key)
    {
        $dismissed = self::all();

        if (!in_array($key, $dismissed, true)) {
            $dismissed[] = $key;
            update_option(self::OPTION, $dismissed, false);
        }
    }

    /**
     * @param string $key
     * @return void
     */
    public static function remove($key)
    {
        update_option(self::OPTION, array_values(array_diff(self::all(), [$key])), false);
    }
}
