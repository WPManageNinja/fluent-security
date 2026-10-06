<?php

namespace FluentAuth\App\Services;

/**
 * How another plugin adopts FluentAuth's login stack for its own screens.
 *
 * FluentAuth's front end forms are behind a site setting, and for a long time that
 * setting was also the only answer available to a plugin asking "can I use FluentAuth
 * here?". Those are different questions. FluentCommunity's portal asked the first one
 * and read it as the second: with the shortcodes switched off it fell back to a login
 * form of its own, while magic login, the passkey button and the second factor all
 * stayed on and went on addressing a DOM that had just been replaced. The result was a
 * form with a magic login button that could not hide the password fields and a second
 * factor that arrived as an error message.
 *
 * The setting governs whether a site's *editors* may drop `[fluent_auth_login]` into a
 * page. It was never meant to govern whether a plugin that has already built an auth
 * screen may hand that screen to FluentAuth. So a host registers here instead, and from
 * then on FluentAuth treats the requests it claims as its own: the shortcodes render,
 * the assets load, the ajax endpoints answer, and the second factor comes back inline
 * the way it does on wp-login.php.
 *
 * The whole integration is meant to be two calls:
 *
 *     // once, wherever the host boots - on every request, ajax included
 *     LoginBridge::register('fluent-community', 'is_fcom_auth');
 *
 *     // on the screen itself, before the form is rendered
 *     LoginBridge::adopt([
 *         'host'          => 'fluent-community',
 *         'redirect_to'   => $currentUrl,
 *         'hidden_fields' => ['is_fcom_auth' => 'yes'],
 *     ]);
 *
 * and then `echo do_shortcode('[fluent_auth_login]')`.
 *
 * Registration is deliberately the thing that confers trust, not the marker in the
 * request: only server side code can register, so a visitor cannot switch the front end
 * forms back on by posting a field at a site whose owner turned them off.
 */
class LoginBridge
{
    /**
     * Registered hosts, by slug, each with the test that decides whether a given
     * request is theirs.
     *
     * @var array<string, callable|string|null>
     */
    private static $hosts = [];

    /**
     * Whether this request has been claimed. Null until asked the first time - the
     * answer cannot change within a request, and isEnabled() is asked on nearly every
     * path through the plugin.
     *
     * @var bool|null
     */
    private static $claimed = null;

    /**
     * The host that called adopt() in this request, if any. Held separately from the
     * claim, because a screen being rendered satisfies no test: the marker and the
     * host's own field are things a *later* request carries, and without this the forms
     * drawn here would go out unmarked and the posts they make would not be recognised.
     *
     * @var string
     */
    private static $adopted = '';

    /**
     * A host adopt() put into $hosts because it had never registered. Kept so release()
     * can take it out again: with no test of its own it would claim every request that
     * followed.
     *
     * @var string
     */
    private static $adoptedUnregistered = '';

    /**
     * The filters adopt() added, as [hook, callback] pairs, so release() can take them
     * off again.
     *
     * @var array<int, array{0: string, 1: callable}>
     */
    private static $adoptionFilters = [];

    /**
     * The nonce action for a host's marker field. Anonymous nonces are what the rest of
     * the login endpoints already use.
     */
    const MARKER_ACTION = 'fls_host_';

    /**
     * The field a form carries to say which host drew it.
     */
    const MARKER_FIELD = '_fls_host';

    /**
     * Declares that a plugin drives FluentAuth's login on some of its own screens.
     *
     * Call this wherever the plugin boots rather than only where it renders. The form
     * posts back to admin-ajax, and that request has to be recognised too - it is a
     * different PHP process, and nothing from the render survives into it except what
     * the browser sent.
     *
     * @param $slug string the host's own identifier, e.g. its text domain
     * @param $claim callable|string|null how to tell whether a request belongs to this
     *                                    host. A string names a request field that must
     *                                    be present; a callable is asked and must return
     *                                    a bool; null claims every request, which suits a
     *                                    plugin that owns login on the whole site.
     * @param $ajaxActions array admin-ajax actions of the host's own that may be answered
     *                           with a second factor form rather than a WP_Error. Declared
     *                           here rather than at adopt() for the same reason the claim
     *                           is: the action arrives on the post, which is a request
     *                           adopt() was never called in.
     * @return void
     */
    public static function register($slug, $claim = null, $ajaxActions = [])
    {
        $slug = sanitize_key($slug);

        if (!$slug) {
            return;
        }

        self::$hosts[$slug] = $claim;
        self::$claimed = null;

        // Registered for real now, so release() must not take it out with an adoption.
        if (self::$adoptedUnregistered === $slug) {
            self::$adoptedUnregistered = '';
        }

        foreach ((array)$ajaxActions as $action) {
            self::allowInline2Fa($action);
        }
    }

    /**
     * @param $slug string
     * @return bool
     */
    public static function isRegistered($slug)
    {
        // Not isset(): a host registered with a null claim claims every request.
        return array_key_exists(sanitize_key($slug), self::$hosts);
    }

    /**
     * Whether a registered host owns this request.
     *
     * @return bool
     */
    public static function claimed()
    {
        // An adoption holds until release(), even if a later register() clears the memo.
        if (self::$adopted) {
            return true;
        }

        if (self::$claimed !== null) {
            return self::$claimed;
        }

        self::$claimed = false;

        foreach (self::$hosts as $slug => $claim) {
            if (self::hostClaims($slug, $claim)) {
                self::$claimed = true;
                break;
            }
        }

        return self::$claimed;
    }

    /**
     * Turns the stack on for the screen about to be drawn.
     *
     * Everything here is per request and per screen: the claim, the assets, the
     * redirect the forms carry and any hidden fields the host needs echoed back to its
     * own handlers. It lasts until release() or the end of the request. Safe to call
     * more than once; the second call replaces the first.
     *
     * @param $args array {
     *     @type string $host          slug passed to register(). Claims this request
     *                                 outright, so a host need not also satisfy its own
     *                                 test on the screen it is rendering.
     *     @type string $redirect_to   where a completed login should land.
     *     @type array  $hidden_fields name => value pairs printed inside the form.
     *     @type array  $ajax_actions  admin-ajax actions of the host's own, for a host
     *                                 that keeps its login endpoint and only wants the
     *                                 second factor to come back inline. Only useful when
     *                                 adopt() is called from inside that endpoint;
     *                                 declaring them at register() covers the ordinary
     *                                 case, where the post arrives long after the screen
     *                                 that adopted was rendered.
     * }
     * @return void
     */
    public static function adopt($args = [])
    {
        $args = wp_parse_args($args, [
            'host'          => '',
            'redirect_to'   => '',
            'hidden_fields' => [],
            'ajax_actions'  => []
        ]);

        self::release();

        $slug = sanitize_key($args['host']);

        if ($slug) {
            /*
             * A host rendering its screen is not asked to prove it. The test given to
             * register() exists for the request that comes back afterwards.
             */
            if (!array_key_exists($slug, self::$hosts)) {
                self::$hosts[$slug] = null;
                self::$adoptedUnregistered = $slug;
            }

            self::$adopted = $slug;
            self::$claimed = true;
        }

        LoginAssets::enqueue();

        /*
         * The marker itself is not added here. Every form FluentAuth renders asks
         * markerFields() for it, so the signup and reset password forms - which a host
         * never passes hidden fields to - carry it too.
         */
        if ($args['hidden_fields']) {
            self::printHiddenFields((array)$args['hidden_fields']);
        }

        if ($args['redirect_to']) {
            self::setRedirect($args['redirect_to']);
        }

        foreach ((array)$args['ajax_actions'] as $action) {
            self::addAdoptionFilter('fluent_auth/can_render_2fa_inline', self::inline2FaFilter($action));
        }
    }

    /**
     * Ends the adoption adopt() began, once the host's form has been rendered.
     *
     * Without this the adoption lasts the rest of the request, and any other FluentAuth
     * form drawn later on the same page - a signup shortcode further down, another
     * plugin's login - would carry this host's marker and redirect, and render even with
     * the forms setting off. Registration is left alone: the form just rendered posts
     * back in a later request, and that is what register() is for.
     *
     * @return void
     */
    public static function release()
    {
        foreach (self::$adoptionFilters as $filter) {
            remove_filter($filter[0], $filter[1]);
        }

        if (self::$adoptedUnregistered) {
            unset(self::$hosts[self::$adoptedUnregistered]);
        }

        self::$adoptionFilters = [];
        self::$adoptedUnregistered = '';
        self::$adopted = '';
        self::$claimed = null;
    }

    /**
     * The marker FluentAuth prints inside its own forms while adopted.
     *
     * The login form gets it through `login_form_top`, but the signup and reset
     * password forms build their fields themselves and ask for it here. Without it only
     * the login post would be recognised, and a host's password reset - which posts a
     * form with none of the host's own fields on it - would be refused on a site whose
     * setting is off.
     *
     * @return string
     */
    public static function markerFields()
    {
        if (!self::claimed()) {
            return '';
        }

        $slug = self::claimingHost();

        if (!$slug) {
            return '';
        }

        return '<input type="hidden" name="' . esc_attr(self::MARKER_FIELD) . '" value="' . esc_attr($slug) . '" />'
            . '<input type="hidden" name="' . esc_attr(self::MARKER_FIELD . '_sig') . '" value="'
            . esc_attr(wp_create_nonce(self::MARKER_ACTION . $slug)) . '" />';
    }

    /**
     * Whether FluentAuth's login stack can be adopted at all, for a host that wants to
     * feature detect before committing to it.
     *
     * @return bool
     */
    public static function isAvailable()
    {
        return defined('FLUENT_AUTH_VERSION');
    }

    /**
     * Forgets every registration. Tests only - a host registers at boot and stays
     * registered for the life of the request.
     *
     * @return void
     */
    public static function reset()
    {
        self::release();
        self::$hosts = [];
    }

    /**
     * @param $slug string
     * @param $claim callable|string|null
     * @return bool
     */
    private static function hostClaims($slug, $claim)
    {
        if (self::markerNames($slug)) {
            return true;
        }

        if ($claim === null) {
            return true;
        }

        if (is_string($claim)) {
            return !empty($_REQUEST[$claim]); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        }

        return is_callable($claim) && (bool)call_user_func($claim, $slug);
    }

    /**
     * Whether the request carries this host's signed marker.
     *
     * @param $slug string
     * @return bool
     */
    private static function markerNames($slug)
    {
        // phpcs:disable WordPress.Security.NonceVerification.Recommended
        if (empty($_REQUEST[self::MARKER_FIELD]) || empty($_REQUEST[self::MARKER_FIELD . '_sig'])) {
            return false;
        }

        if (sanitize_key(wp_unslash($_REQUEST[self::MARKER_FIELD])) !== $slug) {
            return false;
        }

        $sig = sanitize_text_field(wp_unslash($_REQUEST[self::MARKER_FIELD . '_sig']));
        // phpcs:enable WordPress.Security.NonceVerification.Recommended

        return (bool)wp_verify_nonce($sig, self::MARKER_ACTION . $slug);
    }

    /**
     * @return string the slug of whichever registered host claimed this request
     */
    private static function claimingHost()
    {
        if (self::$adopted) {
            return self::$adopted;
        }

        foreach (self::$hosts as $slug => $claim) {
            if (self::hostClaims($slug, $claim)) {
                return $slug;
            }
        }

        return '';
    }

    /**
     * @param $fields array
     * @return void
     */
    private static function printHiddenFields($fields)
    {
        self::addAdoptionFilter('login_form_top', function ($html) use ($fields) {
            foreach ($fields as $name => $value) {
                $html .= '<input type="hidden" name="' . esc_attr($name) . '" value="' . esc_attr($value) . '" />';
            }

            return $html;
        });
    }

    /**
     * @param $url string
     * @return void
     */
    private static function setRedirect($url)
    {
        self::addAdoptionFilter('fluent_auth/login_form_args', function ($args) use ($url) {
            $args['redirect'] = $url;
            $args['force_redirect_to'] = $url;

            return $args;
        });

        self::addAdoptionFilter('fluent_auth/social_redirect_to', function () use ($url) {
            return $url;
        });
    }

    /**
     * @param $hook string
     * @param $callback callable
     * @return void
     */
    private static function addAdoptionFilter($hook, $callback)
    {
        add_filter($hook, $callback);
        self::$adoptionFilters[] = [$hook, $callback];
    }

    /**
     * @param $action string
     * @return void
     */
    private static function allowInline2Fa($action)
    {
        add_filter('fluent_auth/can_render_2fa_inline', self::inline2FaFilter($action));
    }

    /**
     * @param $action string
     * @return \Closure
     */
    private static function inline2FaFilter($action)
    {
        return function ($can) use ($action) {
            if ($can) {
                return $can;
            }

            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            return !empty($_REQUEST['action']) && $_REQUEST['action'] === $action;
        };
    }
}
