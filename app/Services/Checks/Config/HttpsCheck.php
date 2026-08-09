<?php

namespace FluentAuth\App\Services\Checks\Config;

use FluentAuth\App\Services\Checks\Check;
use FluentAuth\App\Services\Checks\Dismissals;
use FluentAuth\App\Services\Checks\Finding;

/**
 * Whether the site is served over HTTPS at all.
 *
 * Everything else this plugin does is undone by its absence. Two-factor codes, magic links
 * and passwords all cross the network in the clear on an http site, and anyone on the same
 * network can read them - so this outranks every other configuration finding on the list.
 *
 * Not fixable from here, and not pretended otherwise: it needs a certificate, which comes
 * from the host. What the row can do is say plainly that the rest of the plugin's work is
 * being given away, and where to go about it.
 */
class HttpsCheck extends Check
{
    public function id()
    {
        return 'https';
    }

    public function group()
    {
        return 'config';
    }

    public function run()
    {
        if ($this->isSecure()) {
            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_PASSED,
                'title'  => __('Your site is served securely', 'fluent-security'),
                'scored' => true
            ])];
        }

        /*
         * Local development is the one place an http site is ordinary rather than alarming,
         * and telling somebody their laptop is insecure every day is how they learn to skim
         * the list that will one day matter.
         */
        if ($this->isLocal()) {
            return [];
        }

        if (Dismissals::has($this->id())) {
            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_ACCEPTED,
                'title'  => __('Your site is not served securely', 'fluent-security'),
                'why'    => __('You have said this one is not for your site.', 'fluent-security'),
                'scored' => false
            ])];
        }

        return [new Finding([
            'id'       => $this->id(),
            'check'    => $this->id(),
            'group'    => $this->group(),
            'state'    => Finding::STATE_OPEN,
            'severity' => Finding::SEVERITY_FIX,
            'title'    => __('Passwords are sent to your site unencrypted', 'fluent-security'),
            'why'      => __('Your site is served over http, so passwords, two-factor codes and login links can be read by anyone on the same network. Almost every host now provides a certificate free of charge.', 'fluent-security'),
            'details'  => [
                sprintf(
                    /* translators: %s: the site address */
                    __('Your site address is %s', 'fluent-security'),
                    home_url()
                ),
                __('Ask your host to enable HTTPS, then change both addresses under Settings → General.', 'fluent-security')
            ],
            'action'   => 'navigate',
            'label'    => __('Open settings', 'fluent-security'),
            'url'      => admin_url('options-general.php'),
            'dismiss'  => 'ignore',
            'scored'   => true
        ])];
    }

    /**
     * @param string $findingId
     * @return array|\WP_Error
     */
    public function accept($findingId)
    {
        if ($findingId !== $this->id()) {
            return new \WP_Error('unknown_check', __('That is not something this plugin knows how to check.', 'fluent-security'), ['status' => 404]);
        }

        Dismissals::add($this->id());

        return ['message' => __('Noted. This will not be mentioned again.', 'fluent-security')];
    }

    /**
     * @param string $findingId
     * @return array|\WP_Error
     */
    public function unaccept($findingId)
    {
        if ($findingId !== $this->id()) {
            return new \WP_Error('unknown_check', __('There is nothing to undo for this one.', 'fluent-security'), ['status' => 404]);
        }

        Dismissals::remove($this->id());

        return ['message' => __('This is back on the list.', 'fluent-security')];
    }

    /**
     * Read from the site's own addresses rather than from this request. An admin reached over
     * https on a site whose public address is http is still a site handing visitors' logins
     * across the network in the clear.
     *
     * @return bool
     */
    protected function isSecure()
    {
        return strpos(strtolower((string)get_option('home')), 'https://') === 0
            && strpos(strtolower((string)get_option('siteurl')), 'https://') === 0;
    }

    /**
     * Whether this is somebody's own machine rather than a site the public can reach.
     *
     * WordPress's own answer first, but most people never set WP_ENVIRONMENT_TYPE, so the
     * hostname is consulted too. Only suffixes that cannot resolve on the public internet are
     * treated as local - being wrong in this direction means silently excusing a real site
     * from the most important row on the list, so the list is short on purpose.
     *
     * Filtered rather than final: a site behind a proxy, or one using a hostname nobody
     * anticipated, needs a way to say so that is not "edit the plugin".
     *
     * @return bool
     */
    protected function isLocal()
    {
        $environment = function_exists('wp_get_environment_type') ? wp_get_environment_type() : 'production';

        $host = strtolower((string)wp_parse_url(home_url(), PHP_URL_HOST));

        $isLocal = in_array($environment, ['local', 'development'], true)
            || in_array($host, ['localhost', '127.0.0.1', '::1'], true)
            || (bool)preg_match('/\.(test|local|localhost|invalid|example)$/', $host);

        return (bool)apply_filters('fluent_auth/is_local_site', $isLocal, $host, $environment);
    }
}
