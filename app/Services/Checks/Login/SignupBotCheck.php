<?php

namespace FluentAuth\App\Services\Checks\Login;

use FluentAuth\App\Services\Checks\Check;
use FluentAuth\App\Services\Checks\Dismissals;
use FluentAuth\App\Services\Checks\Finding;
use FluentAuth\App\Services\Turnstile;

/**
 * Whether anyone can sign up with nothing checking for bots.
 *
 * Advice, not a fault: plenty of open signup forms never meet a bot. When they do, every
 * spam signup makes the site email an address that does not exist, and the bounces hurt
 * the site's email delivery. A site with signup closed hears nothing.
 */
class SignupBotCheck extends Check
{
    public function id()
    {
        return 'signup_bot_protection';
    }

    public function group()
    {
        return 'login';
    }

    public function run()
    {
        $open = Turnstile::unguardedSignups();

        if (!$open) {
            if (!$this->signupIsOpen()) {
                return [];
            }

            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_PASSED,
                'title'  => __('Signup forms check for bots', 'fluent-security'),
                'scored' => false
            ])];
        }

        if (Dismissals::has($this->id())) {
            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_ACCEPTED,
                'title'  => __('Bots can sign up on this site', 'fluent-security'),
                'why'    => __('You have said this one is not for your site.', 'fluent-security'),
                'scored' => false
            ])];
        }

        $names = [
            'wordpress'   => __('WordPress registration is open to anyone.', 'fluent-security'),
            'woocommerce' => __('WooCommerce lets anyone create an account on the My Account page.', 'fluent-security')
        ];

        $details = array_values(array_intersect_key($names, array_flip($open)));
        $details[] = __('Cloudflare Turnstile is free. Turn it on for these forms on the Bot Protection screen.', 'fluent-security');

        return [new Finding([
            'id'       => $this->id(),
            'check'    => $this->id(),
            'group'    => $this->group(),
            'state'    => Finding::STATE_OPEN,
            'severity' => Finding::SEVERITY_ADVICE,
            'title'    => __('Bots can sign up on this site', 'fluent-security'),
            'why'      => __('Spam signups make your site send email to fake addresses. Those emails bounce, and too many bounces hurt your email delivery.', 'fluent-security'),
            'details'  => $details,
            'action'   => 'navigate',
            'label'    => __('Set up', 'fluent-security'),
            'route'    => 'settings_bot_protection',
            'dismiss'  => 'ignore',
            'scored'   => false
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
     * @return bool
     */
    private function signupIsOpen()
    {
        return (!is_multisite() && get_option('users_can_register'))
            || (class_exists('WooCommerce') && get_option('woocommerce_enable_myaccount_registration') === 'yes');
    }
}
