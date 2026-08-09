<?php

namespace FluentAuth\App\Services\Checks\Config;

use FluentAuth\App\Services\Checks\Check;
use FluentAuth\App\Services\Checks\Dismissals;
use FluentAuth\App\Services\Checks\Finding;

/**
 * The two settings that live in wp-config.php.
 *
 * Shared shape because they share the awkward part: this plugin will not write to
 * wp-config.php. It is the one file a WordPress install cannot survive being wrong, an
 * automated edit to it can end a site, and no security benefit either of these buys is worth
 * that risk taken on somebody else's behalf.
 *
 * So the row has no button, and the exact line to add is in the details instead. That is
 * still a row worth drawing - the reader can act on it, or hand it to whoever looks after
 * their site - but it is deliberately not counted in the score, because a recommendation
 * that needs a text editor and SFTP is not one every site can reach.
 */
abstract class ConfigConstantCheck extends Check
{
    public function group()
    {
        return 'config';
    }

    /**
     * @return bool whether the site is already in the state we would want
     */
    abstract protected function isSatisfied();

    /**
     * @return array title, why, snippet
     */
    abstract protected function words();

    public function run()
    {
        $words = $this->words();

        if ($this->isSatisfied()) {
            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_PASSED,
                'title'  => $words['passed'],
                'scored' => false
            ])];
        }

        if (Dismissals::has($this->id())) {
            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_ACCEPTED,
                'title'  => $words['title'],
                'why'    => __('You have said this one is not for your site.', 'fluent-security'),
                'scored' => false
            ])];
        }

        return [new Finding([
            'id'       => $this->id(),
            'check'    => $this->id(),
            'group'    => $this->group(),
            'state'    => Finding::STATE_OPEN,
            'severity' => $words['severity'],
            'title'    => $words['title'],
            'why'      => $words['why'],
            'details'  => [
                __('Add this line to your wp-config.php, above the line that says "That\'s all, stop editing".', 'fluent-security'),
                $words['snippet']
            ],
            /*
             * No button on purpose. This plugin does not edit wp-config.php, and a button that
             * pretended to would be the most dangerous thing it does.
             */
            'action'   => 'none',
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
            return new \WP_Error(
                'unknown_check',
                __('That is not something this plugin knows how to check.', 'fluent-security'),
                ['status' => 404]
            );
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
            return new \WP_Error(
                'unknown_check',
                __('There is nothing to undo for this one.', 'fluent-security'),
                ['status' => 404]
            );
        }

        Dismissals::remove($this->id());

        return ['message' => __('This is back on the list.', 'fluent-security')];
    }
}
