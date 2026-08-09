<?php

namespace FluentAuth\App\Services\Checks;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Services\SecurityChecks;

/**
 * The plugin's own settings, as findings.
 *
 * Deliberately an adapter over SecurityChecks rather than a rewrite of it. That class holds
 * three things worth more than the tidiness of a uniform hierarchy: what counts as
 * recommended comes from Helper::getRecommendedSettings(), so the checklist and the
 * "apply recommended" button cannot disagree; a check can report `in_use`, which is what
 * stopped the list scolding sites for configurations they chose on purpose; and apply()
 * re-reads its evidence and refuses on its own terms, so the endpoint cannot be talked into
 * writing an arbitrary setting. Re-expressing all of that as check classes would risk every
 * bit of it to gain nothing the screen can see.
 *
 * So this maps one vocabulary onto another, and the settings half of the security screen
 * behaves exactly as the dashboard checklist did.
 */
class SettingsCheck extends Check
{
    public function id()
    {
        return 'settings';
    }

    public function group()
    {
        return 'login';
    }

    public function cost()
    {
        return self::COST_INSTANT;
    }

    public function run()
    {
        $checklist = SecurityChecks::get();

        $findings = [];

        foreach (Arr::get($checklist, 'items', []) as $item) {
            $findings[] = $this->toFinding($item);
        }

        return $findings;
    }

    public function fix($findingId)
    {
        $key = $this->keyFromFindingId($findingId);

        if (!$key) {
            return new \WP_Error(
                'unknown_check',
                __('That is not something this plugin can turn on.', 'fluent-security'),
                ['status' => 404]
            );
        }

        /*
         * Every reason to refuse is SecurityChecks' to give - including whether the setting is
         * in use, which it re-reads rather than trusting whatever the screen was showing when
         * the button was drawn.
         */
        return SecurityChecks::apply($key);
    }

    /**
     * @param array $item
     * @return Finding
     */
    protected function toFinding($item)
    {
        $state = Arr::get($item, 'state');
        $scored = !empty($item['scored']);

        /*
         * `in_use` is not a failing and never renders as one - it is the plugin reporting
         * that something on this site relies on the setting being off, with the evidence for
         * saying so. It stays on screen as a fact, with no button to press.
         */
        $inUse = $state === 'in_use';

        $finding = [
            'id'       => $this->id() . '_' . Arr::get($item, 'key'),
            'check'    => $this->id(),
            'group'    => Arr::get($item, 'group', 'login'),
            'state'    => $state === 'done' ? Finding::STATE_PASSED : Finding::STATE_OPEN,
            /*
             * Only a scored recommendation that is simply off is something to fix. Everything
             * else - the ones that depend on what this site connects to, and the ones already
             * relied upon - is worth a look and no more.
             */
            'severity' => ($scored && !$inUse) ? Finding::SEVERITY_FIX : Finding::SEVERITY_LOOK,
            'title'    => Arr::get($item, 'title', ''),
            'why'      => Arr::get($item, 'note') ?: Arr::get($item, 'why', ''),
            'action'   => 'navigate',
            'label'    => __('Set up', 'fluent-security'),
            'route'    => Arr::get($item, 'route', ''),
            'section'  => Arr::get($item, 'section', ''),
            'scored'   => $scored
        ];

        if ($inUse) {
            /*
             * Not "Set up". Nothing here is waiting to be set up - something on this site is
             * relying on the setting being off, and the only useful thing to offer is a look at
             * what that is. A button that implies there is work outstanding turns a fact into
             * a failing, which is the one thing this state exists to avoid.
             */
            $finding['label'] = __('Review', 'fluent-security');
        } elseif (Arr::get($item, 'action') === 'enable') {
            $finding['action'] = 'fix';
            $finding['label'] = __('Turn on', 'fluent-security');
        }

        return new Finding($finding);
    }

    /**
     * @param string $findingId
     * @return string
     */
    protected function keyFromFindingId($findingId)
    {
        $prefix = $this->id() . '_';

        if (strpos((string)$findingId, $prefix) !== 0) {
            return '';
        }

        return substr($findingId, strlen($prefix));
    }
}
