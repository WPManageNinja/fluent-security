<?php

namespace FluentAuth\App\Services\Checks;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Services\SecurityChecks;

/**
 * The plugin's own settings, as findings.
 *
 * Deliberately an adapter over SecurityChecks rather than a rewrite of it. That class holds
 * two things worth more than the tidiness of a uniform hierarchy: what counts as recommended
 * comes from Helper::getRecommendedSettings(), so the checklist and the "apply recommended"
 * button cannot disagree; and apply() takes the name of a check rather than a setting and a
 * value, re-deciding what that means and refusing on its own terms, so the endpoint cannot be
 * talked into writing an arbitrary setting. Re-expressing that as check classes would risk
 * both to gain nothing the screen can see.
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
     * Decline a recommendation.
     *
     * Not the same promise the file checks make. There, accepting says "this file is fine as
     * it is" and the check keeps watching it; here it says "this one is not for my site", and
     * there is nothing left to watch. Which is why a declined recommendation leaves the score
     * altogether rather than counting as satisfied - see toFinding(). Otherwise dismissing
     * things would be the quickest route to a hundred per cent, and the number would stop
     * meaning that the site follows the recommendations.
     *
     * @param string $findingId
     * @return array|\WP_Error
     */
    public function accept($findingId)
    {
        $key = $this->keyFromFindingId($findingId);
        $definitions = SecurityChecks::get();

        $known = wp_list_pluck(Arr::get($definitions, 'items', []), 'key');

        if (!$key || !in_array($key, $known, true)) {
            return new \WP_Error(
                'unknown_check',
                __('That is not something this plugin knows how to check.', 'fluent-security'),
                ['status' => 404]
            );
        }

        Dismissals::add($key);

        return ['message' => __('Noted. This will not be counted or mentioned again.', 'fluent-security')];
    }

    /**
     * @param string $findingId
     * @return array|\WP_Error
     */
    public function unaccept($findingId)
    {
        $key = $this->keyFromFindingId($findingId);

        if (!$key) {
            return new \WP_Error(
                'unknown_check',
                __('There is nothing to undo for this one.', 'fluent-security'),
                ['status' => 404]
            );
        }

        Dismissals::remove($key);

        return ['message' => __('This is back on the list.', 'fluent-security')];
    }

    /**
     * @param array $item
     * @return Finding
     */
    protected function toFinding($item)
    {
        $state = Arr::get($item, 'state');
        $scored = !empty($item['scored']);
        $key = Arr::get($item, 'key');

        /*
         * Declined, and still off. A recommendation the reader has turned down stays on the
         * record with a way back, and leaves the score entirely - `scored` false here is what
         * takes it out of both halves of the fraction rather than handing over the point.
         *
         * Only while it is still undone: a site that later switches the thing on should get
         * the credit and see it counted, not go on being told it once said no.
         */
        if ($state !== 'done' && Dismissals::has($key)) {
            return new Finding([
                'id'      => $this->id() . '_' . $key,
                'check'   => $this->id(),
                'group'   => Arr::get($item, 'group', 'login'),
                'state'   => Finding::STATE_ACCEPTED,
                'title'   => Arr::get($item, 'title', ''),
                'why'     => __('You have said this one is not for your site.', 'fluent-security'),
                'scored'  => false
            ]);
        }

        $finding = [
            'id'       => $this->id() . '_' . $key,
            'check'    => $this->id(),
            'group'    => Arr::get($item, 'group', 'login'),
            'state'    => $state === 'done' ? Finding::STATE_PASSED : Finding::STATE_OPEN,
            /*
             * Only a scored recommendation that is off is something to fix. An unscored one
             * does not suit every site, so it is worth a look and no more; advice is quieter
             * again - sound practice rather than anything wrong with this site.
             */
            'severity' => $this->severityFor($item),
            'title'    => Arr::get($item, 'title', ''),
            'why'      => Arr::get($item, 'why', ''),
            'action'   => 'navigate',
            'label'    => __('Set up', 'fluent-security'),
            'route'    => Arr::get($item, 'route', ''),
            'section'  => Arr::get($item, 'section', ''),
            /*
             * Only an outstanding one can be declined. There is nothing to turn down about a
             * protection that is already on.
             */
            'dismiss'  => $state === 'todo' ? 'ignore' : '',
            'scored'   => $scored
        ];

        if (Arr::get($item, 'action') === 'enable') {
            $finding['action'] = 'fix';
            $finding['label'] = __('Turn on', 'fluent-security');
        }

        return new Finding($finding);
    }

    /**
     * How loudly a checklist item is said.
     *
     * Advice is tested first: a recommendation that depends on how a site is staffed stays
     * quiet whether or not it is one the score counts, because there is nothing wrong with
     * the site either way.
     *
     * @param array $item
     * @return string
     */
    protected function severityFor($item)
    {
        if (!empty($item['advice'])) {
            return Finding::SEVERITY_ADVICE;
        }

        return !empty($item['scored']) ? Finding::SEVERITY_FIX : Finding::SEVERITY_LOOK;
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
