<?php

namespace FluentAuth\App\Services\Checks;

/**
 * One question the plugin knows how to ask about this site.
 *
 * A check runs and returns findings - none, one, or several - and may know how to act on
 * them. Everything else about it is declared rather than inferred, because the screen has
 * to decide what to run before it runs anything.
 *
 * `cost()` is the declaration that matters most. The security screen must not be blank on
 * arrival, and it must not spend a minute of the reader's time proving it. So the checks
 * that answer in microseconds run on every page load with no button, and only the ones that
 * talk to the network or walk the disk wait to be asked. Splitting them by cost rather than
 * by subject is what lets the screen be useful immediately and thorough on request.
 */
abstract class Check
{
    /* Answers from local state alone. Run on every page load. */
    const COST_INSTANT = 'instant';

    /* Needs one HTTP request or similar. Run on load, but its answer is cached. */
    const COST_PROBE = 'probe';

    /* Seconds to minutes. Only on "Scan now" or the schedule; reads stored results otherwise. */
    const COST_DEEP = 'deep';

    /**
     * Stable, slug-safe, and never reused - it is what a fix request names.
     *
     * @return string
     */
    abstract public function id();

    /**
     * files | config | login | users | plugins
     *
     * @return string
     */
    abstract public function group();

    /**
     * @return string
     */
    public function cost()
    {
        return self::COST_INSTANT;
    }

    /**
     * Every item this check evaluated, passed ones included.
     *
     * @return Finding[]
     */
    abstract public function run();

    /**
     * Do what the finding's button says.
     *
     * Takes a finding id rather than any description of the work, so the endpoint can never
     * be talked into an arbitrary write - the check decides what its own id means. Whatever
     * a fix claims to have done must be re-read afterwards and reported as found, never as
     * attempted: a chmod that silently failed and a chmod that worked look identical from
     * the return value of chmod().
     *
     * @param string $findingId
     * @return array|\WP_Error
     */
    public function fix($findingId)
    {
        return new \WP_Error(
            'not_fixable',
            __('This one has to be set up before it can be switched on.', 'fluent-security'),
            ['status' => 422]
        );
    }

    /**
     * Record that the site is happy with this as it stands.
     *
     * @param string $findingId
     * @return array|\WP_Error
     */
    public function accept($findingId)
    {
        return new \WP_Error(
            'not_acceptable',
            __('This is not something that can be marked as expected.', 'fluent-security'),
            ['status' => 422]
        );
    }
}
