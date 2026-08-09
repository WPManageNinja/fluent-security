<?php

namespace FluentAuth\App\Services\Checks;

/**
 * The one place findings come from.
 *
 * The screen asks this for everything it shows, and hands fix and accept requests straight
 * back to it. Nothing else assembles a list of what is wrong with the site - the plugin used
 * to have two such lists, one built from settings on the dashboard and one built from file
 * hashes on the scan screen, and the failure mode of that arrangement is not duplication but
 * disagreement: two answers to "is this site alright", differing, both ours.
 */
class Registry
{
    protected static $checks = null;

    /**
     * @return Check[] keyed by id
     */
    public static function checks()
    {
        if (self::$checks !== null) {
            return self::$checks;
        }

        $checks = [
            new SettingsCheck(),
            new Files\MuPluginsCheck(),
            new Files\DropInsCheck(),
            new Files\UploadsExecutionCheck(),
            new Files\ConfigPermissionsCheck(),
            new Files\BaselineCheck(),
            new Files\BackupFilesCheck(),
            new Config\FileEditorCheck(),
            new Config\DebugDisplayCheck(),
            new Config\HttpsCheck(),
            new Users\AdminUsernameCheck(),
            new Users\DormantAdminCheck()
        ];

        /*
         * Filtered rather than hard-coded so an add-on can contribute a check without this
         * file knowing about it. Anything that is not a Check is dropped rather than trusted,
         * since whatever comes back is called with the site's own privileges.
         */
        $checks = apply_filters('fluent_auth/security_checks', $checks);

        $registered = [];

        foreach ($checks as $check) {
            if (!$check instanceof Check) {
                continue;
            }

            $registered[$check->id()] = $check;
        }

        self::$checks = $registered;

        return self::$checks;
    }

    /**
     * Run every check of the given cost and return what they made of the site.
     *
     * Defaults to the instant ones, because this is what a page load asks for and a page
     * load must not wait on the network.
     *
     * @param array $costs
     * @return Finding[]
     */
    public static function findings($costs = [Check::COST_INSTANT])
    {
        $findings = [];

        foreach (self::checks() as $check) {
            if (!in_array($check->cost(), $costs, true)) {
                continue;
            }

            /*
             * One check that throws must not cost the reader every other check's answer. A
             * scan screen that renders nothing because a single file was unreadable is worse
             * than one that renders eleven findings and says the twelfth could not be run.
             */
            try {
                $results = $check->run();
            } catch (\Exception $exception) {
                continue;
            }

            foreach ($results as $finding) {
                if ($finding instanceof Finding) {
                    $findings[] = $finding;
                }
            }
        }

        return $findings;
    }

    /**
     * Everything the Findings screen needs, in the order it reads them.
     *
     * @param array $costs
     * @return array
     */
    public static function summary($costs = [Check::COST_INSTANT])
    {
        $findings = self::findings($costs);

        $open = [];
        $accepted = [];
        $passed = 0;
        $scoredTotal = 0;
        $scoredPassed = 0;

        foreach ($findings as $finding) {
            if ($finding->isScored()) {
                $scoredTotal++;

                if (!$finding->isOpen()) {
                    $scoredPassed++;
                }
            }

            if ($finding->state() === Finding::STATE_PASSED) {
                $passed++;
                continue;
            }

            if ($finding->state() === Finding::STATE_ACCEPTED) {
                $accepted[] = $finding;
                continue;
            }

            $open[] = $finding;
        }

        /* Worst first, and stable within a severity so the list does not shuffle on reload. */
        usort($open, function ($a, $b) {
            if ($a->severity() === $b->severity()) {
                return strcmp($a->id(), $b->id());
            }

            return $a->severity() === Finding::SEVERITY_FIX ? -1 : 1;
        });

        $toFix = array_values(array_filter($open, function ($finding) {
            return $finding->severity() === Finding::SEVERITY_FIX;
        }));

        return [
            'findings' => array_map(function ($finding) {
                return $finding->toArray();
            }, $open),
            'accepted' => array_map(function ($finding) {
                return $finding->toArray();
            }, $accepted),
            'counts'   => [
                'open'     => count($open),
                'to_fix'   => count($toFix),
                'look'     => count($open) - count($toFix),
                'passed'   => $passed,
                'accepted' => count($accepted)
            ],
            /*
             * Out of what is scored, not out of what was looked at. Only the recommendations
             * that suit every site are scored, so the number stays reachable - a score you
             * cannot reach is a score people stop reading.
             */
            'score'    => [
                'done'    => $scoredPassed,
                'total'   => $scoredTotal,
                'percent' => $scoredTotal ? (int)round(($scoredPassed / $scoredTotal) * 100) : 100
            ]
        ];
    }

    /**
     * @param string $checkId
     * @param string $findingId
     * @return array|\WP_Error
     */
    public static function fix($checkId, $findingId)
    {
        $check = self::find($checkId);

        if (is_wp_error($check)) {
            return $check;
        }

        return $check->fix($findingId);
    }

    /**
     * @param string $checkId
     * @param string $findingId
     * @return array|\WP_Error
     */
    public static function accept($checkId, $findingId)
    {
        $check = self::find($checkId);

        if (is_wp_error($check)) {
            return $check;
        }

        return $check->accept($findingId);
    }

    /**
     * @param string $checkId
     * @param string $findingId
     * @return array|\WP_Error
     */
    public static function unaccept($checkId, $findingId)
    {
        $check = self::find($checkId);

        if (is_wp_error($check)) {
            return $check;
        }

        return $check->unaccept($findingId);
    }

    /**
     * @param string $checkId
     * @return Check|\WP_Error
     */
    protected static function find($checkId)
    {
        $checks = self::checks();

        if (!isset($checks[$checkId])) {
            return new \WP_Error(
                'unknown_check',
                __('That is not something this plugin knows how to check.', 'fluent-security'),
                ['status' => 404]
            );
        }

        return $checks[$checkId];
    }

    /**
     * Test seam - the registry is built once per request and cached.
     *
     * @return void
     */
    public static function reset()
    {
        self::$checks = null;
    }
}
