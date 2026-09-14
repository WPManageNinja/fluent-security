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
            new Files\BaselineCheck(),
            new Files\IntegrityCheck(),
            new Files\BackupFilesCheck(),
            new Config\FileEditorCheck(),
            new Config\DebugDisplayCheck(),
            new Config\HttpsCheck(),
            new Config\SecretEncryptionCheck(),
            new Users\AdminUsernameCheck(),
            new Users\DormantAdminCheck(),
            new Users\HiddenUsersCheck()
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
        $passed = [];
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
                $passed[] = $finding;
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
            $rank = self::rank($a) - self::rank($b);

            return $rank ?: strcmp($a->id(), $b->id());
        });

        $bySeverity = [Finding::SEVERITY_FIX => 0, Finding::SEVERITY_LOOK => 0, Finding::SEVERITY_ADVICE => 0];

        foreach ($open as $finding) {
            $severity = $finding->severity();

            if (isset($bySeverity[$severity])) {
                $bySeverity[$severity]++;
            }
        }

        /*
         * Alphabetical, because there is no worst-first to speak of among things that are
         * fine and any other order would look like one.
         */
        usort($passed, function ($a, $b) {
            return strcmp($a->get('title'), $b->get('title'));
        });

        return [
            'findings' => array_map(function ($finding) {
                return $finding->toArray();
            }, $open),
            'accepted' => array_map(function ($finding) {
                return $finding->toArray();
            }, $accepted),
            /*
             * Sent, not just counted. "18 checks passed" is a number the reader has to take on
             * trust; the list behind it is what makes the claim checkable, and it is the only
             * place the plugin says out loud what it actually looked at.
             */
            'passed'   => array_map(function ($finding) {
                return $finding->toArray();
            }, $passed),
            'counts'   => [
                'open'     => count($open),
                'to_fix'   => $bySeverity[Finding::SEVERITY_FIX],
                'look'     => $bySeverity[Finding::SEVERITY_LOOK],
                'advice'   => $bySeverity[Finding::SEVERITY_ADVICE],
                /*
                 * What the tab badge counts. Advice is open and listed but is not something
                 * the site has to answer for, and a red number on a navigation tab is the one
                 * place a suggestion would read as an outstanding problem.
                 */
                'attention' => $bySeverity[Finding::SEVERITY_FIX] + $bySeverity[Finding::SEVERITY_LOOK],
                'passed'   => count($passed),
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
     * Where a finding sits in the list. Lower is more urgent.
     *
     * Anything unrecognised sorts with `look` rather than to either end: a check contributed
     * by an add-on cannot push itself to the top of the list by inventing a severity, and it
     * cannot be buried by getting one wrong either.
     *
     * @param Finding $finding
     * @return int
     */
    protected static function rank($finding)
    {
        $ranks = [
            Finding::SEVERITY_FIX    => 0,
            Finding::SEVERITY_LOOK   => 1,
            Finding::SEVERITY_ADVICE => 2
        ];

        return isset($ranks[$finding->severity()]) ? $ranks[$finding->severity()] : 1;
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
