<?php

namespace FluentAuth\App\Services\Baseline;

/**
 * Taking the snapshot, and comparing against it afterwards.
 *
 * A file monitor's entire value is that when it speaks, somebody listens. Two rules here
 * exist to protect that, and they matter more than the detection does.
 *
 * A version bump absorbs its own changes. When a plugin's version header has moved since the
 * snapshot, every file that differs is an update - so the record is rewritten and nothing is
 * said. Without this, the Tuesday somebody updates six plugins produces hundreds of changed
 * files, indistinguishable from the thing being watched for, and the feature is over.
 *
 * And only executable files are ever in the snapshot - see BaselineTargets::extensions().
 *
 * The walk is budgeted and picks up where it left off, least-recently-checked first, so a
 * site with forty premium plugins is covered across several runs instead of timing out on
 * every one of them and reporting nothing. That order needs no cursor: the rows carry their
 * own checked_at, so installing or removing a plugin reorders the queue by itself.
 */
class BaselineScanner
{
    /**
     * Record every unit as it stands now.
     *
     * @param array $only limit to these scopes; empty means all
     * @return array
     */
    public static function snapshot($only = [])
    {
        if (!BaselineStore::ensureTable()) {
            return ['taken' => 0, 'failed' => true];
        }

        $units = BaselineTargets::units();
        $taken = 0;

        foreach ($units as $unit) {
            if ($only && !in_array($unit['scope'], $only, true)) {
                continue;
            }

            $hashes = BaselineTargets::hash($unit['path']);

            BaselineStore::put($unit['scope'], [
                'label'      => $unit['label'],
                'version'    => $unit['version'],
                'file_count' => count($hashes),
                'hashes'     => $hashes,
                'status'     => 'ok',
                'changes'    => []
            ]);

            $taken++;
        }

        BaselineStore::forgetMissing(wp_list_pluck($units, 'scope'));

        return ['taken' => $taken, 'failed' => false];
    }

    /**
     * Compare as many units against the snapshot as the budget allows.
     *
     * @param int|null $budgetSeconds
     * @return array
     */
    public static function compare($budgetSeconds = null)
    {
        if (!BaselineStore::hasTable()) {
            return ['checked' => 0, 'changed' => 0, 'remaining' => 0];
        }

        if ($budgetSeconds === null) {
            $budgetSeconds = apply_filters('fluent_auth/baseline_scan_budget', 20);
        }

        $units = BaselineTargets::units();

        BaselineStore::forgetMissing(wp_list_pluck($units, 'scope'));

        $checkedAt = [];

        foreach (BaselineStore::summaries() as $row) {
            $checkedAt[$row->scope] = (string)$row->checked_at;
        }

        /* Never checked sorts to the front on its own, since '' precedes any timestamp. */
        usort($units, function ($a, $b) use ($checkedAt) {
            $left = isset($checkedAt[$a['scope']]) ? $checkedAt[$a['scope']] : '';
            $right = isset($checkedAt[$b['scope']]) ? $checkedAt[$b['scope']] : '';

            return strcmp($left, $right);
        });

        $startedAt = time();
        $checked = 0;
        $changed = 0;

        foreach ($units as $index => $unit) {
            if (self::compareUnit($unit)) {
                $changed++;
            }

            $checked++;

            if ((time() - $startedAt) >= $budgetSeconds) {
                return [
                    'checked'   => $checked,
                    'changed'   => $changed,
                    'remaining' => count($units) - $index - 1
                ];
            }
        }

        return ['checked' => $checked, 'changed' => $changed, 'remaining' => 0];
    }

    /**
     * @param array $unit
     * @return bool whether it has changes to report
     */
    protected static function compareUnit($unit)
    {
        $stored = BaselineStore::find($unit['scope']);

        /*
         * Installed since the snapshot was taken. Recorded rather than reported: somebody
         * installing a plugin is an ordinary Tuesday, and this feature's claim is about files
         * changing under a unit it already knows - not about what is on the site at all,
         * which is what the coverage panel is for.
         */
        if (!$stored) {
            $hashes = BaselineTargets::hash($unit['path']);

            BaselineStore::put($unit['scope'], [
                'label'      => $unit['label'],
                'version'    => $unit['version'],
                'file_count' => count($hashes),
                'hashes'     => $hashes,
                'status'     => 'ok',
                'changes'    => []
            ]);

            return false;
        }

        $current = BaselineTargets::hash($unit['path']);

        /*
         * The version moved, so whatever differs is an update. Re-recorded in silence - this
         * is the rule that keeps a plugin update from reading exactly like a break-in.
         */
        if ((string)$stored->version !== (string)$unit['version']) {
            BaselineStore::put($unit['scope'], [
                'label'      => $unit['label'],
                'version'    => $unit['version'],
                'file_count' => count($current),
                'hashes'     => $current,
                'status'     => 'ok',
                'changes'    => []
            ]);

            return false;
        }

        $changes = self::diff(BaselineStore::hashes($unit['scope']), $current);

        BaselineStore::put($unit['scope'], [
            'label'      => $unit['label'],
            'version'    => $unit['version'],
            'file_count' => count($current),
            'status'     => $changes ? 'changed' : 'ok',
            'changes'    => $changes
        ]);

        return (bool)$changes;
    }

    /**
     * @param array $before
     * @param array $after
     * @return array
     */
    protected static function diff($before, $after)
    {
        $max = apply_filters('fluent_auth/baseline_max_changes', 200);

        $changes = [];

        foreach ($after as $path => $hash) {
            if (!isset($before[$path])) {
                $changes[] = ['path' => $path, 'status' => 'added'];
            } elseif ($before[$path] !== $hash) {
                $changes[] = ['path' => $path, 'status' => 'modified'];
            }
        }

        foreach ($before as $path => $hash) {
            if (!isset($after[$path])) {
                $changes[] = ['path' => $path, 'status' => 'removed'];
            }
        }

        /*
         * Past the cap the paths are dropped and the count is kept. A unit whose folder has
         * been emptied can report thousands at once, and none of that belongs in a text
         * column - but "and 4,812 more" is still the size of the problem.
         */
        if (count($changes) > $max) {
            $total = count($changes);
            $changes = array_slice($changes, 0, $max);
            $changes[] = ['path' => '', 'status' => 'truncated', 'count' => $total - $max];
        }

        return $changes;
    }

    /**
     * What the snapshot covers and what it has found, for the screens.
     *
     * @return array
     */
    public static function summary()
    {
        if (!BaselineStore::hasTable()) {
            return ['exists' => false, 'units' => 0, 'files' => 0, 'changed' => 0, 'taken_at' => ''];
        }

        $units = 0;
        $files = 0;
        $changed = 0;

        foreach (BaselineStore::summaries() as $row) {
            $units++;
            $files += (int)$row->file_count;

            if ($row->status === 'changed') {
                $changed++;
            }
        }

        return [
            'exists'   => $units > 0,
            'units'    => $units,
            'files'    => $files,
            'changed'  => $changed,
            'taken_at' => BaselineStore::takenAt(),
            /* What a snapshot would cover if taken now - the honest denominator. */
            'coverable' => count(BaselineTargets::units())
        ];
    }
}
