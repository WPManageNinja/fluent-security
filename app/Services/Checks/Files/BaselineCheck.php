<?php

namespace FluentAuth\App\Services\Checks\Files;

use FluentAuth\App\Services\Baseline\BaselineScanner;
use FluentAuth\App\Services\Baseline\BaselineStore;
use FluentAuth\App\Services\Checks\Check;
use FluentAuth\App\Services\Checks\Finding;

/**
 * What the site's own snapshot has to say.
 *
 * Instant, even though the comparison behind it is anything but: hashing wp-content takes
 * minutes, so it happens on the scan and on the schedule, and this reads the verdict those
 * left behind. A page load should never be the thing that walks the disk, and a finding
 * should never wait for a scan to be worth showing.
 *
 * Nothing at all is reported when no snapshot has been taken. Reading "you have not set up
 * file monitoring" on the findings list every day would train somebody to skim past the list,
 * and the offer to set it up belongs where the coverage is explained rather than among the
 * things that are wrong with the site.
 */
class BaselineCheck extends Check
{
    public function id()
    {
        return 'baseline';
    }

    public function group()
    {
        return 'files';
    }

    public function cost()
    {
        return self::COST_INSTANT;
    }

    public function run()
    {
        if (!BaselineStore::hasTable()) {
            return [];
        }

        $summary = BaselineScanner::summary();

        if (empty($summary['exists'])) {
            return [];
        }

        $changed = BaselineStore::changed();

        if (!$changed) {
            /*
             * "Nothing has changed" is a claim about everything, so it may only be made when
             * everything was looked at. A unit over the per-unit ceiling leaves files unhashed,
             * and a pass that did not mention that would be the most damaging sentence this
             * plugin can print: a clean bill of health over a part of the site nobody read.
             */
            $skipped = (int)$summary['skipped'];

            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_PASSED,
                'title'  => $skipped
                    ? $this->partialTitle($skipped)
                    : __('Nothing has changed since your snapshot', 'fluent-security'),
                'scored' => true
            ])];
        }

        $files = 0;
        $details = [];

        foreach ($changed as $row) {
            $changes = json_decode((string)$row->changes, true);
            $changes = is_array($changes) ? $changes : [];

            foreach ($changes as $change) {
                if (isset($change['status']) && $change['status'] === 'truncated') {
                    $files += (int)$change['count'];
                    $details[] = sprintf(
                        /* translators: 1: an extension name, 2: number of further files */
                        __('%1$s — and %2$s more files', 'fluent-security'),
                        $row->label,
                        number_format_i18n((int)$change['count'])
                    );
                    continue;
                }

                $files++;

                $details[] = sprintf(
                    '%s — %s (%s)',
                    $row->label,
                    isset($change['path']) ? $change['path'] : '',
                    $this->statusLabel(isset($change['status']) ? $change['status'] : '')
                );
            }
        }

        return [new Finding([
            'id'       => $this->id(),
            'check'    => $this->id(),
            'group'    => $this->group(),
            'state'    => Finding::STATE_OPEN,
            /*
             * The loudest thing this plugin says, and it has earned the right to: these are
             * files that can run, in something with no official copy to check against, which
             * have changed without their version changing. There is no ordinary explanation
             * for that the way there is for everything else on the list.
             */
            'severity' => Finding::SEVERITY_FIX,
            'title'    => $this->title(count($changed), $files),
            'why'      => __('These files can run code, and nothing about the plugin or theme they belong to says it was updated. If you did not edit them yourself, treat this as somebody else having done so.', 'fluent-security'),
            'details'  => $details,
            'action'   => 'none',
            'dismiss'  => 'expected',
            'scored'   => true
        ])];
    }

    /**
     * Accept the site as it is now.
     *
     * Re-takes the snapshot rather than silencing the finding, so what is being agreed to is
     * "this is the correct state of these files" and the watching carries on from here. There
     * is no way to say "stop telling me about this plugin" and that is deliberate.
     *
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

        $scopes = wp_list_pluck(BaselineStore::changed(), 'scope');

        if (!$scopes) {
            return new \WP_Error(
                'nothing_to_accept',
                __('There is nothing waiting to be accepted.', 'fluent-security'),
                ['status' => 422]
            );
        }

        BaselineScanner::snapshot($scopes);

        return [
            'message' => __('Noted. These files are the new normal, and you will hear about the next change to them.', 'fluent-security')
        ];
    }

    /**
     * The pass that has to admit its own blind spot.
     *
     * @param int $skipped
     * @return string
     */
    protected function partialTitle($skipped)
    {
        return sprintf(
            /* translators: %s: number of files */
            _n(
                'Nothing has changed, but %s file is too large a set to watch',
                'Nothing has changed, but %s files are too many to watch',
                $skipped,
                'fluent-security'
            ),
            number_format_i18n($skipped)
        );
    }

    /**
     * @param int $units
     * @param int $files
     * @return string
     */
    protected function title($units, $files)
    {
        return sprintf(
            /* translators: 1: number of files, 2: number of plugins or themes */
            _n(
                '%1$s file has changed in %2$s of your plugins or themes',
                '%1$s files have changed in %2$s of your plugins or themes',
                $files,
                'fluent-security'
            ),
            number_format_i18n($files),
            number_format_i18n($units)
        );
    }

    /**
     * @param string $status
     * @return string
     */
    protected function statusLabel($status)
    {
        $labels = [
            'added'    => __('new file', 'fluent-security'),
            'modified' => __('changed', 'fluent-security'),
            'removed'  => __('deleted', 'fluent-security')
        ];

        return isset($labels[$status]) ? $labels[$status] : $status;
    }
}
