<?php

namespace FluentAuth\App\Services\Checks\Files;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Services\Checks\Check;
use FluentAuth\App\Services\Checks\Finding;
use FluentAuth\App\Services\IntegrityChecker\IntegrityHelper;

/**
 * What the last scan against WordPress.org has to say.
 *
 * Instant, like the snapshot check beside it: the comparison happens on the scan and on the
 * schedule, and this reads what those left behind. It exists because a file in wp-includes
 * that no longer matches the official release is the most serious thing this plugin can
 * find, and until now it was the one finding that never appeared on the findings list - it
 * lived on the scan screen, and a reader who arrived at "Security" and read the list was
 * told everything was fine.
 *
 * Nothing at all before the first scan. The offer to set scanning up belongs where the
 * coverage is explained, not among the things wrong with the site.
 *
 * Cannot be dismissed from here. A changed file is accepted one path at a time on the scan
 * screen, next to the diff, which is the only place that decision can be made with the
 * evidence in view; a "mark as expected" button on a row that summarises four hundred files
 * would be accepting things unread.
 */
class IntegrityCheck extends Check
{
    /* Paths listed under the finding before it says "and N more". */
    const DETAIL_LIMIT = 40;

    public function id()
    {
        return 'integrity';
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
        if (!$this->hasScanned()) {
            return [];
        }

        $core = IntegrityHelper::getActiveCoreFindings();
        $extensions = IntegrityHelper::getActiveExtensionFindings();
        $suspicious = IntegrityHelper::getSuspiciousExtensions();
        /*
         * The folders the scan found at the root. Left out of this finding they were the one
         * thing the alert email listed every day while this list said nothing needed
         * attention - and leftovers from a host move are usually exactly that, a folder.
         */
        $folders = IntegrityHelper::getActiveCoreFolders();
        $truncated = $this->truncated();

        $files = count($core) + count($extensions) + $truncated;

        if (!$files && !$suspicious && !$folders) {
            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_PASSED,
                'title'  => __('Your WordPress files match the official release', 'fluent-security'),
                'scored' => true
            ])];
        }

        /*
         * A stray folder is not something a reinstall puts back, so a finding made only of
         * folders goes to the scan screen, which lists them and lets each be marked expected.
         */
        $onlyFolders = !$files && !$suspicious;

        return [new Finding([
            'id'       => $this->id(),
            'check'    => $this->id(),
            'group'    => $this->group(),
            'state'    => Finding::STATE_OPEN,
            'severity' => Finding::SEVERITY_FIX,
            'title'    => $this->title($files, count($suspicious), count($folders)),
            'why'      => $onlyFolders
                ? __('WordPress does not put folders next to wp-admin and wp-includes. Leftovers from a host move or an old backup are the usual reason, and a folder nobody remembers is also where an attacker hides things. Delete what you do not need, and mark the rest as expected.', 'fluent-security')
                : __('Core files and plugins from the directory should match the official copy exactly. A file that differs was changed on this server, and if you did not change it, somebody else did. Put them back, then look at what cannot be put back.', 'fluent-security'),
            'details'  => $this->details($core, $extensions, $suspicious, $folders, $truncated),
            'action'   => 'navigate',
            'label'    => $onlyFolders ? __('Review folders', 'fluent-security') : __('Put files back', 'fluent-security'),
            'route'    => $onlyFolders ? 'security_scans' : 'security_recovery',
            'scored'   => true
        ])];
    }

    /**
     * Whether there is a result to read. A scan that has never run has nothing to say, and
     * saying "no changes" for it would be a claim nobody made.
     *
     * @return bool
     */
    protected function hasScanned()
    {
        $core = IntegrityHelper::getCoreResults();

        if (!empty($core['checked_at'])) {
            return true;
        }

        if (IntegrityHelper::getExtensionResults()) {
            return true;
        }

        return !empty(Arr::get(IntegrityHelper::getSettings(), 'last_checked'));
    }

    /**
     * Findings past the storage cap. Still findings, just ones without a path to show.
     *
     * @return int
     */
    protected function truncated()
    {
        $truncated = (int)Arr::get(IntegrityHelper::getCoreResults(), 'truncated', 0);

        foreach (IntegrityHelper::getExtensionResults() as $result) {
            if (empty($result['verifiable']) || IntegrityHelper::isExtensionIgnored(Arr::get($result, 'rel_path', ''))) {
                continue;
            }

            $truncated += (int)Arr::get($result, 'truncated', 0);
        }

        return $truncated;
    }

    /**
     * @param int $files
     * @param int $suspicious
     * @param int $folders
     * @return string
     */
    protected function title($files, $suspicious, $folders = 0)
    {
        if (!$files && !$suspicious) {
            return sprintf(
                /* translators: %s: number of folders */
                _n(
                    '%s folder in your WordPress root is not part of WordPress',
                    '%s folders in your WordPress root are not part of WordPress',
                    $folders,
                    'fluent-security'
                ),
                number_format_i18n($folders)
            );
        }

        if (!$files) {
            return sprintf(
                /* translators: %s: number of plugins or themes */
                _n(
                    '%s plugin or theme is on a version WordPress.org never published',
                    '%s plugins or themes are on versions WordPress.org never published',
                    $suspicious,
                    'fluent-security'
                ),
                number_format_i18n($suspicious)
            );
        }

        return sprintf(
            /* translators: %s: number of files */
            _n(
                '%s file differs from what WordPress.org published',
                '%s files differ from what WordPress.org published',
                $files,
                'fluent-security'
            ),
            number_format_i18n($files)
        );
    }

    /**
     * @param array $core
     * @param array $extensions
     * @param array $suspicious
     * @param array $folders
     * @param int   $truncated
     * @return array
     */
    protected function details($core, $extensions, $suspicious, $folders, $truncated)
    {
        $details = [];

        foreach ($suspicious as $item) {
            $details[] = sprintf(
                '%s %s — %s',
                $item['name'],
                $item['version'],
                $item['reason']
            );
        }

        foreach ($folders as $folder) {
            /* translators: %s: folder path, relative to the WordPress root */
            $details[] = sprintf(__('%s (folder not part of WordPress)', 'fluent-security'), $folder);
        }

        $rows = [];

        foreach ($core as $path => $data) {
            $rows[] = sprintf('WordPress — %s (%s)', $path, $this->statusLabel(Arr::get($data, 'status', '')));
        }

        foreach ($extensions as $path => $data) {
            $rows[] = sprintf(
                '%s — %s (%s)',
                Arr::get($data, 'extension', ''),
                $path,
                $this->statusLabel(Arr::get($data, 'status', ''))
            );
        }

        $hidden = max(0, count($rows) - self::DETAIL_LIMIT) + $truncated;
        $details = array_merge($details, array_slice($rows, 0, self::DETAIL_LIMIT));

        if ($hidden) {
            $details[] = sprintf(
                /* translators: %s: number of further files */
                _n('and %s more file, listed under Monitoring', 'and %s more files, listed under Monitoring', $hidden, 'fluent-security'),
                number_format_i18n($hidden)
            );
        }

        return $details;
    }

    /**
     * @param string $status
     * @return string
     */
    protected function statusLabel($status)
    {
        $labels = [
            'new'      => __('not in the official release', 'fluent-security'),
            'modified' => __('changed', 'fluent-security'),
            'deleted'  => __('missing', 'fluent-security')
        ];

        return isset($labels[$status]) ? $labels[$status] : $status;
    }
}
