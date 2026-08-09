<?php

namespace FluentAuth\App\Services\Checks;

use FluentAuth\App\Helpers\Arr;

/**
 * One thing the security screen has to say about this site.
 *
 * Every check produces these and nothing else, whether it read an option row, hashed a
 * file or asked the web server a question. That is the whole point: the screen renders one
 * component, so a new kind of check costs a class and no interface work at all.
 *
 * Two rules are encoded here rather than left to each check to remember.
 *
 * A finding is one *decision*, not one thing found. Four unrecognised files in mu-plugins
 * is a single finding with four entries in `details`, because the reader makes one call
 * about all of them. Emitting four rows is how a scan turns into a wall of text that gets
 * scrolled past, and the paths are not what the reader is deciding on anyway.
 *
 * There are two severities. `fix` is something to act on; `look` is worth knowing. A third
 * tier asks the reader to triage, which is a skill we cannot assume - anything more urgent
 * than "fix this" belongs in the verdict at the top of the page, not in a louder row.
 *
 * Findings that pass are still findings. They are what lets the list end with "18 checks
 * passed" instead of implying that everything unmentioned was simply never looked at.
 */
class Finding
{
    const SEVERITY_FIX = 'fix';

    const SEVERITY_LOOK = 'look';

    /* Nothing wrong. Never rendered as a row; counted at the foot of the list. */
    const STATE_PASSED = 'passed';

    /* Outstanding. This is the only state that gets a row. */
    const STATE_OPEN = 'open';

    /* Outstanding, but the site has said it is expected. Shown only on request. */
    const STATE_ACCEPTED = 'accepted';

    protected $data = [];

    public function __construct($data = [])
    {
        $this->data = wp_parse_args($data, [
            /* Unique across the whole registry, and opaque - the check picks it. */
            'id'       => '',
            /* Which check produced it, so a fix request can be routed back without parsing. */
            'check'    => '',
            /* files | config | login | users | plugins - the filter chips on the screen. */
            'group'    => '',
            'state'    => self::STATE_OPEN,
            'severity' => self::SEVERITY_LOOK,
            /*
             * A sentence about this site, in words the owner uses. Not "DISALLOW_FILE_EDIT"
             * but "Anyone who gets into your admin can edit your site's code".
             */
            'title'    => '',
            /* One line on why it matters. Read far more often than the details are opened. */
            'why'      => '',
            /*
             * Level three. Paths, hashes, dates, setting names - everything the developer
             * they call will want, and nothing the owner needs to get to a decision.
             */
            'details'  => [],
            /*
             * The one button. `fix` does the thing from here; `navigate` can only take you
             * to where it is done; `none` is for a finding that is a fact rather than a task.
             */
            'action'   => 'none',
            'label'    => '',
            /* Where `navigate` goes - a Vue route name, with an optional settings section. */
            'route'    => '',
            'section'  => '',
            /*
             * `expected` records the current state and speaks up if it changes again;
             * `ignore` silences the path for good. Empty means this cannot be dismissed.
             */
            'dismiss'  => '',
            /*
             * Counted towards the score. Only what this plugin recommends for every site,
             * so the score stays reachable - see Helper::getRecommendedSettings().
             */
            'scored'   => false
        ]);
    }

    public function id()
    {
        return $this->data['id'];
    }

    public function check()
    {
        return $this->data['check'];
    }

    public function state()
    {
        return $this->data['state'];
    }

    public function isOpen()
    {
        return $this->data['state'] === self::STATE_OPEN;
    }

    public function isScored()
    {
        return !empty($this->data['scored']);
    }

    public function severity()
    {
        return $this->data['severity'];
    }

    public function get($key, $default = null)
    {
        return Arr::get($this->data, $key, $default);
    }

    public function toArray()
    {
        return $this->data;
    }
}
